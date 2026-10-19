//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define _WINSOCKAPI_

#include <Windows.h>
#include <ShlObj.h>
#include <WS2tcpip.h>
#include <compressapi.h>

#pragma comment(lib, "cabinet.lib")

#include <algorithm>
#include <cstdio>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <filesystem>
#include <memory>
#include <set>

#include "WinPrivShared.h"
#include "WinPriv.h"
#include "../WinPrivLibrary/WinPrivMemoryLoader.h"

extern int LaunchNewLogon(int iArgc, wchar_t* aArgv[]);
extern int LaunchElevated(int iArgc, wchar_t* aArgv[]);
extern int LaunchAsUser(const std::wstring& commandLine, const std::wstring& username, bool bWait,
	const std::vector<std::wstring>& vProcessesToKill);
extern std::map<std::wstring, std::wstring> GetPrivilegeList();
extern std::wstring GetWinPrivHelp();

// Embedded injection libraries in bundle order with their extracted file names.
constexpr std::array<std::pair<DWORD, LPCWSTR>, 3> vLibraryResources{ {
	{ IDR_RT_RCDATA_X86, L"WinPrivLibrary-32.dll" },
	{ IDR_RT_RCDATA_X64, L"WinPrivLibrary-64.dll" },
	{ IDR_RT_RCDATA_ARM64, L"WinPrivLibrary-arm64.dll" } } };

winpriv::memory::LibraryImage LoadLibraryResource(const DWORD iResourceId, std::vector<BYTE>& vBytes)
{
	// Locate and decompress an embedded library image; failures return an empty image.
	const HRSRC hResource = FindResource(nullptr, MAKEINTRESOURCE(iResourceId), L"RT_RCDATA");
	const HGLOBAL hLoaded = hResource == nullptr ? nullptr : LoadResource(nullptr, hResource);
	const LPCVOID pData = hLoaded == nullptr ? nullptr : LockResource(hLoaded);
	SmartPointer<DECOMPRESSOR_HANDLE> hDecompressor(CloseDecompressor, nullptr);
	if (pData == nullptr || !CreateDecompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &hDecompressor)) return {};
	const DWORD iCompressedSize = SizeofResource(nullptr, hResource);
	SIZE_T iSize = 0;
	if (Decompress(hDecompressor, pData, iCompressedSize, nullptr, 0, &iSize) ||
		GetLastError() != ERROR_INSUFFICIENT_BUFFER) return {};

	// Bound allocations based on the size stored in the compressed resource.
	if (iSize == 0 || iSize > 64 * 1024 * 1024)
	{
		SetLastError(ERROR_BAD_COMPRESSION_BUFFER);
		return {};
	}
	try
	{
		vBytes.resize(iSize);
	}
	catch (...)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return {};
	}
	if (!Decompress(hDecompressor, pData, iCompressedSize, vBytes.data(), vBytes.size(), &iSize)) return {};
	return { vBytes.data(), static_cast<DWORD>(iSize) };
}

int RunProgram(int iArgc, wchar_t* aArgv[])
{
	// get list of all privileges for general use later
	const std::map<std::wstring, std::wstring> vPrivMaps = GetPrivilegeList();

	// Validate settings against the private CRT's limit before passing them to injected processes.
	const auto SetSetting = [](LPCWSTR sName, LPCWSTR sValue)
	{
		const DWORD iError = wcsnlen(sValue, _MAX_ENV) == _MAX_ENV ? ERROR_BAD_ENVIRONMENT :
			SetEnvironmentVariableW(sName, sValue) ? NO_ERROR : GetLastError();
		if (iError == NO_ERROR) return true;
		PrintMessage(L"ERROR: Could not store process setting %s (error %lu).\n", sName, iError);
		return false;
	};

	// reset settings inherited by subprocesses and identify this launcher as their parent
	for (const LPCWSTR sName : WinPrivSettingNames)
		if (!SetSetting(sName, L"")) return __LINE__;
	if (!SetSetting(WINPRIV_EV_PARENT_PID, std::to_wstring(GetCurrentProcessId()).c_str())) return __LINE__;

	// settings populated by command line arguments
	std::vector<std::wstring> vPrivsToEnable;
	std::vector<std::wstring> vProcessesToKill;
	std::wstring sRegistryOverride;
	std::wstring sFileRules;
	std::wstring sHostOverride;
	std::wstring sProcessParams;
	std::wstring sProcess;
	bool bDisplayExecutionTime = false;
	bool bUseShellExecute = false;
	WORD iShowWindow = SW_NORMAL;

	// load arguments from a cfg file as a command-line string
	const auto LoadCfgFile = [](const std::wstring& sCfgPath) -> std::optional<std::wstring>
	{
		std::ifstream oFileStream(sCfgPath);
		std::ostringstream oStringStream;
		if (oFileStream.is_open()) oStringStream << oFileStream.rdbuf();

		// strip a UTF-8 BOM so the first switch is not mistaken for the target executable
		std::string sNarrow = oStringStream.str();
		if (sNarrow.starts_with("\xEF\xBB\xBF")) sNarrow.erase(0, 3);
		const int iNarrowLen = static_cast<int>(sNarrow.size());
		const int iWideLen = MultiByteToWideChar(CP_UTF8, 0, sNarrow.c_str(), iNarrowLen, nullptr, 0);
		std::wstring sWide(iWideLen, L'\0');
		MultiByteToWideChar(CP_UTF8, 0, sNarrow.c_str(), iNarrowLen, sWide.data(), iWideLen);

		// newlines separate tokens for CommandLineToArgvW, and environment variables are expanded
		std::ranges::replace_if(sWide, [](wchar_t c) { return c == L'\r' || c == L'\n'; }, L' ');
		std::wstring sExpanded(ExpandEnvironmentStringsW(sWide.c_str(), nullptr, 0), L'\0');
		if (!oFileStream.is_open() || oFileStream.bad() || oStringStream.bad() || sExpanded.empty() ||
			ExpandEnvironmentStringsW(sWide.c_str(), sExpanded.data(), static_cast<DWORD>(sExpanded.size())) == 0)
		{
			PrintMessage(L"ERROR: Could not read cfg file: %s\n", sCfgPath.c_str());
			return std::nullopt;
		}
		sExpanded.resize(sExpanded.find(L'\0'));
		return sExpanded;
	};

	// remember expanded command lines to reject cycles while allowing a file to be loaded repeatedly
	constexpr size_t iMaxCommandFileExpansions = 64;
	size_t iCommandFileExpansions = 0;
	std::set<std::wstring> vExpandedCommandLines;

	// parsed argument arrays are owned here; the original CRT-owned argv must not be released
	std::unique_ptr<void, decltype(&LocalFree)> pOwnedArgv(nullptr, &LocalFree);
	const auto ReplaceArgs = [&](const std::wstring& sCommandLine)
	{
		LPWSTR* pParsedArgv = CommandLineToArgvW(sCommandLine.c_str(), &iArgc);
		if (pParsedArgv == nullptr)
		{
			PrintMessage(L"ERROR: Could not parse arguments loaded from cfg file.\n");
			return false;
		}
		pOwnedArgv.reset(pParsedArgv);
		aArgv = pParsedArgv;
		return true;
	};

	// read command line from cfg file if it exists
	std::wstring sExecutable(MAX_PATH + 1, L'\0');
	const DWORD iExecutableLength = GetModuleFileName(nullptr, sExecutable.data(), MAX_PATH + 1);
	if (iExecutableLength == 0 || iExecutableLength > MAX_PATH)
	{
		PrintMessage(L"ERROR: Could not determine the executable path.\n");
		return __LINE__;
	}
	sExecutable.resize(iExecutableLength);

	// Credential and elevation relaunches must execute this image regardless of argv[0] or the search path.
	aArgv[0] = sExecutable.data();
	const std::wstring sCfgPath = std::filesystem::path(sExecutable).replace_extension(L".cfg").wstring();

	// internal relaunches already carry expanded arguments and must retain their phase marker
	const bool bRelaunched = iArgc > 1 && (_wcsicmp(aArgv[1], L"/RelaunchElevated") == 0 ||
		_wcsicmp(aArgv[1], L"/RelaunchComplete") == 0);
	if (!bRelaunched && GetFileAttributes(sCfgPath.c_str()) != INVALID_FILE_ATTRIBUTES)
	{
		const std::optional<std::wstring> sCfgArgs = LoadCfgFile(sCfgPath);
		if (!sCfgArgs || !ReplaceArgs(L"\"" + sExecutable + L"\" " + *sCfgArgs)) return __LINE__;
	}

	// enumerate arguments
	for (int iArg = 1; iArg < iArgc; iArg++)
	{
		const std::wstring sArg(aArgv[iArg]);
		const auto IsSwitch = [&sArg](LPCWSTR sName) { return _wcsicmp(sArg.c_str(), sName) == 0; };
		const auto JoinArgs = [&](int iFirst, int iLast)
		{
			return ArgvToCommandLine(iFirst, iLast, std::vector<LPWSTR>(aArgv, aArgv + iArgc));
		};
		const auto HasArgs = [&](int iCount)
		{
			if (iArg + iCount < iArgc) return true;
			PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
			return false;
		};

		// the first argument without a leading slash begins the target command
		if (!sArg.starts_with(L'/'))
		{
			if (bUseShellExecute) sProcess = aArgv[iArg++];
			sProcessParams = JoinArgs(iArg, iArgc - 1);
			break;
		}

		// internal: relaunch elevated after a new logon has acquired the requested privileges
		else if (IsSwitch(L"/RelaunchElevated"))
		{
			return LaunchElevated(iArgc, aArgv);
		}

		// internal: mark the privileged relaunch so it cannot recurse and console targets pause at exit
		else if (IsSwitch(L"/RelaunchComplete"))
		{
			if (!SetSetting(WINPRIV_EV_RELAUNCH_MODE, L"1")) return __LINE__;
		}

		// use the plus variant of the session token's integrity level for run-as targets
		else if (IsSwitch(L"/MediumPlus"))
		{
			if (!SetSetting(WINPRIV_EV_MEDIUM_PLUS, L"1")) return __LINE__;
		}

		// launch the remaining command in the console user's or a named user's session
		else if (IsSwitch(L"/RunAsConsoleUser") || IsSwitch(L"/RunAsConsoleUserNoWait") ||
			IsSwitch(L"/RunAsUser") || IsSwitch(L"/RunAsUserNoWait"))
		{
			const bool bNamedUser = IsSwitch(L"/RunAsUser") || IsSwitch(L"/RunAsUserNoWait");
			const bool bWait = !IsSwitch(L"/RunAsConsoleUserNoWait") && !IsSwitch(L"/RunAsUserNoWait");
			if (bNamedUser && !HasArgs(1)) return __LINE__;
			const std::wstring sUser = bNamedUser ? aArgv[++iArg] : L"";
			sProcessParams = JoinArgs(iArg + 1, iArgc - 1);
			if (bNamedUser) wprintf(L"INFO: Launching process as user %s: %s\n", sUser.c_str(), sProcessParams.c_str());
			return LaunchAsUser(sProcessParams, sUser, bWait, vProcessesToKill);
		}

		// insert arguments from an additional cfg file at this position
		else if (IsSwitch(L"/LoadCommands"))
		{
			if (!HasArgs(1)) return __LINE__;
			const int iFirstCfgArg = iArg;
			const std::wstring sProcessedArgs = JoinArgs(1, iArg - 1);
			const std::wstring sExtraCfgPath(aArgv[++iArg]);
			if (GetFileAttributes(sExtraCfgPath.c_str()) == INVALID_FILE_ATTRIBUTES)
			{
				PrintMessage(L"ERROR: Cfg file not found: %s\n", sExtraCfgPath.c_str());
				return __LINE__;
			}

			// preserve processed arguments for relaunch while replacing this command-file switch
			const std::optional<std::wstring> sCfgArgs = LoadCfgFile(sExtraCfgPath);
			if (!sCfgArgs) return __LINE__;
			std::wstring sExpandedCommandLine = L"\"" + sExecutable + L"\"";
			for (const std::wstring& sPart : { sProcessedArgs, *sCfgArgs, JoinArgs(iArg + 1, iArgc - 1) })
				if (!sPart.empty()) sExpandedCommandLine += L" " + sPart;
			if (++iCommandFileExpansions > iMaxCommandFileExpansions ||
				!vExpandedCommandLines.insert(sExpandedCommandLine).second)
			{
				PrintMessage(L"ERROR: Recursive or excessively nested /LoadCommands expansion detected.\n");
				return __LINE__;
			}
			if (!ReplaceArgs(sExpandedCommandLine)) return __LINE__;
			iArg = iFirstCfgArg - 1;
		}

		// enable a comma-delimited list of privileges
		else if (IsSwitch(L"/WithPrivs"))
		{
			if (!HasArgs(1)) return __LINE__;
			for (const auto sPriv : std::wstring_view(aArgv[++iArg]) | std::views::split(L','))
				vPrivsToEnable.emplace_back(sPriv.begin(), sPriv.end());
		}

		// enable every privilege defined on the system
		else if (IsSwitch(L"/WithAllPrivs"))
		{
			for (const std::wstring& sPriv : vPrivMaps | std::views::keys) vPrivsToEnable.push_back(sPriv);
		}

		// kill processes with the specified name before launch
		else if (IsSwitch(L"/KillProcess"))
		{
			if (!HasArgs(1)) return __LINE__;
			vProcessesToKill.push_back(aArgv[++iArg]);
		}

		// write the embedded libraries beside this executable
		else if (IsSwitch(L"/ExtractLibrary"))
		{
			for (const auto& [iResourceId, sFileName] : vLibraryResources)
			{
				std::vector<BYTE> vBytes;
				const winpriv::memory::LibraryImage tImage = LoadLibraryResource(iResourceId, vBytes);
				const std::wstring sPath = std::filesystem::path(sExecutable).replace_filename(sFileName).wstring();
				SmartPointer<HANDLE> hFile(CloseHandle, tImage.data == nullptr ? INVALID_HANDLE_VALUE : CreateFile(
					sPath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
				DWORD iWritten = 0;
				if (hFile == INVALID_HANDLE_VALUE || !WriteFile(hFile, tImage.data, tImage.size, &iWritten, nullptr) ||
					iWritten != tImage.size)
				{
					PrintMessage(L"ERROR: Failed to extract libraries.\n");
					return __LINE__;
				}
			}
			return 0;
		}

		// display the system's privilege names and descriptions
		else if (IsSwitch(L"/ListPrivileges") || IsSwitch(L"/ListPrivs"))
		{
			size_t iColumnSize = 0;
			for (const std::wstring& sPriv : vPrivMaps | std::views::keys)
				iColumnSize = (std::max)(iColumnSize, sPriv.length());
			const int iWidth = static_cast<int>(iColumnSize) + 1;
			std::wstringstream ss;
			ss << std::left << std::setw(iWidth) << L"Privilege Constant" << L" Privilege Description\n";
			ss << std::setw(iWidth) << L"==================" << L" =====================\n";
			for (const auto& [sName, sDescription] : vPrivMaps)
				ss << std::setw(iWidth) << sName << L" " << sDescription << L"\n";
			PrintMessage(L"%s", ss.str().c_str());
			return 0;
		}

		// override the MAC address reported to the target, removing colon or dash separators
		else if (IsSwitch(L"/MacOverride"))
		{
			if (!HasArgs(1)) return __LINE__;
			std::wstring sMacAddr(aArgv[++iArg]);
			std::erase_if(sMacAddr, [](const wchar_t c) { return c == L':' || c == L'-'; });
			if (!SetSetting(WINPRIV_EV_MAC_OVERRIDE, sMacAddr.c_str())) return __LINE__;
		}

		// redirect a file path and its descendants
		else if (IsSwitch(L"/FileRedirect"))
		{
			if (!HasArgs(2)) return __LINE__;

			// Resolve paths before launching so descendants retain the same rules after changing directories.
			std::wstring sSource = ResolveFileRulePath(aArgv[iArg + 1]);
			std::wstring sDestination = ResolveFileRulePath(aArgv[iArg + 2]);
			if (sSource.empty() || sDestination.empty())
			{
				PrintMessage(L"ERROR: Invalid file path specified for: %s\n", sArg.c_str());
				return __LINE__;
			}
			sFileRules += ArgvToCommandLine(0, 1, { sSource.data(), sDestination.data() }) + L" ";
			iArg += 2;
		}

		// override a registry value: <key name> <value name> <value type> <value data>
		else if (IsSwitch(L"/RegOverride"))
		{
			if (!HasArgs(4)) return __LINE__;
			sRegistryOverride += JoinArgs(iArg + 1, iArg + 4) + L" ";
			iArg += 4;
		}

		// report every value under a registry key and its subkeys as not found
		else if (IsSwitch(L"/RegBlock"))
		{
			if (!HasArgs(1)) return __LINE__;
			++iArg;
			sRegistryOverride += JoinArgs(iArg, iArg) + L" N/A REG_BLOCK N/A ";
		}

		// request the target's initial window state
		else if (IsSwitch(L"/WindowStyle"))
		{
			if (!HasArgs(1)) return __LINE__;
			const LPCWSTR sWindowStyle = aArgv[++iArg];
			if (_wcsicmp(sWindowStyle, L"NoActive") == 0) iShowWindow = SW_SHOWNOACTIVATE;
			if (_wcsicmp(sWindowStyle, L"Minimized") == 0) iShowWindow = SW_SHOWMINIMIZED;
			if (_wcsicmp(sWindowStyle, L"Maximized") == 0) iShowWindow = SW_SHOWMAXIMIZED;
			if (_wcsicmp(sWindowStyle, L"MinimizedNoActive") == 0) iShowWindow = SW_SHOWMINNOACTIVE;
			if (_wcsicmp(sWindowStyle, L"Hidden") == 0) iShowWindow = SW_HIDE;
		}

		// override the FIPS setting through the registry override capability
		else if (IsSwitch(L"/FipsOn") || IsSwitch(L"/FipsOff"))
		{
			sRegistryOverride += L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy ";
			sRegistryOverride += L"Enabled REG_DWORD ";
			sRegistryOverride += IsSwitch(L"/FipsOn") ? L"1 " : L"0 ";
		}

		// block access to the common group policy registry areas
		else if (IsSwitch(L"/PolicyBlock"))
		{
			for (const LPCWSTR sKey : { L"HKCU\\SOFTWARE\\Policies", L"HKLM\\SOFTWARE\\Policies",
				L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies",
				L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies" })
				sRegistryOverride += std::wstring(sKey) + L" N/A REG_BLOCK N/A ";
		}

		// control amsi scanning
		else if (IsSwitch(L"/AmsiOn") || IsSwitch(L"/AmsiOff"))
		{
			if (!SetSetting(WINPRIV_EV_DISABLE_AMSI, IsSwitch(L"/AmsiOff") ? L"1" : L"0")) return __LINE__;
		}

		// control powershell constrained language mode
		else if (IsSwitch(L"/ClmOn") || IsSwitch(L"/ClmOff"))
		{
			if (!SetSetting(WINPRIV_EV_CLM, IsSwitch(L"/ClmOn") ? L"1" : L"0")) return __LINE__;
		}

		// override host name lookups: <host name to override> <host override value>
		else if (IsSwitch(L"/HostOverride"))
		{
			if (!HasArgs(2)) return __LINE__;

			// Validate names while retaining the replacement's DNS identity and absolute spelling.
			const std::wstring sTargetHost = NormalizeHostName(aArgv[iArg + 1]);
			std::wstring sReplacementHost = NormalizeHostName(aArgv[iArg + 2]);
			if (sTargetHost.empty() || sReplacementHost.empty())
			{
				PrintMessage(L"ERROR: Invalid host name specified for: %s\n", sArg.c_str());
				return __LINE__;
			}
			const wchar_t cLastReplacement = std::wstring_view(aArgv[iArg + 2]).back();
			if (cLastReplacement == L'.' || cLastReplacement == L'\u3002' ||
				cLastReplacement == L'\uFF0E' || cLastReplacement == L'\uFF61') sReplacementHost += L'.';

			// Verify that the replacement resolves without pinning its addresses in child processes.
			WSADATA tWSAData;
			int iResolveError = WSAStartup(MAKEWORD(2, 2), &tWSAData);
			SmartPointer<LPWSADATA> oWinsockCleanup([](LPWSADATA) { WSACleanup(); },
				iResolveError == 0 ? &tWSAData : nullptr);
			PADDRINFOW tResult = nullptr;
			if (iResolveError == 0) iResolveError = GetAddrInfoW(sReplacementHost.c_str(), nullptr, nullptr, &tResult);
			SmartPointer<PADDRINFOW> oAddressCleanup(FreeAddrInfoW, tResult);
			if (iResolveError != 0)
			{
				PrintMessage(L"ERROR: Could not resolve replacement host: %s (error %d).\n",
					aArgv[iArg + 2], iResolveError);
				return __LINE__;
			}
			sHostOverride += sTargetHost + L" " + sReplacementHost + L" ";
			iArg += 2;
		}

		// enable backup and restore privileges and request backup intent when opening files
		else if (IsSwitch(L"/BypassFileSecurity"))
		{
			vPrivsToEnable.insert(vPrivsToEnable.end(),
				{ SE_RESTORE_NAME, SE_BACKUP_NAME, SE_TAKE_OWNERSHIP_NAME, SE_CHANGE_NOTIFY_NAME });
			if (!SetSetting(WINPRIV_EV_BACKUP_RESTORE, L"1")) return __LINE__;
		}

		// break remote file locks when a file operation fails because of one
		else if (IsSwitch(L"/BreakRemoteLocks"))
		{
			if (!SetSetting(WINPRIV_EV_BREAK_LOCKS, L"1")) return __LINE__;
		}

		// report administrator membership regardless of security tokens or group memberships
		else if (IsSwitch(L"/AdminImpersonate"))
		{
			if (!SetSetting(L"__COMPAT_LAYER", L"RunAsInvoker") ||
				!SetSetting(WINPRIV_EV_ADMIN_IMPERSONATE, L"1")) return __LINE__;
		}

		// report a server operating system
		else if (IsSwitch(L"/ServerEdition"))
		{
			if (!SetSetting(WINPRIV_EV_SERVER_EDITION, L"1")) return __LINE__;
		}

		// record encrypt/decrypt operations to a directory, or display them when 'SHOW' is specified
		else if (IsSwitch(L"/RecordCrypto"))
		{
			if (!HasArgs(1)) return __LINE__;
			std::wstring sRecordCrypto = aArgv[++iArg];
			if (_wcsicmp(sRecordCrypto.c_str(), L"SHOW") != 0)
			{
				// Keep the selected directory stable when the target or a descendant changes its working directory.
				std::error_code tError;
				const auto tDirectory = std::filesystem::absolute(sRecordCrypto, tError);
				if (sRecordCrypto.empty() || tError || (!std::filesystem::create_directory(tDirectory, tError) &&
					!std::filesystem::is_directory(tDirectory, tError)))
				{
					PrintMessage(L"ERROR: Could not create the specified directory for /RecordCrypto\n");
					return __LINE__;
				}
				sRecordCrypto = tDirectory.wstring();
			}
			if (!SetSetting(WINPRIV_EV_RECORD_CRYPTO, sRecordCrypto.c_str())) return __LINE__;
		}

		// show sql connection information
		else if (IsSwitch(L"/SqlConnectShow"))
		{
			if (!SetSetting(WINPRIV_EV_SQL_CONNECT_SHOW, L"1")) return __LINE__;
		}

		// search and replace sql connection information
		else if (IsSwitch(L"/SqlConnectSearchReplace"))
		{
			if (!HasArgs(2)) return __LINE__;
			if (!SetSetting(WINPRIV_EV_SQL_CONNECT_SEARCH, aArgv[++iArg]) ||
				!SetSetting(WINPRIV_EV_SQL_CONNECT_REPLACE, aArgv[++iArg])) return __LINE__;
		}

		// launch the target with ShellExecuteEx
		else if (IsSwitch(L"/UseShellExecute"))
		{
			bUseShellExecute = true;
		}

		// grant or revoke an LSA account right or privilege: <right> <user>
		else if (IsSwitch(L"/GrantRight") || IsSwitch(L"/RevokeRight"))
		{
			if (!HasArgs(2)) return __LINE__;
			return ModifyAccountRights(aArgv[iArg + 2], { aArgv[iArg + 1] }, IsSwitch(L"/GrantRight")) ? 0 : __LINE__;
		}

		// remove deny-logon rights from a named account, or from every account when none is specified
		else if (IsSwitch(L"/ClearDenyRights"))
		{
			return ClearDenyRights(iArg + 1 < iArgc ? aArgv[iArg + 1] : L"") ? 0 : __LINE__;
		}

		// grant all non-deny rights and privileges to a named account
		else if (IsSwitch(L"/GrantAllRights"))
		{
			if (!HasArgs(1)) return __LINE__;
			return GrantAllRights(aArgv[iArg + 1]) ? 0 : __LINE__;
		}

		// display a message box; a yes/no prompt cancels execution if No is clicked
		else if (IsSwitch(L"/ShowMessage") || IsSwitch(L"/AskMessage"))
		{
			if (!HasArgs(1)) return __LINE__;
			const bool bAsk = IsSwitch(L"/AskMessage");
			const int iResult = MessageBox(nullptr, aArgv[++iArg], L"Message", bAsk ? MB_YESNO : MB_OK);
			if (bAsk && iResult != IDYES) return __LINE__;
		}

		// apply a fixed wall clock offset to the target and its descendants
		else if (IsSwitch(L"/MockTime"))
		{
			if (!HasArgs(1)) return __LINE__;
			FILETIME tTime{};
			GetSystemTimeAsFileTime(&tTime);
			const LONGLONG iCurrentTime = static_cast<LONGLONG>(tTime.dwHighDateTime) << 32 | tTime.dwLowDateTime;
			LONGLONG iOffset = 0;
			if (!ParseMockTimeOffset(aArgv[++iArg], iCurrentTime, iOffset))
			{
				PrintMessage(L"ERROR: Invalid /MockTime delta: %s. Use +/-number with y, mo, w, d, h, min, s, ms, us.\n",
					aArgv[iArg]);
				return __LINE__;
			}
			if (!SetSetting(WINPRIV_EV_MOCK_TIME, std::to_wstring(iOffset).c_str())) return __LINE__;
		}

		// display process execution time
		else if (IsSwitch(L"/MeasureTime"))
		{
			bDisplayExecutionTime = true;
		}

		// display help by leaving the target undefined
		else if (IsSwitch(L"/Help") || IsSwitch(L"/?"))
		{
			break;
		}

		// invalid parameter
		else
		{
			PrintMessage(L"ERROR: Unrecognized parameter: %s\n", sArg.c_str());
			return __LINE__;
		}
	}

	// display help if no target was specified
	if ((bUseShellExecute ? sProcess : sProcessParams).empty())
	{
		PrintMessage(L"%s", GetWinPrivHelp().c_str());
		return 0;
	}

	// Match PowerShell's machine-level debug fallback to the final CLM switch.
	if (VariableNotEmpty(WINPRIV_EV_CLM))
	{
		sRegistryOverride += L"\"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment\" ";
		sRegistryOverride += L"__PSLockdownPolicy REG_SZ ";
		sRegistryOverride += VariableIsSet(WINPRIV_EV_CLM, 1) ? L"4 " : L"0 ";
	}

	// pass the registry, file, and host rules to child processes
	if (!SetSetting(WINPRIV_EV_REG_OVERRIDE, TrimString(sRegistryOverride, L' ').c_str()) ||
		!SetSetting(WINPRIV_EV_FILE_RULES, TrimString(sFileRules, L' ').c_str()) ||
		!SetSetting(WINPRIV_EV_HOST_OVERRIDE, TrimString(sHostOverride, L' ').c_str())) return __LINE__;

	// sort privs, remove duplicate privs, and pass the validated list to child processes
	std::ranges::sort(vPrivsToEnable);
	vPrivsToEnable.erase(std::ranges::unique(vPrivsToEnable).begin(), vPrivsToEnable.end());
	std::wstring sPrivsToSetList;
	for (const std::wstring& sPrivToSet : vPrivsToEnable)
	{
		if (!vPrivMaps.contains(sPrivToSet))
		{
			PrintMessage(L"ERROR: Invalid privilege specified: %s\n", sPrivToSet.c_str());
			return __LINE__;
		}
		sPrivsToSetList += sPrivToSet + L",";
	}
	if (!SetSetting(WINPRIV_EV_PRIVLIST, TrimString(sPrivsToSetList, L',').c_str())) return __LINE__;

	// grant any privileges that cannot be enabled
	std::vector<std::wstring> vFailedPrivs = EnablePrivs(vPrivsToEnable);
	if (!vFailedPrivs.empty())
	{
		// ensure we did not get here by means of relaunching as elevated
		if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
		{
			PrintMessage(L"ERROR: Could not relaunch with privileges.\n");
			return __LINE__;
		}

		// adjust local security policy to add the necessary privileges
		std::vector<std::wstring> vAddedPrivs;
		if (AlterCurrentUserPrivs(vFailedPrivs, TRUE, &vAddedPrivs) == FALSE)
		{
			AlterCurrentUserPrivs(vAddedPrivs, FALSE);
			PrintMessage(L"ERROR: Could not adjust security policy. User may not be an administrator.\n");
			return __LINE__;
		}

		// relaunch under a new logon token to acquire the new privs, then restore original privs
		const int iRet = LaunchNewLogon(iArgc, aArgv);
		if (AlterCurrentUserPrivs(vAddedPrivs, FALSE) == FALSE && iRet == 0) return __LINE__;
		return iRet;
	}

	PROCESS_MITIGATION_DYNAMIC_CODE_POLICY tDynamicCodePolicy{};
	if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy,
		&tDynamicCodePolicy, sizeof(tDynamicCodePolicy)) &&
		tDynamicCodePolicy.ProhibitDynamicCode && !tDynamicCodePolicy.AllowThreadOptOut)
	{
		PrintMessage(L"ERROR: Process dynamic-code policy (ACG) prohibits WinPriv API hooks (error %lu).\n",
			static_cast<DWORD>(ERROR_DYNAMIC_CODE_BLOCKED));
		return ERROR_DYNAMIC_CODE_BLOCKED;
	}

	// kill any processes requested
	KillProcesses(vProcessesToKill);

	// Load the embedded library directly and retain all architecture images for descendant processes.
	std::array<std::vector<BYTE>, 3> vLibraryBytes;
	std::array<winpriv::memory::LibraryImage, 3> vImages{};
	for (size_t iIndex = 0; iIndex < vImages.size(); ++iIndex)
		vImages[iIndex] = LoadLibraryResource(vLibraryResources[iIndex].first, vLibraryBytes[iIndex]);
	std::vector<BYTE> vBundle;
	if (!winpriv::memory::CreateBundle(vImages, vBundle) ||
		!winpriv::memory::LoadBundle(reinterpret_cast<const winpriv::memory::LibraryBundle*>(vBundle.data())))
	{
		PrintMessage(L"ERROR: Could not load injection library (error %lu).\n", GetLastError());
		return __LINE__;
	}

	// create process with the requested window state and launch method
	STARTUPINFO o_StartInfo{ .cb = sizeof(STARTUPINFO),
		.dwFlags = iShowWindow == SW_NORMAL ? 0UL : STARTF_USESHOWWINDOW, .wShowWindow = iShowWindow };
	SHELLEXECUTEINFOW o_ShellExecute{ .cbSize = sizeof(SHELLEXECUTEINFOW), .fMask = SEE_MASK_NOCLOSEPROCESS |
		SEE_MASK_NOASYNC, .lpFile = sProcess.c_str(), .lpParameters = sProcessParams.c_str(), .nShow = iShowWindow };
	PROCESS_INFORMATION o_ProcessInfo{};
	const ULONGLONG iTimeStart = GetTickCount64();
	if (bUseShellExecute ? !ShellExecuteEx(&o_ShellExecute) : !CreateProcess(nullptr, sProcessParams.data(),
		nullptr, nullptr, FALSE, 0, nullptr, nullptr, &o_StartInfo, &o_ProcessInfo))
	{
		const DWORD iLaunchError = GetLastError();
		PrintMessage(L"ERROR: Problem starting target executable: %s (error %lu)\n",
			(bUseShellExecute ? sProcess : sProcessParams).c_str(), iLaunchError);
		return __LINE__;
	}
	if (bUseShellExecute) o_ProcessInfo.hProcess = o_ShellExecute.hProcess;
	if (o_ProcessInfo.hProcess == nullptr)
	{
		PrintMessage(L"ERROR: ShellExecute did not return a target process handle.\n");
		return __LINE__;
	}

	// wait for our process to complete
	SmartPointer<HANDLE> hProcess(CloseHandle, o_ProcessInfo.hProcess);
	SmartPointer<HANDLE> hThread(CloseHandle, o_ProcessInfo.hThread);
	if (WaitForSingleObject(hProcess, INFINITE) == WAIT_FAILED)
	{
		PrintMessage(L"ERROR: Problem waiting for process to complete.");
		return __LINE__;
	}

	// display execution time if requested
	if (bDisplayExecutionTime)
	{
		const double fSeconds = static_cast<double>(GetTickCount64() - iTimeStart) / 1000.0;
		PrintMessage(L"Execution Time In Seconds: %.3f\n", fSeconds);
	}

	// fetch process exit code
	DWORD iExitCode = 0;
	GetExitCodeProcess(hProcess, &iExitCode);
	return iExitCode;
}

//   ___      ___  __          __   __         ___  __
//  |__  |\ |  |  |__) \ /    |__) /  \ | |\ |  |  /__`
//  |___ | \|  |  |  \  |     |    \__/ | | \|  |  .__/
//

#ifdef _CONSOLE
int wmain(const int iArgc, wchar_t* aArgv[])
{
	return RunProgram(iArgc, aArgv);
}
#else
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PWSTR pCmdLine, _In_ int nCmdShow)
{
	return RunProgram(__argc, __wargv);
}
#endif
