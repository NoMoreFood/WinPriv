//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define _WINSOCKAPI_

#include <Windows.h>
#include <rpc.h>
#include <ShlObj.h>
#include <WS2tcpip.h>

#include <cstdio>
#include <map>
#include <string>
#include <vector>
#include <cctype>
#include <regex>
#include <sstream>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <codecvt>

#include "WinPrivShared.h"
#include "WinPrivResource.h"

#pragma comment(lib,"rpcrt4.lib")

extern int LaunchNewLogon(int iArgc, wchar_t *aArgv[]);
extern int LaunchElevated(int iArgc, wchar_t *aArgv[]);
extern std::map<std::wstring, std::wstring> GetPrivilegeList();
extern std::wstring GetWinPrivHelp();

bool WriteResourceToFile(std::wstring sOutputDirectory, DWORD iResourceId)
{
	// locate the resource that has the embedded library
	HRSRC hRes = FindResource(NULL, MAKEINTRESOURCE(iResourceId), L"RT_RCDATA");
	if (hRes == NULL)
	{
		PrintMessage(L"ERROR: Could not locate internal resource data.\n");
		return false;
	}

	// load the resource that has the embedded detours library
	HGLOBAL hResourceLoadedX86 = LoadResource(NULL, hRes);
	if (hResourceLoadedX86 == NULL)
	{
		PrintMessage(L"ERROR: Could not load internal resource data.\n");
		return false;
	}

	// create the library files
	HANDLE hTempFile = CreateFile(sOutputDirectory.c_str(), GENERIC_WRITE, 0,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTempFile == INVALID_HANDLE_VALUE)
	{
		PrintMessage(L"ERROR: Problem creating library file.\n");
		return false;
	}

	// write the resource into the temporary file
	DWORD wSizeRes = SizeofResource(NULL, hRes);
	if (WriteFile(hTempFile, hResourceLoadedX86, wSizeRes, &wSizeRes, NULL) == 0)
	{
		PrintMessage(L"ERROR: Problem writing library file.\n");
		return false;
	}

	// close out handles so process can use it
	if (CloseHandle(hTempFile) == 0)
	{
		PrintMessage(L"ERROR: Problem closing library file.\n");
		return false;
	}
	
	return true;
}

std::wstring GetRunningExecutable()
{
	// attempt to get the directory to the path to this executable
	std::wstring sThisExecutable;
	sThisExecutable.resize(MAX_PATH + 1);
	if (GetModuleFileName(NULL, sThisExecutable.data(), MAX_PATH + 1) == 0)
	{
		PrintMessage(L"ERROR: Error fetching currently executable path.\n");
		std::exit(0);
		return L"";
	}

	sThisExecutable.resize(sThisExecutable.find(L'\0'));
	return sThisExecutable;
}

std::wstring GetLocalLibraryPath(bool bIs64Bit)
{
	std::wstring sThisExecutable = GetRunningExecutable();

	// trim of final path element
	std::wstring sBasePath = sThisExecutable.substr(0, sThisExecutable.find_last_of(L'\\'));
	
	// return directory name
	return sBasePath + (bIs64Bit ? L"\\WinPrivLibrary-x64.dll" : L"\\WinPrivLibrary-x86.dll");
}

int RunProgram(int iArgc, wchar_t *aArgv[])
{
	// get list of all privileges for general use later
	std::map<std::wstring, std::wstring> vPrivMaps = GetPrivilegeList();
	
	// list of privs populated by command line args that will be enabled
	std::vector<std::wstring> vPrivsToEnable;

	// initialize settings that will be inherited by subprocesses
	SetEnvironmentVariable(WINPRIV_EV_PRIVLIST, L"");
	SetEnvironmentVariable(WINPRIV_EV_HOST_OVERRIDE, L"");
	SetEnvironmentVariable(WINPRIV_EV_MAC_OVERRIDE, L"");
	SetEnvironmentVariable(WINPRIV_EV_REG_OVERRIDE, L"");
	SetEnvironmentVariable(WINPRIV_EV_BACKUP_RESTORE, L"0");
	SetEnvironmentVariable(WINPRIV_EV_BREAK_LOCKS, L"0");
	SetEnvironmentVariable(WINPRIV_EV_ADMIN_IMPERSONATE, L"0");
	SetEnvironmentVariable(WINPRIV_EV_SERVER_EDITION, L"0");
	SetEnvironmentVariable(WINPRIV_EV_RECORD_CRYPTO, L"");
	SetEnvironmentVariable(WINPRIV_EV_SQL_CONNECT_SHOW, L"");
	SetEnvironmentVariable(WINPRIV_EV_SQL_CONNECT_SEARCH, L"");
	SetEnvironmentVariable(WINPRIV_EV_SQL_CONNECT_REPLACE, L"");
	SetEnvironmentVariable(WINPRIV_EV_RELAUNCH_MODE, L"0");
	SetEnvironmentVariable(WINPRIV_EV_PARENT_PID, std::to_wstring(GetCurrentProcessId()).c_str());

	// registry override parameters populated by command line args
	std::wstring sRegistryOverride;

	// host override parameters populated by command line args
	std::wstring sHostOverride;

	// target executable and options provided by command line args
	std::wstring sProcessParams;

	// whether or not to provide execution time
	bool bDisplayExecutionTime = false;

	// whether or not to kill any processes
	std::vector<std::wstring> vProcessesToKill;

	// read command line from cfg file if it exists
	std::wstring sExecutable = GetRunningExecutable();
	std::wstring sCfgPath = sExecutable.substr(0, sExecutable.find_last_of(L".exe") - 3) + L".cfg";
	if (GetFileAttributes(sCfgPath.c_str()) != INVALID_FILE_ATTRIBUTES)
	{
		std::wifstream oFileStream(sCfgPath);
		oFileStream.imbue(std::locale(std::locale::empty(), new std::codecvt_utf8<wchar_t>));
		std::wstringstream oStringStream;
		oStringStream << oFileStream.rdbuf();
		aArgv = CommandLineToArgvW((L"IGNORE " + oStringStream.str()).c_str(), &iArgc);
	}

	// enumerate arguments
	for (int iArg = 1; iArg < iArgc; iArg++)
	{
		// convert to a std string for ease
		std::wstring sArg(aArgv[iArg]);

		// as soon as we see one parameter that does not start with
		// a slash, then assume we are processing the command to run
		if (sArg.c_str()[0] != L'/')
		{
			sProcessParams = ArgvToCommandLine(iArg, iArgc - 1,
				std::vector<LPWSTR>({ aArgv, aArgv + iArgc }));
			break;
		}

		// this switch is only called by winpriv to instructed itself to relaunch
		// itself as an elevated process. this is done after establishing a new
		// logon following new privs have been granted
		else if (_wcsicmp(sArg.c_str(), L"/RelaunchElevated") == 0)
		{
			// launch as elevated
			return LaunchElevated(iArgc, aArgv);
		}

		// this switch is only called by winpriv to instruct itself that is has
		// been launched with a new, privileged logon and it now should be able
		// to launch the target process with the newly acquired privileges.
		// this is used to control whether an exit prompt appears in command line
		// programs and to prevent infinite relaunching if the new privileges can
		// not be enabled
		else if (_wcsicmp(sArg.c_str(), L"/RelaunchComplete") == 0)
		{
			// update relaunch phase to prevent recursion
			SetEnvironmentVariable(WINPRIV_EV_RELAUNCH_MODE, L"1");
		}

		// this instructs winpriv to attempt to enable a user-provided list of privs
		else if (_wcsicmp(sArg.c_str(), L"/WithPrivs") == 0)
		{
			// one additional parameter is required
			if (iArg + 1 >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// tokenize the comma-delimited string and add the privs to the priv vector
			std::wstring sPrivString(aArgv[++iArg]);
			std::wregex oRegex(L",");
			std::wsregex_token_iterator oFirst{ sPrivString.begin(), sPrivString.end(), oRegex, -1 }, oLast;
			std::vector<std::wstring> vPrivsToAdd({ oFirst, oLast });
			vPrivsToEnable.insert(vPrivsToEnable.end(), vPrivsToAdd.begin(), vPrivsToAdd.end());
		}

		// this instructs winpriv to kill any processes with the specified name
		else if (_wcsicmp(sArg.c_str(), L"/KillProcess") == 0)
		{
			constexpr int iArgsRequired = 1;

			// one additional parameter is required
			if (iArg + iArgsRequired >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// add to a list or processes to kill
			vProcessesToKill.push_back(aArgv[iArg + 1]);
			iArg += iArgsRequired;
		}

		// this instructs winpriv to write out any temporary dlls into the following directory
		else if (_wcsicmp(sArg.c_str(), L"/ExtractLibrary") == 0)
		{
			if (WriteResourceToFile(GetLocalLibraryPath(false), IDR_RT_RCDATA_X86) == false ||
				WriteResourceToFile(GetLocalLibraryPath(true), IDR_RT_RCDATA_X64) == false)
			{
				PrintMessage(L"ERROR: Failed to extract libraries.\n");
				return __LINE__;
			}

			return 0;
		}

		// instructs winpriv to attempt to enable all privs on the system
		else if (_wcsicmp(sArg.c_str(), L"/WithAllPrivs") == 0)
		{
			for (std::pair<std::wstring, std::wstring> tPriv : vPrivMaps)
			{
				// add privs to list of privs we are going to set
				vPrivsToEnable.push_back(tPriv.first);
			}
		}

		// instructs winpriv to create a list of privs and display it to the user
		else if (_wcsicmp(sArg.c_str(), L"/ListPrivs") == 0)
		{
			// calculate column display size
			size_t iColumnSize = 0;
			for (std::pair<std::wstring, std::wstring> tPriv : vPrivMaps)
			{
				iColumnSize = max(iColumnSize, tPriv.first.length());
			}

			// format the output into columns
			std::wstringstream ss;
			ss << std::setiosflags(std::ios::left);
			ss << std::setw(iColumnSize + 1ULL) << L"Privilege Constant" << L" " << L"Privilege Description\n";
			ss << std::setw(iColumnSize + 1ULL) << L"==================" << L" " << L"=====================\n";
			for (std::pair<std::wstring, std::wstring> tPriv : vPrivMaps)
			{
				ss << std::setw(iColumnSize + 1ULL) << tPriv.first.c_str() << L" " << tPriv.second.c_str() << L"\n";
			}

			PrintMessage(L"%s", ss.str().c_str());
			return 0;
		}

		// instructs winpriv to impersonate the mac address on the system
		else if (_wcsicmp(sArg.c_str(), L"/MacOverride") == 0)
		{
			constexpr int iArgsRequired = 1;

			// one additional parameter is required
			if (iArg + iArgsRequired >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// format the mac address to a consistent format by removing colons or dashes
			std::wstring sMacAddr(aArgv[iArg + 1]);
			sMacAddr.erase(std::remove(sMacAddr.begin(), sMacAddr.end(), ':'), sMacAddr.end());
			sMacAddr.erase(std::remove(sMacAddr.begin(), sMacAddr.end(), '-'), sMacAddr.end());
			SetEnvironmentVariable(WINPRIV_EV_MAC_OVERRIDE, sMacAddr.c_str());
			iArg += iArgsRequired;
		}

		// instructs winpriv to override all registry queries for a specific key
		else if (_wcsicmp(sArg.c_str(), L"/RegOverride") == 0)
		{
			constexpr int iArgsRequired = 4;

			// four additional parameters are required
			if (iArg + iArgsRequired >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// append the registry key override data which should be four params:
			// <key name> <value name> <value type> <value data>
			// currently no error checking is being done for the proper structure
			sRegistryOverride += ArgvToCommandLine(iArg + 1, iArg + iArgsRequired,
				std::vector<LPWSTR>({ aArgv, aArgv + iArgc })) + L" ";
			iArg += iArgsRequired;
		}

		// instructs winpriv to report all accesses of the specified registry key or
		// any subkeys as being not found to the target process
		else if (_wcsicmp(sArg.c_str(), L"/RegBlock") == 0)
		{
			constexpr int iArgsRequired = 1;

			// one additional parameter is required
			if (iArg + 1 >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// this capability is implemented by the registry override code
			// block by indicating a winpriv proprietary type called REG_BLOCK
			sRegistryOverride += ArgvToCommandLine(iArg + 1, iArg + iArgsRequired,
				std::vector<LPWSTR>({ aArgv, aArgv + iArgc })) + L" N/A REG_BLOCK N/A ";
			iArg += iArgsRequired;
		}
		
		// instructs winpriv to override the fips setting on the system
		else if (_wcsicmp(sArg.c_str(), L"/FipsOn") == 0 || _wcsicmp(sArg.c_str(), L"/FipsOff") == 0)
		{
			// implement the fips override using the registry override capability
			sRegistryOverride += L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy ";
			sRegistryOverride += L"Enabled ";
			sRegistryOverride += L"REG_DWORD ";
			sRegistryOverride += (_wcsicmp(sArg.c_str(), L"/FipsOn") == 0) ? L"1 " : L"0 ";
		}
		
		// instructs winpriv to block access to popular group policy areas
		else if (_wcsicmp(sArg.c_str(), L"/PolicyBlock") == 0)
		{
			sRegistryOverride += L"HKCU\\SOFTWARE\\Policies ";
			sRegistryOverride += L"N/A REG_BLOCK N/A ";

			sRegistryOverride += L"HKLM\\SOFTWARE\\Policies ";
			sRegistryOverride += L"N/A REG_BLOCK N/A ";

			sRegistryOverride += L"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies ";
			sRegistryOverride += L"N/A REG_BLOCK N/A ";

			sRegistryOverride += L"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies ";
			sRegistryOverride += L"N/A REG_BLOCK N/A ";
		}

		// instructs winpriv to override all host name lookups
		else if (_wcsicmp(sArg.c_str(), L"/HostOverride") == 0)
		{
			constexpr int iArgsRequired = 2;

			// four additional parameters are required
			if (iArg + iArgsRequired >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// initialize winsock
			WSADATA tWSAData;
			if (WSAStartup(MAKEWORD(2, 2), &tWSAData) != 0)
			{
				return __LINE__;
			}

			// first lookup the address
			PADDRINFOW tResult;
			INT iGetAddrInfoResult = GetAddrInfoW(aArgv[iArg + 2], NULL, NULL, &tResult);
			WSACleanup();
			if (iGetAddrInfoResult != 0)
			{
				return __LINE__;
			}

			// convert the address to a string
			WCHAR sAddress[16];
			InetNtop(AF_INET, &((PSOCKADDR_IN)tResult->ai_addr)->sin_addr, sAddress, _countof(sAddress));

			// append the host override data which should be two params:
			// <host name to override> <host override value>
			sHostOverride += std::wstring(aArgv[iArg + 1]) + L" " + sAddress + L" ";
			iArg += iArgsRequired;
		}

		// instruct winpriv to enable backup and restore privileges and send in
		// extra flags to file open/create command to exercise the privileges
		else if (_wcsicmp(sArg.c_str(), L"/BypassFileSecurity") == 0)
		{
			vPrivsToEnable.push_back(SE_RESTORE_NAME);
			vPrivsToEnable.push_back(SE_BACKUP_NAME);
			vPrivsToEnable.push_back(SE_TAKE_OWNERSHIP_NAME);
			vPrivsToEnable.push_back(SE_CHANGE_NOTIFY_NAME);
			SetEnvironmentVariable(WINPRIV_EV_BACKUP_RESTORE, L"1");
		}

		// instruct winpriv to break remote file locks if a file operation
		// cannot complete due to a remote file lock
		else if (_wcsicmp(sArg.c_str(), L"/BreakRemoteLocks") == 0)
		{
			SetEnvironmentVariable(WINPRIV_EV_BREAK_LOCKS, L"1");
		}

		// instruct winpriv to tell the target process that the current user is
		// an admin regardless of security tokens or group memberships
		else if (_wcsicmp(sArg.c_str(), L"/AdminImpersonate") == 0)
		{
			SetEnvironmentVariable(L"__COMPAT_LAYER", L"RunAsInvoker");
			SetEnvironmentVariable(WINPRIV_EV_ADMIN_IMPERSONATE, L"1");
		}

		// instruct winpriv to tell the target process that the current 
		// operating system is a server operating sysem
		else if (_wcsicmp(sArg.c_str(), L"/ServerEdition") == 0)
		{
			SetEnvironmentVariable(WINPRIV_EV_SERVER_EDITION, L"1");
		}

		// instructs winpriv to record encrypt/decrypt operations
		else if (_wcsicmp(sArg.c_str(), L"/RecordCrypto") == 0)
		{
			constexpr int iArgsRequired = 1;

			// one additional parameter is required
			if (iArg + iArgsRequired >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// if not 'SHOW' then ensure the passed directory exists
			std::wstring sRecordCrypto(aArgv[iArg + 1]);
			if (_wcsicmp(sRecordCrypto.c_str(), L"SHOW") != 0)
			{
				if (CreateDirectory(sRecordCrypto.c_str(), NULL) == FALSE &&
					ERROR_ALREADY_EXISTS != GetLastError())
				{
					PrintMessage(L"ERROR: Could not create the specified directory for /CrytpoRecord");
					return __LINE__;
				}
			}

			// store the crypto variable in the environment variable to pass to child
			SetEnvironmentVariable(WINPRIV_EV_RECORD_CRYPTO, sRecordCrypto.c_str());
			iArg += iArgsRequired;
		}

		// instructs winpriv to show or replace sql connection information
		else if (_wcsicmp(sArg.c_str(), L"/SqlConnectShow") == 0)
		{
			// store the sql connect info in the environment variable to pass to child
			SetEnvironmentVariable(WINPRIV_EV_SQL_CONNECT_SHOW, L"1");
		}

		// instructs winpriv to show or replace sql connection information
		else if (_wcsicmp(sArg.c_str(), L"/SqlConnectSearchReplace") == 0)
		{
			constexpr int iArgsRequired = 2;

			// one additional parameter is required
			if (iArg + iArgsRequired >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// store the sql connect info in the environment variable to pass to child
			SetEnvironmentVariable(WINPRIV_EV_SQL_CONNECT_SEARCH, aArgv[iArg + 1]);
			SetEnvironmentVariable(WINPRIV_EV_SQL_CONNECT_REPLACE, aArgv[iArg + 2]);
			iArg += iArgsRequired;
		}

		// instruct winpriv to display process execution time
		else if (_wcsicmp(sArg.c_str(), L"/MeasureTime") == 0)
		{
			bDisplayExecutionTime = true;
		}

		// instructs to display help by break from the loop with causes no
		// target process to be defined
		else if (_wcsicmp(sArg.c_str(), L"/Help") == 0 || _wcsicmp(sArg.c_str(), L"/?") == 0)
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
	if (sProcessParams.length() == 0)
	{
		PrintMessage(L"%s",GetWinPrivHelp().c_str());
		return __LINE__;
	}

	// setup the registry override and block values to pass to child processes
	TrimString(sRegistryOverride, L' ');
	SetEnvironmentVariable(WINPRIV_EV_REG_OVERRIDE, sRegistryOverride.c_str());

	// setup the host override values to pass to child processes
	TrimString(sHostOverride, L' ');
	SetEnvironmentVariable(WINPRIV_EV_HOST_OVERRIDE, sHostOverride.c_str());

	// sort privs, remove duplicate privs, and reconstruct into a list of privs
	// that can be set as an environment variable and passed to a child process
	std::sort(vPrivsToEnable.begin(), vPrivsToEnable.end());
	vPrivsToEnable.erase(std::unique(vPrivsToEnable.begin(), vPrivsToEnable.end()), vPrivsToEnable.end());
	std::wstring sPrivsToSetList = L"";
	for (std::wstring sPrivToSet : vPrivsToEnable)
	{
		if (vPrivMaps.find(sPrivToSet) == vPrivMaps.end())
		{
			PrintMessage(L"ERROR: Invalid privilege specified: %s\n", sPrivToSet.c_str());
			return __LINE__;
		}

		// create a new list to be passed to subprocesses
		sPrivsToSetList += sPrivToSet + L",";
	}

	// setup priv list environment variable to pass to child processes
	TrimString(sPrivsToSetList, L',');
	SetEnvironmentVariable(WINPRIV_EV_PRIVLIST, sPrivsToSetList.c_str());

	// attempt to enable all privileges specified
	std::vector<std::wstring> vFailedPrivs = EnablePrivs(vPrivsToEnable);

	// grant any privileges that cannot be enabled
	if (vFailedPrivs.size() > 0)
	{
		// ensure we did not get here by means of relaunching as elevated
		if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
		{
			PrintMessage(L"ERROR: Could not relaunch with privileges.\n");
			return __LINE__;
		}

		// adjust local security policy to add the necessary privileges
		if (AlterCurrentUserPrivs(vFailedPrivs, TRUE) == FALSE)
		{
			PrintMessage(L"ERROR: Could not adjust security policy. User may not be an administrator.\n");
			return __LINE__;
		}

		// relaunch under a new logon token to acquire the new privs
		int iRet = LaunchNewLogon(iArgc, aArgv);

		// restore original privs and return
		AlterCurrentUserPrivs(vFailedPrivs, FALSE);
		return iRet;
	}
	
	// user the standard temp directory
	std::wstring sTempDirectory;
	sTempDirectory.resize(MAX_PATH + 1);
	if (GetTempPath(MAX_PATH, sTempDirectory.data()) == 0)
	{
		return __LINE__;
	}
	sTempDirectory.resize(sTempDirectory.find(L'\0'));
	
	// ensure temp directory actually exists
	if (GetFileAttributes(sTempDirectory.c_str()) == INVALID_FILE_ATTRIBUTES &&
		CreateDirectory(sTempDirectory.c_str(), NULL) == 0)
	{
		PrintMessage(L"ERROR: Could not create temporary directory for library files.\n");
		return __LINE__;
	}
	
	// fetch the default library paths
	bool bCleanupLibrary = false;
	std::wstring sTempLibraryX86 = GetLocalLibraryPath(false);
	std::wstring sTempLibraryX64 = GetLocalLibraryPath(true);;

	if (GetFileAttributes(sTempLibraryX86.c_str()) == INVALID_FILE_ATTRIBUTES ||
		GetFileAttributes(sTempLibraryX64.c_str()) == INVALID_FILE_ATTRIBUTES)
	{
		// generate a uuid string to create the temporary file
		bCleanupLibrary = true;
		RPC_WSTR sUUID;
		UUID tUUID;
		if (UuidCreate(&tUUID) != RPC_S_OK ||
			UuidToString(&tUUID, &sUUID) != RPC_S_OK)
		{
			PrintMessage(L"ERROR: Could not generate name for temporary file.\n");
			return __LINE__;
		}

		// generate the files names to use for library names
		sTempLibraryX86 = sTempDirectory + L"\\" + LPWSTR(sUUID) + L"-32.dll";
		sTempLibraryX64 = sTempDirectory + L"\\" + LPWSTR(sUUID) + L"-64.dll";

		// cleanup the guid structure
		RpcStringFree(&sUUID);

		// create the library files
		if (WriteResourceToFile(sTempLibraryX86, IDR_RT_RCDATA_X86) == false ||
			WriteResourceToFile(sTempLibraryX64, IDR_RT_RCDATA_X64) == false)
		{
			DeleteFile(sTempLibraryX86.c_str());
			DeleteFile(sTempLibraryX64.c_str());
			PrintMessage(L"ERROR: Problem creating temporary library file.\n");
			return __LINE__;
		}
	}

	// kill any processes requested
	for (std::wstring & sProcessName : vProcessesToKill)
	{
		KillProcess(sProcessName);
	}

	STARTUPINFO o_StartInfo;
	PROCESS_INFORMATION o_ProcessInfo;
	ZeroMemory(&o_ProcessInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&o_StartInfo, sizeof(STARTUPINFO));
	o_StartInfo.cb = sizeof(STARTUPINFO);

	// load the detour library into memory - the main reason we do this
	// is so that the create process command below will load the detour library
	// that matches the architecture of the target executable
	HMODULE hLibrary = LoadLibrary((sizeof(INT_PTR) == sizeof(LONGLONG)) 
		? sTempLibraryX64.c_str() : sTempLibraryX86.c_str());

	// create process and detour
	ULONGLONG iTimeStart = GetTickCount64();;
	if (CreateProcess(NULL, (LPWSTR)sProcessParams.c_str(), NULL, NULL, FALSE, 0, NULL, NULL,
		&o_StartInfo, &o_ProcessInfo) == 0)
	{
		PrintMessage(L"ERROR: Problem starting target executable: %s\n", sProcessParams.c_str());
		if (bCleanupLibrary)
		{
			DeleteFile(sTempLibraryX86.c_str());
			DeleteFile(sTempLibraryX64.c_str());
		}
		return __LINE__;
	}

	// wait for our process to complete
	if (WaitForSingleObject(o_ProcessInfo.hProcess, INFINITE) == WAIT_FAILED)
	{
		PrintMessage(L"ERROR: Problem waiting for process to complete.");
		if (bCleanupLibrary)
		{
			DeleteFile(sTempLibraryX86.c_str());
			DeleteFile(sTempLibraryX64.c_str());
		}
		return __LINE__;
	}

	// display execution time if requested
	if (bDisplayExecutionTime)
	{
		ULONGLONG iTimeStop = GetTickCount64();
		PrintMessage(L"Execution Time In Seconds: %.3f", ((double)(iTimeStop - iTimeStart)) / 1000.0);
	}

	// fetch process exit code
	DWORD iExitCode = 0;
	GetExitCodeProcess(o_ProcessInfo.hProcess, &iExitCode);
	CloseHandle(o_ProcessInfo.hProcess);
	CloseHandle(o_ProcessInfo.hThread);

	// cleanup
	if (hLibrary != NULL) FreeLibrary(hLibrary);
	if (bCleanupLibrary)
	{
		DeleteFile(sTempLibraryX86.c_str());
		DeleteFile(sTempLibraryX64.c_str());
	}
	return iExitCode;
}

//   ___      ___  __          __   __         ___  __
//  |__  |\ |  |  |__) \ /    |__) /  \ | |\ |  |  /__`
//  |___ | \|  |  |  \  |     |    \__/ | | \|  |  .__/
//

#ifdef _CONSOLE
int wmain(int iArgc, wchar_t *aArgv[])
{
	RunProgram(iArgc, aArgv);
}
#else
int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ PWSTR pCmdLine, _In_ int nCmdShow)
{
	return RunProgram(__argc, __wargv);
}
#endif