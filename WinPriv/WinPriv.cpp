#include <windows.h>
#include <rpc.h>
#include <stdio.h>
#include <shlobj.h>

#include <map>
#include <string>
#include <vector>
#include <cctype>
#include <regex>
#include <sstream>
#include <iostream>
#include <iomanip>

#include "WinPrivShared.h"
#include "WinPrivResource.h"

#pragma comment(lib,"rpcrt4.lib")

extern int LaunchNewLogon(int iArgc, wchar_t *aArgv[]);
extern int LaunchElevated(int iArgc, wchar_t *aArgv[]);
extern std::map<std::wstring, std::wstring> GetPrivilegeList();
extern std::wstring GetWinPrivHelp();

int RunProgram(int iArgc, wchar_t *aArgv[])
{
	// get list of all privileges for general use later
	std::map<std::wstring, std::wstring> vPrivMaps = GetPrivilegeList();
	
	// list of privs populated by command line args that will be enabled
	std::vector<std::wstring> vPrivsToEnable;

	// initialize settings that will be inherited by subprocesses
	SetEnvironmentVariable(WINPRIV_EV_PRIVLIST, L"");
	SetEnvironmentVariable(WINPRIV_EV_MAC_OVERRIDE, L"");
	SetEnvironmentVariable(WINPRIV_EV_REG_OVERRIDE, L"");
	SetEnvironmentVariable(WINPRIV_EV_BACKUP_RESTORE, L"0");
	SetEnvironmentVariable(WINPRIV_EV_RELAUNCH_MODE, L"0");
	SetEnvironmentVariable(WINPRIV_EV_PARENT_PID, std::to_wstring(GetCurrentProcessId()).c_str());

	// registry override parameters populated by command line args
	std::wstring sRegistryOverride;
	
	// target executable and options provided by command line args
	std::wstring sProcessParams;

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
		// itself as an elevated process.  this is done after establishing a new
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

		// instructs winpriv to attempt to enable all privs on the system
		else if (_wcsicmp(sArg.c_str(), L"/WithAllPrivs") == 0)
		{
			for (std::pair<std::wstring, std::wstring> tPriv : vPrivMaps)
			{
				// add privs to list of privs we are going to set
				vPrivsToEnable.push_back(tPriv.first);
			}
		}

		// instructs winpriv to create a list of privs and display it to th user
		else if (_wcsicmp(sArg.c_str(), L"/ListPrivs") == 0)
		{
			// calculate column display size
			int iColumnSize = 0;
			for (std::pair<std::wstring, std::wstring> tPriv : vPrivMaps)
			{
				iColumnSize = max(iColumnSize, (int)tPriv.first.length());
			}

			// format the output into columns
			std::wstringstream ss;
			ss << std::setiosflags(std::ios::left);
			ss << std::setw(iColumnSize + 1) << L"Privilege Constant" << L" " << L"Privilege Description\n";
			ss << std::setw(iColumnSize + 1) << L"==================" << L" " << L"=====================\n";
			for (std::pair<std::wstring, std::wstring> tPriv : vPrivMaps)
			{
				ss << std::setw(iColumnSize + 1) << tPriv.first.c_str() << L" " << tPriv.second.c_str() << L"\n";
			}

			PrintMessage(L"%s", ss.str().c_str());
			return 0;
		}

		// instructs winpriv to impersonate the mac address on the system
		else if (_wcsicmp(sArg.c_str(), L"/MacOverride") == 0)
		{
			// one additional parameter is required
			if (iArg + 1 >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// format the mac address to a consistent format by removing colons or dashes
			std::wstring sMacAddr(aArgv[++iArg]);
			sMacAddr.erase(std::remove(sMacAddr.begin(), sMacAddr.end(), ':'), sMacAddr.end());
			sMacAddr.erase(std::remove(sMacAddr.begin(), sMacAddr.end(), '-'), sMacAddr.end());
			SetEnvironmentVariable(WINPRIV_EV_MAC_OVERRIDE, sMacAddr.c_str());
		}

		// instructs winpriv to override all registry queries for a specific key
		else if (_wcsicmp(sArg.c_str(), L"/RegOverride") == 0)
		{
			// four additional parameters are required
			if (iArg + 4 >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// append the registry key override data which should be four params:
			// <key name> <value name> <value type> <value data>
			// currently no error checking is being done for the proper structure 
			sRegistryOverride += ArgvToCommandLine(iArg + 1, (iArg += 4),
				std::vector<LPWSTR>({ aArgv, aArgv + iArgc })) + L" ";
		}

		// instructs winpriv to report all accesses of the specified registry key or
		// any subkeys as being not found to the target process
		else if (_wcsicmp(sArg.c_str(), L"/RegBlock") == 0)
		{
			// one additional parameter is required
			if (iArg + 1 >= iArgc)
			{
				PrintMessage(L"ERROR: Not enough parameters specified for: %s\n", sArg.c_str());
				return __LINE__;
			}

			// this capability is implemented by the registry override code 
			// block by indicating a winpriv proprietary type called REG_BLOCK
			sRegistryOverride += ArgvToCommandLine(iArg + 1, iArg += 1,
				std::vector<LPWSTR>({ aArgv, aArgv + iArgc })) + L" N/A REG_BLOCK N/A ";
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

	// gets the temp path env string (no guarantee it is a valid path)
	WCHAR sTempDirectory[_MAX_PATH];
	if (GetTempPath(sizeof(sTempDirectory) / sizeof(WCHAR), sTempDirectory) == 0)
	{
		return __LINE__;
	}

	// generate a uuid string to create the temporary file
	RPC_WSTR sUUID;
	UUID tUUID;
	UuidCreate(&tUUID);
	UuidToString(&tUUID, &sUUID);

	// generate the files names to use for library names
	CHAR sTempLibraryX86[_MAX_PATH + 1];
	CHAR sTempLibraryX64[_MAX_PATH + 1];
	sprintf_s(sTempLibraryX86, _countof(sTempLibraryX86), "%S\\%S-32.dll", sTempDirectory, (LPWSTR)sUUID);
	sprintf_s(sTempLibraryX64, _countof(sTempLibraryX64), "%S\\%S-64.dll", sTempDirectory, (LPWSTR)sUUID);

	// cleanup the guid structure
	RpcStringFree(&sUUID);

	// locate the resource that has the embedded library
	HRSRC hResX86 = FindResource(NULL, MAKEINTRESOURCE(IDR_RT_RCDATA_X86), L"RT_RCDATA");
	HRSRC hResX64 = FindResource(NULL, MAKEINTRESOURCE(IDR_RT_RCDATA_X64), L"RT_RCDATA");
	if (hResX86 == NULL || hResX64 == NULL)
	{
		PrintMessage(L"ERROR: Could not locate internal resource data.\n");
		return __LINE__;
	}

	// load the resource that has the embedded detours library
	HGLOBAL hResourceLoadedX86 = LoadResource(NULL, hResX86);
	HGLOBAL hResourceLoadedX64 = LoadResource(NULL, hResX64);
	if (hResourceLoadedX86 == NULL || hResourceLoadedX64 == NULL)
	{
		PrintMessage(L"ERROR: Could not load internal resource data.\n");
		return __LINE__;
	}

	// create the library files
	HANDLE hTempFileX86 = CreateFileA(sTempLibraryX86, GENERIC_ALL, 0,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hTempFileX64 = CreateFileA(sTempLibraryX64, GENERIC_ALL, 0,
		NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hTempFileX86 == INVALID_HANDLE_VALUE || hTempFileX64 == INVALID_HANDLE_VALUE)
	{
		PrintMessage(L"ERROR: Problem creating temporary library file.\n");
		return __LINE__;
	}

	// get the size of the data to write to the files
	DWORD wSizeResX86 = SizeofResource(NULL, hResX86);
	DWORD wSizeResX64 = SizeofResource(NULL, hResX64);

	// write the resource into the temporary file
	if (WriteFile(hTempFileX86, hResourceLoadedX86, wSizeResX86, &wSizeResX86, NULL) == 0 ||
		WriteFile(hTempFileX64, hResourceLoadedX64, wSizeResX64, &wSizeResX64, NULL) == 0)
	{
		PrintMessage(L"ERROR: Problem writing temporary library file.\n");
		return __LINE__;
	}

	// close the temporary file so our created process can use it
	if (CloseHandle(hTempFileX86) == 0 || CloseHandle(hTempFileX64) == 0)
	{
		DeleteFileA(sTempLibraryX86);
		DeleteFileA(sTempLibraryX64);
		PrintMessage(L"ERROR: Problem closing temporary library file.\n");
		return __LINE__;
	}

	STARTUPINFO o_StartInfo;
	PROCESS_INFORMATION o_ProcessInfo;
	ZeroMemory(&o_ProcessInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&o_StartInfo, sizeof(STARTUPINFO));
	o_StartInfo.cb = sizeof(STARTUPINFO);

	// load the detour library into memory - the main reason we do this
	// is so that the create process command below will load the detour library
	// that matches the architecture of the target executable
	LoadLibraryA((sizeof(INT_PTR) == sizeof(LONGLONG)) ? sTempLibraryX64 : sTempLibraryX86);
	
	// create process and detour
	if (CreateProcess(NULL, (LPWSTR)sProcessParams.c_str(), NULL, NULL, FALSE, 0, NULL, NULL,
		&o_StartInfo, &o_ProcessInfo) == 0)
	{
		PrintMessage(L"ERROR: Problem starting target executable: %s\n", sProcessParams.c_str());
		DeleteFileA(sTempLibraryX86);
		DeleteFileA(sTempLibraryX64);
		return __LINE__;
	}

	// wait for our process to complete
	if (WaitForSingleObject(o_ProcessInfo.hProcess, INFINITE) == WAIT_FAILED)
	{
		PrintMessage(L"ERROR: Problem waiting for process to complete.");
		DeleteFileA(sTempLibraryX86);
		DeleteFileA(sTempLibraryX64);
		return __LINE__;
	}

	// cleanup
	DeleteFileA(sTempLibraryX86);
	DeleteFileA(sTempLibraryX64);

	// return process exit code
	DWORD iExitCode = 0;
	GetExitCodeProcess(o_ProcessInfo.hProcess, &iExitCode);
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
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
	return RunProgram(__argc, __wargv);
}
#endif