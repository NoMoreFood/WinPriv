//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <wincred.h>

#include "WinPrivShared.h"

#pragma comment(lib,"credui.lib")

int LaunchElevated(int iArgc, wchar_t *aArgv[])
{
	// construct a command line containing just the argument passed this executable
	const std::wstring sCommand = L"/RelaunchComplete " + ArgvToCommandLine(2, iArgc - 1,
		std::vector<LPWSTR>({ aArgv, aArgv + iArgc }));

	// get the current working directory to pass to the child process
	WCHAR sCurrentDir[MAX_PATH + 1];
	_wgetcwd(sCurrentDir, _countof(sCurrentDir));

	// re-execute the process to run elevated
	SHELLEXECUTEINFO tShellExecInfo;
	ZeroMemory(&tShellExecInfo, sizeof(SHELLEXECUTEINFO));
	tShellExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	tShellExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOZONECHECKS;
	tShellExecInfo.hwnd = nullptr;
	tShellExecInfo.lpVerb = L"runas";
	tShellExecInfo.lpFile = aArgv[0];
	tShellExecInfo.lpParameters = sCommand.c_str();
	tShellExecInfo.nShow = SW_SHOWNORMAL;
	tShellExecInfo.hInstApp = nullptr;
	ShellExecuteEx(&tShellExecInfo);

	// wait for completion and return process exit code
	WaitForSingleObject(tShellExecInfo.hProcess, INFINITE);
	DWORD iExitCode = 0;
	GetExitCodeProcess(tShellExecInfo.hProcess, &iExitCode);
	return iExitCode;
}

int LaunchNewLogon(int iArgc, wchar_t *aArgv[])
{
	// setup the interface parameters for credential solicitation solicit credentials from the user
	CREDUI_INFO cui;
	cui.cbSize = sizeof(CREDUI_INFO);
	cui.hwndParent = nullptr;
	cui.pszMessageText = L"In order to active the privileges that you requested, " \
		"you must enter your credentials to acquire a new logon token.";
	cui.pszCaptionText = L"Enter Your Credentials";
	cui.hbmBanner = nullptr;

	// prompt the user for a set of credentials
	VOID * oOutInformation = nullptr;
	DWORD iOutInformationSize = 0;
	DWORD iAuthPackage = 0;
	DWORD iErr = 0;
	if ((iErr = CredUIPromptForWindowsCredentials(&cui, 0, &iAuthPackage, nullptr, 0,
		&oOutInformation, &iOutInformationSize, nullptr, 0)) != NO_ERROR)
	{
		PrintMessage(L"A problem occurred while soliciting the credentials.\n");
		return __LINE__;
	}

	// decode the credentials
	WCHAR sUserName[CREDUI_MAX_USERNAME_LENGTH + 1] = L"";
	DWORD iUserName = _countof(sUserName);
	WCHAR sPassword[CREDUI_MAX_PASSWORD_LENGTH + 1] = L"";
	DWORD iPassword = _countof(sPassword);
	if ((iErr = CredUnPackAuthenticationBuffer(CRED_PACK_PROTECTED_CREDENTIALS,
		oOutInformation, iOutInformationSize, sUserName, &iUserName, nullptr, nullptr, sPassword, &iPassword)) == FALSE)
	{
		PrintMessage(L"A problem occurred while decoding the credentials.\n");
		return __LINE__;
	}

	// pull apart the domain from the user name
	WCHAR sUserNameShort[CREDUI_MAX_USERNAME_LENGTH + 1] = L"";
	constexpr DWORD iUserNameShort = _countof(sUserNameShort);
	WCHAR sDomainName[CREDUI_MAX_DOMAIN_TARGET_LENGTH + 1] = L"";
	constexpr DWORD iDomainName = _countof(sDomainName);
	CredUIParseUserName(sUserName, sUserNameShort, iUserNameShort, sDomainName, iDomainName);

	STARTUPINFO o_StartInfo;
	PROCESS_INFORMATION o_ProcessInfo;
	ZeroMemory(&o_ProcessInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&o_StartInfo, sizeof(STARTUPINFO));
	o_StartInfo.cb = sizeof(STARTUPINFO);
	o_StartInfo.dwFlags = STARTF_USESHOWWINDOW;
	o_StartInfo.wShowWindow = SW_HIDE;

	// reconstruct a command line with a flag to indicate relaunch
	const std::vector<LPWSTR> sArgs({ aArgv, aArgv + iArgc });
	const std::wstring sCommand = ArgvToCommandLine(0, 0, sArgs) +
		L" /RelaunchElevated " + ArgvToCommandLine(1, iArgc - 1, sArgs);

	// get the current working directory to pass to the child process
	WCHAR sCurrentDir[MAX_PATH + 1];
	if (_wgetcwd(sCurrentDir, _countof(sCurrentDir)) == nullptr)
	{
		PrintMessage(L"ERROR: Problem obtaining current directory.\n");
		return __LINE__;
	}
	
	// relaunch process under altered security policy
	const LPWSTR sBlock = GetEnvironmentStrings();
	if (CreateProcessWithLogonW(sUserNameShort, sDomainName, sPassword, LOGON_WITH_PROFILE, nullptr, (LPWSTR) sCommand.c_str(), CREATE_UNICODE_ENVIRONMENT, sBlock,
		sCurrentDir, &o_StartInfo, &o_ProcessInfo) == 0)
	{
		PrintMessage(L"ERROR: Problem starting process (%d) (%s).\n", GetLastError(), sCommand.c_str());
		return __LINE__;
	}

	// zero out the password from memory
	SecureZeroMemory(sPassword, _countof(sPassword));

	// return process exit code
	WaitForSingleObject(o_ProcessInfo.hProcess, INFINITE);
	DWORD iExitCode = 0;
	GetExitCodeProcess(o_ProcessInfo.hProcess, &iExitCode);
	CloseHandle(o_ProcessInfo.hProcess);
	CloseHandle(o_ProcessInfo.hThread);
	return iExitCode;
}