//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <Windows.h>
#include <winternl.h>
#include <cstdio>
#include <wincred.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <memory>
#include <Sddl.h>
#include <LMCons.h>

#include "WinPrivShared.h"

#pragma comment(lib,"credui.lib")
#pragma comment(lib,"wtsapi32.lib")
#pragma comment(lib,"userenv.lib")

int LaunchElevated(const int iArgc, wchar_t *aArgv[])
{
	// construct a command line containing just the argument passed this executable
	const std::wstring sCommand = L"/RelaunchComplete " + ArgvToCommandLine(2, iArgc - 1,
		std::vector<LPWSTR>({ aArgv, aArgv + iArgc }));

	// get the current working directory to pass to the child process
	WCHAR sCurrentDir[MAX_PATH + 1];
	_wgetcwd(sCurrentDir, _countof(sCurrentDir));

	// re-execute the process to run elevated with designated initializers
	SHELLEXECUTEINFO tShellExecInfo{
		.cbSize = sizeof(SHELLEXECUTEINFO),
		.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOZONECHECKS,
		.lpVerb = L"runas",
		.lpFile = aArgv[0],
		.lpParameters = sCommand.c_str(),
		.nShow = SW_SHOWNORMAL
	};
	
	if (ShellExecuteEx(&tShellExecInfo) == FALSE)
	{
		PrintMessage(L"ERROR: Could not relaunch as elevated.\n");
		return __LINE__;
	}

	// wait for completion and return process exit code
	WaitForSingleObject(tShellExecInfo.hProcess, INFINITE);
	DWORD iExitCode = 0;
	GetExitCodeProcess(tShellExecInfo.hProcess, &iExitCode);
	CloseHandle(tShellExecInfo.hProcess);
	return iExitCode;
}

int LaunchNewLogon(const int iArgc, wchar_t *aArgv[])
{
	// setup the interface parameters for credential solicitation solicit credentials from the user
	CREDUI_INFO cui{ .cbSize = sizeof(CREDUI_INFO) };
	cui.pszMessageText = L"In order to active the privileges that you requested, " \
		"you must enter your credentials to acquire a new logon token.";
	cui.pszCaptionText = L"Enter Your Credentials";

	// prompt the user for a set of credentials
	PVOID oOutInformation = nullptr;
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

	STARTUPINFO o_StartInfo{
		.cb = sizeof(STARTUPINFO),
		.dwFlags = STARTF_USESHOWWINDOW,
		.wShowWindow = SW_HIDE
	};
	
	PROCESS_INFORMATION o_ProcessInfo{};

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
	const BOOL bCreateResult = CreateProcessWithLogonW(sUserNameShort, sDomainName, sPassword, LOGON_WITH_PROFILE, nullptr, (LPWSTR) sCommand.c_str(), CREATE_UNICODE_ENVIRONMENT, sBlock,
		sCurrentDir, &o_StartInfo, &o_ProcessInfo);
	FreeEnvironmentStrings(sBlock);

	// zero out the password from memory as early as possible
	SecureZeroMemory(sPassword, sizeof(sPassword));

	if (bCreateResult == 0)
	{
		PrintMessage(L"ERROR: Problem starting process (%d) (%s).\n", GetLastError(), sCommand.c_str());
		return __LINE__;
	}

	// return process exit code
	WaitForSingleObject(o_ProcessInfo.hProcess, INFINITE);
	DWORD iExitCode = 0;
	GetExitCodeProcess(o_ProcessInfo.hProcess, &iExitCode);
	CloseHandle(o_ProcessInfo.hProcess);
	CloseHandle(o_ProcessInfo.hThread);
	return iExitCode;
}

static constexpr WCHAR SYSTEM_SID_STRING[] = L"S-1-5-18";
static constexpr DWORD INVALID_SESSION = 0xFFFFFFFF;

static std::wstring GetSidStringForUser(const std::wstring& username)
{
    // Prepare buffers for SID and domain lookup
    BYTE sidBuffer[SECURITY_MAX_SID_SIZE];
    WCHAR domainBuffer[DNLEN + 1];
    DWORD sidSize = sizeof(sidBuffer);
    DWORD domainSize = DNLEN + 1;
    SID_NAME_USE sidUse;
    SmartPointer<LPWSTR> sidString(LocalFree, nullptr);

    // Resolve username to SID and convert to string
    if (!LookupAccountNameW(nullptr, username.c_str(), sidBuffer, &sidSize, domainBuffer, &domainSize, &sidUse) ||
        !ConvertSidToStringSidW(sidBuffer, &sidString))
    {
        return {};
    }

    return std::wstring(sidString);
}

static std::wstring GetSessionUserSidString(const DWORD sessionId)
{
    // Query session for username and domain
    SmartPointer<LPWSTR> pUserName(WTSFreeMemory, nullptr);
    SmartPointer<LPWSTR> pDomainName(WTSFreeMemory, nullptr);
    DWORD bytesReturned = 0;

    if (!WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSUserName, &pUserName, &bytesReturned) || bytesReturned <= sizeof(WCHAR) ||
        !WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, sessionId, WTSDomainName, &pDomainName, &bytesReturned) || bytesReturned <= sizeof(WCHAR))
    {
        return {};
    }

    // Convert domain\username to SID string
    return GetSidStringForUser(std::wstring(pDomainName) + L"\\" + std::wstring(pUserName));
}

static bool IsValidUserSession(const std::wstring& sidString)
{
    return !sidString.empty() && sidString != SYSTEM_SID_STRING;
}

static DWORD FindTargetSession(const std::wstring& username)
{
    // Enumerate all sessions on the system
    SmartPointer<PWTS_SESSION_INFOW> pSessionInfo(WTSFreeMemory, nullptr);
    DWORD sessionCount = 0;

    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &pSessionInfo, &sessionCount))
    {
        return INVALID_SESSION;
    }

    // Resolve target username to SID if specified
    const std::wstring targetSidString = username.empty() ? std::wstring{} : GetSidStringForUser(username);
    if (!username.empty() && targetSidString.empty())
    {
        return INVALID_SESSION;
    }

    // Get console session ID for priority matching
    const DWORD consoleSessionId = username.empty() ? WTSGetActiveConsoleSessionId() : INVALID_SESSION;
    DWORD firstActiveSession = INVALID_SESSION;
    DWORD firstDisconnectedSession = INVALID_SESSION;

    // Iterate sessions to find best match
    for (DWORD i = 0; i < sessionCount; ++i)
    {
        const DWORD sessionId = pSessionInfo[i].SessionId;
        const WTS_CONNECTSTATE_CLASS state = pSessionInfo[i].State;
        const std::wstring sessionSidString = GetSessionUserSidString(sessionId);

        if (username.empty())
        {
            // Skip invalid or SYSTEM sessions
            if (!IsValidUserSession(sessionSidString))
            {
                continue;
            }
            // Prefer console session if valid
            if (sessionId == consoleSessionId)
            {
                return consoleSessionId;
            }
            // Track first active session
            if (state == WTSActive && firstActiveSession == INVALID_SESSION)
            {
                firstActiveSession = sessionId;
            }
            // Track first disconnected session as fallback
            if (state == WTSDisconnected && firstDisconnectedSession == INVALID_SESSION)
            {
                firstDisconnectedSession = sessionId;
            }
        }
        else
        {
            // Match by SID for specified username (active or disconnected)
            if ((state == WTSActive || state == WTSDisconnected) && sessionSidString == targetSidString)
            {
                return sessionId;
            }
        }
    }

    // Return first active, then first disconnected, then invalid
    return (firstActiveSession != INVALID_SESSION) ? firstActiveSession : firstDisconnectedSession;
}

int LaunchAsUser(const std::wstring& commandLine, const std::wstring& username)
{
    // Find appropriate session for target user
    const DWORD targetSessionId = FindTargetSession(username);
    if (targetSessionId == INVALID_SESSION)
    {
        return __LINE__;
    }

    // Get user token and create environment block
    SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
    SmartPointer<HANDLE> hPrimaryToken(CloseHandle, nullptr);
    SmartPointer<LPVOID> pEnvironment(DestroyEnvironmentBlock, nullptr);

    if (!WTSQueryUserToken(targetSessionId, &hToken) ||
        !DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityIdentification, TokenPrimary, &hPrimaryToken) ||
        !CreateEnvironmentBlock(&pEnvironment, hPrimaryToken, FALSE))
    {
        return __LINE__;
    }

    // Configure process to run on interactive desktop
    STARTUPINFOW si = { sizeof(si) };
    si.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;

    // Launch process as the target user
    PROCESS_INFORMATION pi = {};
    std::wstring cmdLineCopy = commandLine;

    if (!CreateProcessAsUserW(hPrimaryToken, nullptr, cmdLineCopy.data(), nullptr, nullptr, FALSE, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE, pEnvironment, nullptr, &si, &pi))
    {
        return __LINE__;
    }

    // Wait for process to complete and clean up handles
    SmartPointer<HANDLE> hProcess(CloseHandle, pi.hProcess);
    SmartPointer<HANDLE> hThread(CloseHandle, pi.hThread);

    if (WaitForSingleObject(hProcess, INFINITE) == WAIT_FAILED)
    {
        return __LINE__;
    }

    DWORD iExitCode = 0;
    GetExitCodeProcess(hProcess, &iExitCode);
    return iExitCode;
}