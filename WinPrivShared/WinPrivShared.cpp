//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <Windows.h>
#include <winternl.h>
#include <wincred.h>
#include <cinttypes>
#include <TlHelp32.h>

#define _NTDEF_
#include <NTSecAPI.h>

#include <string>
#include <vector>
#include <cctype>
#include <regex>

#include "WinPrivShared.h"

std::wstring ArgvToCommandLine(unsigned int iStart, unsigned int iEnd, const std::vector<LPWSTR>& vArgs)
{
	std::wstring sResult;

	for (unsigned int iCurrent = iStart; iCurrent <= iEnd && iEnd < vArgs.size(); iCurrent++)
	{
		std::wstring sArg(vArgs.at(iCurrent));

		if (std::ranges::count_if(sArg,
			[](const wchar_t c) { return isblank(c); }) > 0)
		{
			// enclose the parameter in double quotes
			sArg = L'"' + sArg + L'"';
		}

		sResult += sArg + L' ';
	}

	// trim off last character if space
	if (!sResult.empty() && sResult.back() == L' ') sResult.pop_back();
	
	// append a space for the next param
	return sResult;
}

std::vector<std::wstring> EnablePrivs(std::vector<std::wstring> vRequestedPrivs)
{
	// open the current token
	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken) == 0)
	{
		// error
		PrintMessage(L"ERROR: Could not open process token for enabling privileges.\n");
		return vRequestedPrivs;
	}

	// get the current user sid out of the token
	const BYTE aBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE] = {};
	const PTOKEN_USER tTokenUser = (PTOKEN_USER)(aBuffer);
	DWORD iBytesFilled = 0;
	if (GetTokenInformation(hToken, TokenUser, tTokenUser, sizeof(aBuffer), &iBytesFilled) == 0)
	{
		// error
		CloseHandle(hToken);
		PrintMessage(L"ERROR: Could retrieve process token information.\n");
		return vRequestedPrivs;
	}

	// vector to store privileges we had issues with
	std::vector<std::wstring> vUnavailablePrivs;

	// tokenize the string
	for (std::wstring sPrivilege : vRequestedPrivs)
	{
		// populate the privilege adjustment structure
		TOKEN_PRIVILEGES tPrivEntry = {};
		tPrivEntry.PrivilegeCount = 1;
		tPrivEntry.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// rights do not have to be enabled since they are automatically established
		std::wstring sRight(L"Right");
		if (std::equal(sRight.rbegin(), sRight.rend(), sPrivilege.rbegin())) continue;

		// translate the privilege name into the binary representation
		if (LookupPrivilegeValue(nullptr, sPrivilege.c_str(), &tPrivEntry.Privileges[0].Luid) == 0)
		{
			PrintMessage(L"ERROR: Could not lookup privilege: %s\n", sPrivilege.c_str());
			continue;
		}

		// adjust the process to change the privilege
		if (AdjustTokenPrivileges(hToken, FALSE, &tPrivEntry, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) == 0 || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			// add to list of privileges we had issues with
			vUnavailablePrivs.emplace_back(sPrivilege.c_str());
		}
	}

	CloseHandle(hToken);
	return vUnavailablePrivs;
}

BOOL AlterCurrentUserPrivs(const std::vector<std::wstring>& vPrivsToGrant, BOOL bAddRights)
{
	// open the current token
	HANDLE hToken = nullptr;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == 0)
	{
		// error
		PrintMessage(L"ERROR: Could not open process token for enabling privileges.\n");
		return FALSE;
	}

	// get the current user sid out of the token
	const BYTE aBuffer[sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE] = {};
	const PTOKEN_USER tTokenUser = (PTOKEN_USER)(aBuffer);
	DWORD iBytesFilled = 0;
	const BOOL bRet = GetTokenInformation(hToken, TokenUser, tTokenUser, sizeof(aBuffer), &iBytesFilled);
	CloseHandle(hToken);
	if (bRet == 0)
	{
		// error
		PrintMessage(L"ERROR: Could retrieve process token information.\n");
		return FALSE;
	}

	// object attributes are reserved, so initialize to zeros.
	LSA_OBJECT_ATTRIBUTES ObjectAttributes;
	ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

	// get a handle to the policy object.
	LSA_HANDLE hPolicyHandle;
	NTSTATUS iResult = 0;
	if ((iResult = LsaOpenPolicy(nullptr, &ObjectAttributes,
		POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &hPolicyHandle)) != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Local security policy could not be opened with error '%lu'\n",
			LsaNtStatusToWinError(iResult));
		return FALSE;
	}

	// grant policy to all users
	BOOL bSuccessful = TRUE;
	for (const std::wstring& sPrivilege : vPrivsToGrant)
	{
		// convert the privilege name to a unicode string format
		LSA_UNICODE_STRING sUnicodePrivilege = {};
		sUnicodePrivilege.Buffer = (PWSTR)sPrivilege.c_str();
		sUnicodePrivilege.Length = static_cast<USHORT>(wcslen(sPrivilege.c_str()) * sizeof(WCHAR));
		sUnicodePrivilege.MaximumLength = static_cast<USHORT>((wcslen(sPrivilege.c_str()) + 1) * sizeof(WCHAR));

		// attempt to add the account to policy
		if (bAddRights)
		{
			if ((iResult = LsaAddAccountRights(hPolicyHandle,
				tTokenUser->User.Sid, &sUnicodePrivilege, 1)) != STATUS_SUCCESS)
			{
				bSuccessful = FALSE;
				PrintMessage(L"ERROR: Privilege '%s' was not able to be added with error '%u'\n",
					sPrivilege.c_str(), LsaNtStatusToWinError(iResult));
			}
		}
		else
		{
			if ((iResult = LsaRemoveAccountRights(hPolicyHandle,
				tTokenUser->User.Sid, FALSE, &sUnicodePrivilege, 1)) != STATUS_SUCCESS)
			{
				bSuccessful = FALSE;
				PrintMessage(L"ERROR: Privilege '%s' was not able to be remove with error '%u'\n",
					sPrivilege.c_str(), LsaNtStatusToWinError(iResult));
			}
		}
	}

	// cleanup
	LsaClose(hPolicyHandle);
	return bSuccessful;
}

void KillProcess(const std::wstring & sProcessName)
{
	PROCESSENTRY32 tEntry = {};
	tEntry.dwSize = sizeof(PROCESSENTRY32);

	// fetch current session id
	DWORD iCurrentSessionId = 0;
	if (ProcessIdToSessionId(GetCurrentProcessId(), &iCurrentSessionId) == 0) return;

	// enumerate all processes, looking for match by name
	HANDLE const hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	for (BOOL bValid = Process32First(hSnapshot, &tEntry); bValid; bValid = Process32Next(hSnapshot, &tEntry))
	{
		if (_wcsicmp(tEntry.szExeFile, sProcessName.c_str()) != 0) continue;

		// skip process if not the current session id or session id lookup fails
		DWORD iSessionId = 0;
		if (ProcessIdToSessionId(tEntry.th32ProcessID, &iSessionId) == 0 
			|| iSessionId != iCurrentSessionId) continue;

		// kill process
		HANDLE const hProcess = OpenProcess(PROCESS_TERMINATE, 0, tEntry.th32ProcessID);
		TerminateProcess(hProcess, 1);
		CloseHandle(hProcess);
	}

	// cleanup
	CloseHandle(hSnapshot);
}
