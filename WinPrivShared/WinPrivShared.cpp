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

#include <array>
#include <string>
#include <vector>
#include <cctype>
#include <regex>

#include "WinPrivShared.h"

std::wstring ArgvToCommandLine(const unsigned int iStart, const unsigned int iEnd, const std::vector<LPWSTR>& vArgs)
{
	std::wstring sResult;

	for (unsigned int iCurrent = iStart; iCurrent <= iEnd && iEnd < vArgs.size(); iCurrent++)
	{
		std::wstring sArg(vArgs.at(iCurrent));

		if (std::ranges::count_if(sArg,
			[](const wchar_t c) { return iswblank(c); }) > 0)
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
	SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken) == 0)
	{
		// error
		PrintMessage(L"ERROR: Could not open process token for enabling privileges.\n");
		return vRequestedPrivs;
	}

	// get the current user sid out of the token
	std::array<BYTE, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> aBuffer = {};
	PTOKEN_USER tTokenUser = (PTOKEN_USER)(aBuffer.data());
	DWORD iBytesFilled = 0;
	if (GetTokenInformation(hToken, TokenUser, tTokenUser, aBuffer.size(), &iBytesFilled) == 0)
	{
		// error
		PrintMessage(L"ERROR: Could not retrieve process token information.\n");
		return vRequestedPrivs;
	}

	// vector to store privileges we had issues with
	std::vector<std::wstring> vUnavailablePrivs;

	// use ranges algorithm to process privileges
	std::ranges::for_each(vRequestedPrivs, [&](const std::wstring& sPrivilege) {
		// populate the privilege adjustment structure with designated initializers
		TOKEN_PRIVILEGES tPrivEntry{
			.PrivilegeCount = 1,
			.Privileges = {{ .Luid = {}, .Attributes = SE_PRIVILEGE_ENABLED }}
		};

		// rights do not have to be enabled since they are automatically established
		constexpr std::wstring_view sRight(L"Right");
		if (std::equal(sRight.rbegin(), sRight.rend(), sPrivilege.rbegin())) return;

		// translate the privilege name into the binary representation
		if (LookupPrivilegeValue(nullptr, sPrivilege.c_str(), &tPrivEntry.Privileges[0].Luid) == 0)
		{
			PrintMessage(L"ERROR: Could not lookup privilege: %s\n", sPrivilege.c_str());
			return;
		}

		// adjust the process to change the privilege
		if (AdjustTokenPrivileges(hToken, FALSE, &tPrivEntry, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) == 0 || GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			// add to list of privileges we had issues with
			vUnavailablePrivs.emplace_back(sPrivilege.c_str());
		}
	});

	return vUnavailablePrivs;
}

BOOL AlterCurrentUserPrivs(const std::vector<std::wstring>& vPrivsToGrant, const BOOL bAddRights)
{
	// open the current token 
	SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) == 0)
	{
		// error
		PrintMessage(L"ERROR: Could not open process token for enabling privileges.\n");
		return FALSE;
	}

	// get the current user sid out of the token
	std::array<BYTE, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> aBuffer = {};
	PTOKEN_USER tTokenUser = (PTOKEN_USER)(aBuffer.data());
	DWORD iBytesFilled = 0;
	const BOOL bRet = GetTokenInformation(hToken, TokenUser, tTokenUser, aBuffer.size(), &iBytesFilled);
	if (bRet == 0)
	{
		// error
		PrintMessage(L"ERROR: Could not retrieve process token information.\n");
		return FALSE;
	}

	// object attributes are reserved, so initialize to zeros with designated initializer
	LSA_OBJECT_ATTRIBUTES ObjectAttributes{};

	// get a handle to the policy object 
	SmartPointer<LSA_HANDLE> hPolicyHandle(LsaClose, nullptr);
	NTSTATUS iResult = 0;
	if ((iResult = LsaOpenPolicy(nullptr, &ObjectAttributes,
		POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &hPolicyHandle)) != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Local security policy could not be opened with error '%lu'\n",
			LsaNtStatusToWinError(iResult));
		return FALSE;
	}

	// grant policy to all users using ranges algorithm
	BOOL bSuccessful = TRUE;
	std::ranges::for_each(vPrivsToGrant, [&](const std::wstring& sPrivilege) {
		// convert the privilege name to a unicode string format
		LSA_UNICODE_STRING sUnicodePrivilege{
			.Length = static_cast<USHORT>(sPrivilege.length() * sizeof(WCHAR)),
			.MaximumLength = static_cast<USHORT>((sPrivilege.length() + 1) * sizeof(WCHAR)),
			.Buffer = const_cast<PWSTR>(sPrivilege.c_str())
		};

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
	});

	return bSuccessful;
}

void KillProcess(const std::wstring& sProcessName)
{
	PROCESSENTRY32 tEntry = {};
	tEntry.dwSize = sizeof(PROCESSENTRY32);

	// fetch current session id
	DWORD iCurrentSessionId = 0;
	if (ProcessIdToSessionId(GetCurrentProcessId(), &iCurrentSessionId) == 0) return;

	// enumerate all processes, looking for match by name 
	SmartPointer<HANDLE> hSnapshot(CloseHandle, CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));
	for (BOOL bValid = Process32First(hSnapshot, &tEntry); bValid; bValid = Process32Next(hSnapshot, &tEntry))
	{
		if (_wcsicmp(tEntry.szExeFile, sProcessName.c_str()) != 0) continue;

		// skip process if not the current session id or session id lookup fails
		DWORD iSessionId = 0;
		if (ProcessIdToSessionId(tEntry.th32ProcessID, &iSessionId) == 0
			|| iSessionId != iCurrentSessionId) continue;

		// kill process
		SmartPointer<HANDLE> hProcess(CloseHandle, OpenProcess(PROCESS_TERMINATE, 0, tEntry.th32ProcessID));
		TerminateProcess(hProcess, 1);
	}
}
