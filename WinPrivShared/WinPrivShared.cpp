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
#include <ntlsa.h>

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
	if (GetTokenInformation(hToken, TokenUser, tTokenUser, 
		static_cast<DWORD>(aBuffer.size()), &iBytesFilled) == 0)
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
	const BOOL bRet = GetTokenInformation(hToken, TokenUser, tTokenUser, static_cast<DWORD>(aBuffer.size()), &iBytesFilled);
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

// deny-logon rights that can explicitly block an account's access
static const std::vector<std::wstring> g_vDenyRights = {
	L"SeDenyNetworkLogonRight",             // Deny access to this computer from the network
	L"SeDenyInteractiveLogonRight",          // Deny log on locally
	L"SeDenyRemoteInteractiveLogonRight",    // Deny log on through Remote Desktop Services
	L"SeDenyBatchLogonRight",               // Deny log on as a batch job
	L"SeDenyServiceLogonRight",             // Deny log on as a service
};

// allow-logon rights that permit an account to log on in various ways
static const std::vector<std::wstring> g_vLogonRights = {
	L"SeNetworkLogonRight",                 // Access this computer from the network
	L"SeInteractiveLogonRight",             // Allow log on locally
	L"SeRemoteInteractiveLogonRight",       // Allow log on through Remote Desktop Services
	L"SeBatchLogonRight",                   // Log on as a batch job
	L"SeServiceLogonRight",                 // Log on as a service
};

BOOL ModifyAccountRights(const std::wstring& sAccountName,
	const std::vector<std::wstring>& vRights, const BOOL bGrant)
{
	// resolve the SID for the named account on the local machine
	BYTE aSidBuffer[SECURITY_MAX_SID_SIZE] = {};
	DWORD iSidSize = sizeof(aSidBuffer);
	WCHAR sReferencedDomain[MAX_PATH] = {};
	DWORD iDomainSize = MAX_PATH;
	SID_NAME_USE tSidType;
	if (LookupAccountName(nullptr, sAccountName.c_str(), aSidBuffer, &iSidSize,
		sReferencedDomain, &iDomainSize, &tSidType) == 0)
	{
		PrintMessage(L"ERROR: Could not resolve account '%s': %lu\n",
			sAccountName.c_str(), GetLastError());
		return FALSE;
	}

	// open LSA policy on the local machine
	LSA_OBJECT_ATTRIBUTES tAttrs{};
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, nullptr);
	NTSTATUS iResult = LsaOpenPolicy(nullptr, &tAttrs,
		POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &hPolicy);
	if (iResult != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Could not open security policy: %lu\n",
			LsaNtStatusToWinError(iResult));
		return FALSE;
	}

	BOOL bSuccessful = TRUE;
	std::ranges::for_each(vRights, [&](const std::wstring& sRight) {
		LSA_UNICODE_STRING tRight{
			.Length = static_cast<USHORT>(sRight.length() * sizeof(WCHAR)),
			.MaximumLength = static_cast<USHORT>((sRight.length() + 1) * sizeof(WCHAR)),
			.Buffer = const_cast<PWSTR>(sRight.c_str())
		};

		if (bGrant)
		{
			iResult = LsaAddAccountRights(hPolicy, aSidBuffer, &tRight, 1);
			if (iResult != STATUS_SUCCESS)
			{
				bSuccessful = FALSE;
				PrintMessage(L"ERROR: Failed to grant right '%s' to '%s': %lu\n",
					sRight.c_str(), sAccountName.c_str(), LsaNtStatusToWinError(iResult));
			}
			else
			{
				PrintMessage(L"INFO: Granted right '%s' to '%s'\n",
					sRight.c_str(), sAccountName.c_str());
			}
		}
		else
		{
			iResult = LsaRemoveAccountRights(hPolicy, aSidBuffer, FALSE, &tRight, 1);
			if (iResult == STATUS_OBJECT_NAME_NOT_FOUND)
			{
				// right was not assigned — desired end state already reached, not an error
			}
			else if (iResult != STATUS_SUCCESS)
			{
				bSuccessful = FALSE;
				PrintMessage(L"ERROR: Failed to revoke right '%s' from '%s': %lu\n",
					sRight.c_str(), sAccountName.c_str(), LsaNtStatusToWinError(iResult));
			}
			else
			{
				PrintMessage(L"INFO: Revoked right '%s' from '%s'\n",
					sRight.c_str(), sAccountName.c_str());
			}
		}
	});

	return bSuccessful;
}

static std::vector<std::wstring> QueryAccountRights(const std::wstring& sAccountName)
{
	std::vector<std::wstring> vRights;

	// resolve the SID for the named account on the local machine
	BYTE aSidBuffer[SECURITY_MAX_SID_SIZE] = {};
	DWORD iSidSize = sizeof(aSidBuffer);
	WCHAR sReferencedDomain[MAX_PATH] = {};
	DWORD iDomainSize = MAX_PATH;
	SID_NAME_USE tSidType;
	if (LookupAccountName(nullptr, sAccountName.c_str(), aSidBuffer, &iSidSize,
		sReferencedDomain, &iDomainSize, &tSidType) == 0)
	{
		PrintMessage(L"ERROR: Could not resolve account '%s': %lu\n",
			sAccountName.c_str(), GetLastError());
		return vRights;
	}

	// open LSA policy on the local machine
	LSA_OBJECT_ATTRIBUTES tAttrs{};
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, nullptr);
	NTSTATUS iResult = LsaOpenPolicy(nullptr, &tAttrs, POLICY_LOOKUP_NAMES, &hPolicy);
	if (iResult != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Could not open security policy: %lu\n",
			LsaNtStatusToWinError(iResult));
		return vRights;
	}

	// enumerate all rights currently assigned to this account
	SmartPointer<PLSA_UNICODE_STRING> pRights(LsaFreeMemory, nullptr);
	ULONG iCount = 0;
	iResult = LsaEnumerateAccountRights(hPolicy, aSidBuffer, &pRights, &iCount);
	if (iResult == STATUS_OBJECT_NAME_NOT_FOUND)
	{
		// account exists but has no rights assigned — not an error
		return vRights;
	}
	if (iResult != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Could not enumerate rights for '%s': %lu\n",
			sAccountName.c_str(), LsaNtStatusToWinError(iResult));
		return vRights;
	}

	for (ULONG i = 0; i < iCount; i++)
	{
		vRights.emplace_back(pRights[i].Buffer, pRights[i].Length / sizeof(WCHAR));
	}

	return vRights;
}

BOOL ClearDenyRights(const std::wstring& sAccountName)
{
	// if no account name specified, clear deny rights for every account on the machine
	if (sAccountName.empty())
	{
		// open LSA policy with the access needed to enumerate accounts,
		// read their rights, and remove rights
		LSA_OBJECT_ATTRIBUTES tAttrs{};
		SmartPointer<LSA_HANDLE> hPolicy(LsaClose, nullptr);
		NTSTATUS iResult = LsaOpenPolicy(nullptr, &tAttrs,
			POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &hPolicy);
		if (iResult != STATUS_SUCCESS)
		{
			PrintMessage(L"ERROR: Could not open security policy: %lu\n",
				LsaNtStatusToWinError(iResult));
			return FALSE;
		}

		// enumerate all accounts that have any rights assigned on this machine
		LSA_ENUMERATION_HANDLE hEnum = 0;
		ULONG iAccountCount = 0;
		BOOL bSuccessful = TRUE;
		SmartPointer<PLSA_ENUMERATION_INFORMATION> pAccounts(LsaFreeMemory, nullptr);

		while (LsaEnumerateAccounts(hPolicy, &hEnum,
			reinterpret_cast<PVOID*>(&pAccounts), ULONG_MAX, &iAccountCount) == STATUS_SUCCESS)
		{
			for (ULONG i = 0; i < iAccountCount; i++)
			{
				PSID pSid = pAccounts[i].Sid;

				// resolve the SID to an account name for display purposes
				WCHAR sName[MAX_PATH] = {};
				DWORD iNameSize = MAX_PATH;
				WCHAR sDomainName[MAX_PATH] = {};
				DWORD iDomainNameSize = MAX_PATH;
				SID_NAME_USE tSidType;
				LookupAccountSid(nullptr, pSid,
					sName, &iNameSize,
					sDomainName, &iDomainNameSize, &tSidType);

				const std::wstring sDisplayName = (iDomainNameSize > 0 && sDomainName[0] != L'\0')
					? std::wstring(sDomainName) + L"\\" + sName
					: sName;

				// enumerate all rights currently assigned to this account
				SmartPointer<PLSA_UNICODE_STRING> pRights(LsaFreeMemory, nullptr);
				ULONG iRightCount = 0;
				iResult = LsaEnumerateAccountRights(hPolicy, pSid, &pRights, &iRightCount);
				if (iResult == STATUS_OBJECT_NAME_NOT_FOUND || iResult != STATUS_SUCCESS) continue;

				// collect whichever deny rights are present on this account
				std::vector<std::wstring> vToRemove;
				for (ULONG j = 0; j < iRightCount; j++)
				{
					std::wstring sRight(pRights[j].Buffer, pRights[j].Length / sizeof(WCHAR));
					if (std::ranges::find(g_vDenyRights, sRight) != g_vDenyRights.end())
					{
						vToRemove.push_back(sRight);
					}
				}

				// remove each deny right directly using the resolved SID
				for (const auto& sRight : vToRemove)
				{
					LSA_UNICODE_STRING tRight{
						.Length = static_cast<USHORT>(sRight.length() * sizeof(WCHAR)),
						.MaximumLength = static_cast<USHORT>((sRight.length() + 1) * sizeof(WCHAR)),
						.Buffer = const_cast<PWSTR>(sRight.c_str())
					};

					iResult = LsaRemoveAccountRights(hPolicy, pSid, FALSE, &tRight, 1);
					if (iResult != STATUS_SUCCESS)
					{
						bSuccessful = FALSE;
						PrintMessage(L"ERROR: Failed to revoke '%s' from '%s': %lu\n",
							sRight.c_str(), sDisplayName.c_str(), LsaNtStatusToWinError(iResult));
					}
					else
					{
						PrintMessage(L"INFO: Revoked '%s' from '%s'\n",
							sRight.c_str(), sDisplayName.c_str());
					}
				}
			}
		}

		return bSuccessful;
	}

	// enumerate rights actually assigned so we only act on ones that are present
	const std::vector<std::wstring> vAssigned = QueryAccountRights(sAccountName);

	// intersect the deny list with what is actually assigned so output is meaningful
	std::vector<std::wstring> vToRemove;
	for (const auto& sRight : g_vDenyRights)
	{
		if (std::ranges::find(vAssigned, sRight) != vAssigned.end())
		{
			vToRemove.push_back(sRight);
		}
	}

	if (vToRemove.empty())
	{
		PrintMessage(L"INFO: No deny rights are assigned to '%s'\n", sAccountName.c_str());
		return TRUE;
	}

	return ModifyAccountRights(sAccountName, vToRemove, FALSE);
}

BOOL GrantAllRights(const std::wstring& sAccountName)
{
	// open LSA policy to enumerate all privileges defined on the system
	LSA_OBJECT_ATTRIBUTES tAttrs{};
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, nullptr);
	NTSTATUS iResult = LsaOpenPolicy(nullptr, &tAttrs, POLICY_VIEW_LOCAL_INFORMATION, &hPolicy);
	if (iResult != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Could not open security policy: %lu\n",
			LsaNtStatusToWinError(iResult));
		return FALSE;
	}

	// enumerate all privileges on the system
	std::vector<std::wstring> vRightsToGrant;
	LSA_ENUMERATION_HANDLE hEnum = 0;
	ULONG iCount = 0;
	SmartPointer<PPOLICY_PRIVILEGE_DEFINITION> pPrivs(LsaFreeMemory, nullptr);
	while (LsaEnumeratePrivileges(hPolicy, &hEnum,
		reinterpret_cast<PVOID*>(&pPrivs), ULONG_MAX, &iCount) == STATUS_SUCCESS)
	{
		for (ULONG i = 0; i < iCount; i++)
		{
			vRightsToGrant.emplace_back(pPrivs[i].Name.Buffer,
				pPrivs[i].Name.Length / sizeof(WCHAR));
		}
	}

	// append all allow-logon rights (these are not returned by LsaEnumeratePrivileges)
	for (const auto& sRight : g_vLogonRights)
	{
		vRightsToGrant.push_back(sRight);
	}

	return ModifyAccountRights(sAccountName, vRightsToGrant, TRUE);
}

void KillProcess(const std::wstring& sProcessName, DWORD iSessionId)
{
	PROCESSENTRY32 tEntry = {};
	tEntry.dwSize = sizeof(PROCESSENTRY32);

	// use the caller's own session id if no explicit session was specified
	DWORD iCurrentSessionId = iSessionId;
	if (iCurrentSessionId == MAXDWORD)
	{
		if (ProcessIdToSessionId(GetCurrentProcessId(), &iCurrentSessionId) == 0) return;
	}

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
