//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <ntlsa.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cwctype>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "WinPrivShared.h"

#pragma comment(lib, "ntdll.lib")

bool ParseMockTimeOffset(std::wstring_view sDelta, LONGLONG iCurrentTime, LONGLONG& iOffset)
{
	// Parse signed components exactly to the clock's 100-nanosecond resolution.
	constexpr LONGLONG iMaxTime = (std::numeric_limits<LONGLONG>::max)();
	using TimeUnit = std::pair<std::wstring_view, LONGLONG>;
	constexpr TimeUnit vUnits[] = {
		{ L"w", 6048000000000 }, { L"wk", 6048000000000 }, { L"d", 864000000000 },
		{ L"h", 36000000000 }, { L"hr", 36000000000 }, { L"m", 600000000 }, { L"min", 600000000 },
		{ L"s", 10000000 }, { L"sec", 10000000 }, { L"ms", 10000 }, { L"us", 10 },
	};
	LONGLONG iTime = iCurrentTime;
	int iSign = 1;
	size_t iPosition = 0;
	bool bParsed = false;
	if (iCurrentTime < 0) return false;
	while (iPosition < sDelta.size())
	{
		while (iPosition < sDelta.size() && iswspace(sDelta[iPosition])) ++iPosition;
		if (iPosition == sDelta.size()) break;
		if (sDelta[iPosition] == L'+' || sDelta[iPosition] == L'-')
			iSign = sDelta[iPosition++] == L'-' ? -1 : 1;
		if (iPosition == sDelta.size() || sDelta[iPosition] < L'0' || sDelta[iPosition] > L'9') return false;
		LONGLONG iWhole = 0;
		while (iPosition < sDelta.size() && sDelta[iPosition] >= L'0' && sDelta[iPosition] <= L'9')
		{
			const int iDigit = sDelta[iPosition++] - L'0';
			if (iWhole > (iMaxTime - iDigit) / 10) return false;
			iWhole = iWhole * 10 + iDigit;
		}
		LONGLONG iFraction = 0;
		LONGLONG iScale = 1;
		if (iPosition < sDelta.size() && sDelta[iPosition] == L'.')
		{
			++iPosition;
			const size_t iStart = iPosition;
			while (iPosition < sDelta.size() && sDelta[iPosition] >= L'0' && sDelta[iPosition] <= L'9')
			{
				if (iScale == 10000000) return false;
				iFraction = iFraction * 10 + sDelta[iPosition++] - L'0';
				iScale *= 10;
			}
			if (iStart == iPosition) return false;
		}
		while (iPosition < sDelta.size() && iswspace(sDelta[iPosition])) ++iPosition;
		std::wstring sUnit;
		while (iPosition < sDelta.size() && iswalpha(sDelta[iPosition]))
			sUnit += static_cast<wchar_t>(towlower(sDelta[iPosition++]));
		if (sUnit.size() > 2 && sUnit.ends_with(L's')) sUnit.pop_back();

		// Calendar components keep the time of day and clamp month-end and leap-day dates.
		if (sUnit == L"y" || sUnit == L"yr" || sUnit == L"mo" || sUnit == L"mon")
		{
			const LONGLONG iMonthsPerUnit = sUnit == L"y" || sUnit == L"yr" ? 12 : 1;
			if (iFraction != 0 || iWhole > 30827 * 12) return false;
			FILETIME tTime{ static_cast<DWORD>(iTime), static_cast<DWORD>(iTime >> 32) };
			SYSTEMTIME tDate{};
			if (!FileTimeToSystemTime(&tTime, &tDate)) return false;
			const LONGLONG iMonth = tDate.wYear * 12 + tDate.wMonth - 1 + iSign * iWhole * iMonthsPerUnit;
			if (iMonth < 1601 * 12 || iMonth >= 30828 * 12) return false;
			tDate.wYear = static_cast<WORD>(iMonth / 12);
			tDate.wMonth = static_cast<WORD>(iMonth % 12 + 1);
			const std::chrono::year_month_day_last tLastDay{
				std::chrono::year{ tDate.wYear }, std::chrono::month_day_last{ std::chrono::month{ tDate.wMonth } } };
			tDate.wDay = (std::min)(tDate.wDay, static_cast<WORD>(static_cast<unsigned>(tLastDay.day())));
			if (!SystemTimeToFileTime(&tDate, &tTime)) return false;
			iTime = (static_cast<LONGLONG>(tTime.dwHighDateTime) << 32 | tTime.dwLowDateTime) + iTime % 10000;
			bParsed = true;
			continue;
		}

		// Fixed-duration components reject overflow and fractions smaller than one clock tick.
		const auto pUnit = std::ranges::find(vUnits, sUnit, &TimeUnit::first);
		if (pUnit == std::end(vUnits)) return false;
		const LONGLONG iUnit = pUnit->second;
		if (iWhole > iMaxTime / iUnit || iFraction * (iUnit % iScale) % iScale != 0) return false;
		const LONGLONG iFractionTicks = iFraction * (iUnit / iScale) + iFraction * (iUnit % iScale) / iScale;
		const LONGLONG iWholeTicks = iWhole * iUnit;
		if (iFractionTicks > iMaxTime - iWholeTicks) return false;
		const LONGLONG iTicks = iWholeTicks + iFractionTicks;
		if ((iSign > 0 && iTicks > iMaxTime - iTime) || (iSign < 0 && iTicks > iTime)) return false;
		iTime += iSign * iTicks;
		bParsed = true;
	}

	FILETIME tTime{ static_cast<DWORD>(iTime), static_cast<DWORD>(iTime >> 32) };
	SYSTEMTIME tDate{};
	if (!bParsed || !FileTimeToSystemTime(&tTime, &tDate) || tDate.wYear > 30827) return false;
	iOffset = iTime - iCurrentTime;
	return true;
}

std::wstring ResolveFileRulePath(std::wstring path)
{
	// Normalize DOS paths once, before rules are inherited by processes with different current directories.
	std::ranges::replace(path, L'/', L'\\');
	constexpr std::wstring_view extendedPrefix = L"\\\\?\\";
	if (path.empty() || path.find_first_of(L"*?\"",
		path.starts_with(extendedPrefix) ? extendedPrefix.size() : 0) != std::wstring::npos) return {};

	// Let the native runtime allocate the absolute NT path.
	static const auto convert = LoadNtFunction<NTSTATUS(NTAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, PVOID)>(
		"RtlDosLongPathNameToNtPathName_U_WithStatus");
	UNICODE_STRING name{};
	SmartPointer<PUNICODE_STRING> cleanup(RtlFreeUnicodeString, &name);
	if (convert(path.c_str(), &name, nullptr, nullptr) < 0) return {};
	return { name.Buffer, name.Length / sizeof(WCHAR) };
}

std::wstring ArgvToCommandLine(const unsigned int iStart, const unsigned int iEnd, const std::vector<LPWSTR>& vArgs)
{
	std::wstring sResult;

	if (iStart > iEnd || iEnd >= vArgs.size()) return sResult;

	for (unsigned int iCurrent = iStart; iCurrent <= iEnd; iCurrent++)
	{
		const std::wstring sArg(vArgs.at(iCurrent));
		if (!sResult.empty()) sResult += L' ';

		// CommandLineToArgvW and the Microsoft C runtime give backslashes
		// special meaning only when they precede a quote. Quote empty arguments
		// and arguments containing delimiters, doubling the appropriate runs of
		// backslashes so parsing the resulting command line reproduces sArg.
		const bool bNeedsQuotes = sArg.empty() || sArg.find_first_of(L" \t\"") != std::wstring::npos;
		if (!bNeedsQuotes)
		{
			sResult += sArg;
			continue;
		}

		sResult += L'"';
		size_t iBackslashes = 0;
		for (const wchar_t c : sArg)
		{
			if (c == L'\\')
			{
				iBackslashes++;
				continue;
			}

			if (c == L'"')
			{
				// Escape both the accumulated backslashes and the quote itself.
				sResult.append((iBackslashes * 2) + 1, L'\\');
				sResult += c;
			}
			else
			{
				sResult.append(iBackslashes, L'\\');
				sResult += c;
			}
			iBackslashes = 0;
		}

		// Backslashes immediately before the closing quote must be doubled.
		sResult.append(iBackslashes * 2, L'\\');
		sResult += L'"';
	}

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
		if (sPrivilege.ends_with(sRight)) return;

		// translate the privilege name into the binary representation
		if (LookupPrivilegeValue(nullptr, sPrivilege.c_str(), &tPrivEntry.Privileges[0].Luid) == 0)
		{
			PrintMessage(L"ERROR: Could not lookup privilege: %s\n", sPrivilege.c_str());
			vUnavailablePrivs.emplace_back(sPrivilege);
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

BOOL AlterCurrentUserPrivs(const std::vector<std::wstring>& vPrivsToGrant, const BOOL bAddRights,
	std::vector<std::wstring>* pAddedPrivs)
{
	if (pAddedPrivs != nullptr) pAddedPrivs->clear();
	if (vPrivsToGrant.empty()) return TRUE;

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

	// Preserve rights already assigned to the account but absent from its current logon token.
	std::vector<std::wstring> vAssignedPrivs;
	if (bAddRights)
	{
		SmartPointer<PLSA_UNICODE_STRING> pRights(LsaFreeMemory, nullptr);
		ULONG iCount = 0;
		iResult = LsaEnumerateAccountRights(hPolicyHandle, tTokenUser->User.Sid, &pRights, &iCount);
		if (iResult == STATUS_OBJECT_NAME_NOT_FOUND) iCount = 0;
		if (iResult != STATUS_SUCCESS && iResult != STATUS_OBJECT_NAME_NOT_FOUND)
		{
			PrintMessage(L"ERROR: Could not read current account privileges: %lu\n", LsaNtStatusToWinError(iResult));
			return FALSE;
		}
		for (ULONG i = 0; i < iCount; i++)
		{
			vAssignedPrivs.emplace_back(pRights[i].Buffer, pRights[i].Length / sizeof(WCHAR));
		}
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
			if (std::ranges::any_of(vAssignedPrivs, [&](const std::wstring& sAssigned) {
				return _wcsicmp(sAssigned.c_str(), sPrivilege.c_str()) == 0;
			})) return;
			if ((iResult = LsaAddAccountRights(hPolicyHandle,
				tTokenUser->User.Sid, &sUnicodePrivilege, 1)) != STATUS_SUCCESS)
			{
				bSuccessful = FALSE;
				PrintMessage(L"ERROR: Privilege '%s' was not able to be added with error '%u'\n",
					sPrivilege.c_str(), LsaNtStatusToWinError(iResult));
			}
			else
			{
				vAssignedPrivs.push_back(sPrivilege);
				if (pAddedPrivs != nullptr) pAddedPrivs->push_back(sPrivilege);
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

static std::optional<std::vector<std::wstring>> QueryAccountRights(const std::wstring& sAccountName)
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
		return std::nullopt;
	}

	// open LSA policy on the local machine
	LSA_OBJECT_ATTRIBUTES tAttrs{};
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, nullptr);
	NTSTATUS iResult = LsaOpenPolicy(nullptr, &tAttrs, POLICY_LOOKUP_NAMES, &hPolicy);
	if (iResult != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Could not open security policy: %lu\n",
			LsaNtStatusToWinError(iResult));
		return std::nullopt;
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
		return std::nullopt;
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
		NTSTATUS iEnumerationStatus = STATUS_SUCCESS;

		while ((iEnumerationStatus = LsaEnumerateAccounts(hPolicy, &hEnum,
			reinterpret_cast<PVOID*>(&pAccounts), ULONG_MAX, &iAccountCount)) == STATUS_SUCCESS ||
			iEnumerationStatus == STATUS_MORE_ENTRIES)
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
				if (iResult == STATUS_OBJECT_NAME_NOT_FOUND) continue;
				if (iResult != STATUS_SUCCESS)
				{
					bSuccessful = FALSE;
					PrintMessage(L"ERROR: Could not enumerate rights for '%s': %lu\n",
						sDisplayName.c_str(), LsaNtStatusToWinError(iResult));
					continue;
				}

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

			pAccounts.Cleanup();
		}
		if (iEnumerationStatus != STATUS_NO_MORE_ENTRIES)
		{
			bSuccessful = FALSE;
			PrintMessage(L"ERROR: Could not enumerate security-policy accounts: %lu\n",
				LsaNtStatusToWinError(iEnumerationStatus));
		}

		return bSuccessful;
	}

	// enumerate rights actually assigned so we only act on ones that are present
	const std::optional<std::vector<std::wstring>> vAssigned = QueryAccountRights(sAccountName);
	if (!vAssigned.has_value()) return FALSE;

	// intersect the deny list with what is actually assigned so output is meaningful
	std::vector<std::wstring> vToRemove;
	for (const auto& sRight : g_vDenyRights)
	{
		if (std::ranges::find(*vAssigned, sRight) != vAssigned->end())
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

		pPrivs.Cleanup();
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
		SmartPointer<HANDLE> hProcess(CloseHandle,
			OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, 0, tEntry.th32ProcessID));
		if (!hProcess || TerminateProcess(hProcess, 1) == 0)
		{
			const DWORD iError = GetLastError();
			PrintMessage(L"ERROR: Could not terminate process '%s' (%lu): %lu\n",
				sProcessName.c_str(), tEntry.th32ProcessID, iError);
			continue;
		}
		if (WaitForSingleObject(hProcess, INFINITE) != WAIT_OBJECT_0)
		{
			PrintMessage(L"ERROR: Could not wait for process '%s' (%lu) to terminate.\n",
				sProcessName.c_str(), tEntry.th32ProcessID);
		}
	}
}
