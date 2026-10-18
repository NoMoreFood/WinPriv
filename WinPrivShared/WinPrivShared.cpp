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
#include <string>
#include <string_view>
#include <vector>

#include "WinPrivShared.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "normaliz.lib")

std::wstring NormalizeHostName(std::wstring_view name)
{
	// Match DNS names by their ASCII spelling without a terminal root separator.
	if (name.empty() || name.size() > static_cast<size_t>((std::numeric_limits<int>::max)()) ||
		name.find_first_of(L" \t\r\n\"/\\*?") != name.npos) return {};
	std::wstring normalized(name);
	if (name.find(L':') == name.npos)
	{
		const int length = IdnToAscii(0, name.data(), static_cast<int>(name.size()), nullptr, 0);
		if (length == 0) return {};
		normalized.resize(length);
		if (IdnToAscii(0, name.data(), static_cast<int>(name.size()), normalized.data(), length) == 0) return {};
	}
	if (!normalized.empty() && normalized.back() == L'.') normalized.pop_back();
	for (wchar_t& character : normalized)
		if (character >= L'A' && character <= L'Z') character += L'a' - L'A';
	return normalized;
}

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

static const auto ConvertFileRulePath = LoadNtFunction<NTSTATUS(NTAPI*)(PCWSTR, PUNICODE_STRING, PWSTR*, PVOID)>(
	"RtlDosLongPathNameToNtPathName_U_WithStatus");

std::wstring ResolveFileRulePath(std::wstring path)
{
	// Normalize DOS paths once, before rules are inherited by processes with different current directories.
	std::ranges::replace(path, L'/', L'\\');
	constexpr std::wstring_view extendedPrefix = L"\\\\?\\";
	if (path.empty() || path.find_first_of(L"*?\"",
		path.starts_with(extendedPrefix) ? extendedPrefix.size() : 0) != std::wstring::npos) return {};

	// Let the native runtime allocate the absolute NT path.
	UNICODE_STRING name{};
	SmartPointer<PUNICODE_STRING> cleanup(RtlFreeUnicodeString, &name);
	if (ConvertFileRulePath(path.c_str(), &name, nullptr, nullptr) < 0) return {};
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
		if (!sArg.empty() && sArg.find_first_of(L" \t\"") == std::wstring::npos)
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

			// Escape both the accumulated backslashes and any quote itself.
			sResult.append(c == L'"' ? iBackslashes * 2 + 1 : iBackslashes, L'\\');
			sResult += c;
			iBackslashes = 0;
		}

		// Backslashes immediately before the closing quote must be doubled.
		sResult.append(iBackslashes * 2, L'\\');
		sResult += L'"';
	}

	return sResult;
}

std::vector<std::wstring> EnablePrivs(const std::vector<std::wstring>& vRequestedPrivs)
{
	// open the current token
	SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken) == 0)
	{
		PrintMessage(L"ERROR: Could not open process token for enabling privileges.\n");
		return vRequestedPrivs;
	}

	// enable each privilege; rights do not have to be enabled since they are automatically established
	std::vector<std::wstring> vUnavailablePrivs;
	for (const std::wstring& sPrivilege : vRequestedPrivs)
	{
		if (sPrivilege.ends_with(L"Right")) continue;
		TOKEN_PRIVILEGES tPrivEntry{
			.PrivilegeCount = 1,
			.Privileges = {{ .Luid = {}, .Attributes = SE_PRIVILEGE_ENABLED }}
		};
		if (LookupPrivilegeValue(nullptr, sPrivilege.c_str(), &tPrivEntry.Privileges[0].Luid) == 0)
		{
			PrintMessage(L"ERROR: Could not lookup privilege: %s\n", sPrivilege.c_str());
			vUnavailablePrivs.push_back(sPrivilege);
		}
		else if (AdjustTokenPrivileges(hToken, FALSE, &tPrivEntry, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) == 0 ||
			GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		{
			vUnavailablePrivs.push_back(sPrivilege);
		}
	}

	return vUnavailablePrivs;
}

static LSA_HANDLE OpenLocalPolicy(const ACCESS_MASK iAccess)
{
	// open LSA policy on the local machine; object attributes are reserved
	LSA_OBJECT_ATTRIBUTES tAttributes{};
	LSA_HANDLE hPolicy = nullptr;
	const NTSTATUS iResult = LsaOpenPolicy(nullptr, &tAttributes, iAccess, &hPolicy);
	if (iResult == STATUS_SUCCESS) return hPolicy;
	PrintMessage(L"ERROR: Could not open security policy: %lu\n", LsaNtStatusToWinError(iResult));
	return nullptr;
}

static bool ResolveAccountSid(const std::wstring& sAccountName, std::array<BYTE, SECURITY_MAX_SID_SIZE>& aSid)
{
	// resolve the SID for the named account on the local machine
	DWORD iSidSize = static_cast<DWORD>(aSid.size());
	WCHAR sReferencedDomain[MAX_PATH] = {};
	DWORD iDomainSize = MAX_PATH;
	SID_NAME_USE tSidType;
	if (LookupAccountName(nullptr, sAccountName.c_str(), aSid.data(), &iSidSize,
		sReferencedDomain, &iDomainSize, &tSidType)) return true;
	PrintMessage(L"ERROR: Could not resolve account '%s': %lu\n", sAccountName.c_str(), GetLastError());
	return false;
}

static NTSTATUS EnumerateAccountRights(LSA_HANDLE hPolicy, PSID pSid, std::vector<std::wstring>& vRights)
{
	// an account without assigned rights reports not found, which is an empty list
	SmartPointer<PLSA_UNICODE_STRING> pRights(LsaFreeMemory, nullptr);
	ULONG iCount = 0;
	const NTSTATUS iResult = LsaEnumerateAccountRights(hPolicy, pSid, &pRights, &iCount);
	if (iResult == STATUS_OBJECT_NAME_NOT_FOUND) return STATUS_SUCCESS;
	for (ULONG i = 0; iResult == STATUS_SUCCESS && i < iCount; i++)
		vRights.emplace_back(pRights[i].Buffer, pRights[i].Length / sizeof(WCHAR));
	return iResult;
}

static LSA_UNICODE_STRING ToLsaString(const std::wstring& sValue)
{
	return { static_cast<USHORT>(sValue.length() * sizeof(WCHAR)),
		static_cast<USHORT>((sValue.length() + 1) * sizeof(WCHAR)), const_cast<PWSTR>(sValue.c_str()) };
}

BOOL AlterCurrentUserPrivs(const std::vector<std::wstring>& vPrivsToGrant, const BOOL bAddRights,
	std::vector<std::wstring>* pAddedPrivs)
{
	if (pAddedPrivs != nullptr) pAddedPrivs->clear();
	if (vPrivsToGrant.empty()) return TRUE;

	// get the current user sid out of the token
	SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
	alignas(TOKEN_USER) std::array<BYTE, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> aBuffer{};
	const auto tTokenUser = reinterpret_cast<PTOKEN_USER>(aBuffer.data());
	DWORD iBytesFilled = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) ||
		!GetTokenInformation(hToken, TokenUser, tTokenUser, static_cast<DWORD>(aBuffer.size()), &iBytesFilled))
	{
		PrintMessage(L"ERROR: Could not retrieve process token information.\n");
		return FALSE;
	}
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, OpenLocalPolicy(POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT));
	if (!hPolicy) return FALSE;

	// Preserve rights already assigned to the account but absent from its current logon token.
	std::vector<std::wstring> vAssignedPrivs;
	const PSID pSid = tTokenUser->User.Sid;
	NTSTATUS iResult = bAddRights ? EnumerateAccountRights(hPolicy, pSid, vAssignedPrivs) : STATUS_SUCCESS;
	if (iResult != STATUS_SUCCESS)
	{
		PrintMessage(L"ERROR: Could not read current account privileges: %lu\n", LsaNtStatusToWinError(iResult));
		return FALSE;
	}

	// add or remove each privilege for the current user
	BOOL bSuccessful = TRUE;
	for (const std::wstring& sPrivilege : vPrivsToGrant)
	{
		if (bAddRights && std::ranges::any_of(vAssignedPrivs, [&](const std::wstring& sAssigned) {
			return _wcsicmp(sAssigned.c_str(), sPrivilege.c_str()) == 0; })) continue;
		LSA_UNICODE_STRING tPrivilege = ToLsaString(sPrivilege);
		iResult = bAddRights ? LsaAddAccountRights(hPolicy, pSid, &tPrivilege, 1) :
			LsaRemoveAccountRights(hPolicy, pSid, FALSE, &tPrivilege, 1);
		if (iResult != STATUS_SUCCESS)
		{
			bSuccessful = FALSE;
			PrintMessage(L"ERROR: Privilege '%s' could not be %s with error '%lu'\n",
				sPrivilege.c_str(), bAddRights ? L"added" : L"removed", LsaNtStatusToWinError(iResult));
		}
		else if (bAddRights)
		{
			vAssignedPrivs.push_back(sPrivilege);
			if (pAddedPrivs != nullptr) pAddedPrivs->push_back(sPrivilege);
		}
	}

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
	// resolve the account and open local security policy
	std::array<BYTE, SECURITY_MAX_SID_SIZE> aSid{};
	if (!ResolveAccountSid(sAccountName, aSid)) return FALSE;
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, OpenLocalPolicy(POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT));
	if (!hPolicy) return FALSE;

	// apply each right; revoking a right that is not assigned already reaches the desired state
	BOOL bSuccessful = TRUE;
	for (const std::wstring& sRight : vRights)
	{
		LSA_UNICODE_STRING tRight = ToLsaString(sRight);
		const NTSTATUS iResult = bGrant ? LsaAddAccountRights(hPolicy, aSid.data(), &tRight, 1) :
			LsaRemoveAccountRights(hPolicy, aSid.data(), FALSE, &tRight, 1);
		if (!bGrant && iResult == STATUS_OBJECT_NAME_NOT_FOUND) continue;
		if (iResult != STATUS_SUCCESS)
		{
			bSuccessful = FALSE;
			PrintMessage(L"ERROR: Failed to %s right '%s' %s '%s': %lu\n", bGrant ? L"grant" : L"revoke",
				sRight.c_str(), bGrant ? L"to" : L"from", sAccountName.c_str(), LsaNtStatusToWinError(iResult));
		}
		else
		{
			PrintMessage(L"INFO: %s right '%s' %s '%s'\n", bGrant ? L"Granted" : L"Revoked",
				sRight.c_str(), bGrant ? L"to" : L"from", sAccountName.c_str());
		}
	}

	return bSuccessful;
}

BOOL ClearDenyRights(const std::wstring& sAccountName)
{
	// open LSA policy with the access needed to enumerate accounts, read their rights, and remove rights
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose,
		OpenLocalPolicy(POLICY_VIEW_LOCAL_INFORMATION | POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT));
	if (!hPolicy) return FALSE;

	// remove the deny rights assigned to an account, returning false only when it has none
	BOOL bSuccessful = TRUE;
	const auto ClearAccount = [&](PSID pSid, const std::wstring& sDisplayName)
	{
		std::vector<std::wstring> vAssigned;
		NTSTATUS iResult = EnumerateAccountRights(hPolicy, pSid, vAssigned);
		if (iResult != STATUS_SUCCESS)
		{
			bSuccessful = FALSE;
			PrintMessage(L"ERROR: Could not enumerate rights for '%s': %lu\n",
				sDisplayName.c_str(), LsaNtStatusToWinError(iResult));
			return true;
		}

		bool bFound = false;
		for (const std::wstring& sRight : g_vDenyRights)
		{
			if (std::ranges::find(vAssigned, sRight) == vAssigned.end()) continue;
			bFound = true;
			LSA_UNICODE_STRING tRight = ToLsaString(sRight);
			iResult = LsaRemoveAccountRights(hPolicy, pSid, FALSE, &tRight, 1);
			if (iResult != STATUS_SUCCESS)
			{
				bSuccessful = FALSE;
				PrintMessage(L"ERROR: Failed to revoke '%s' from '%s': %lu\n",
					sRight.c_str(), sDisplayName.c_str(), LsaNtStatusToWinError(iResult));
			}
			else
			{
				PrintMessage(L"INFO: Revoked '%s' from '%s'\n", sRight.c_str(), sDisplayName.c_str());
			}
		}
		return bFound;
	};

	// clear the named account
	if (!sAccountName.empty())
	{
		std::array<BYTE, SECURITY_MAX_SID_SIZE> aSid{};
		if (!ResolveAccountSid(sAccountName, aSid)) return FALSE;
		if (!ClearAccount(aSid.data(), sAccountName))
			PrintMessage(L"INFO: No deny rights are assigned to '%s'\n", sAccountName.c_str());
		return bSuccessful;
	}

	// otherwise clear every account that has any rights assigned on this machine
	LSA_ENUMERATION_HANDLE hEnum = 0;
	ULONG iAccountCount = 0;
	SmartPointer<PLSA_ENUMERATION_INFORMATION> pAccounts(LsaFreeMemory, nullptr);
	NTSTATUS iEnumerationStatus = STATUS_SUCCESS;
	while ((iEnumerationStatus = LsaEnumerateAccounts(hPolicy, &hEnum,
		reinterpret_cast<PVOID*>(&pAccounts), ULONG_MAX, &iAccountCount)) == STATUS_SUCCESS ||
		iEnumerationStatus == STATUS_MORE_ENTRIES)
	{
		for (ULONG i = 0; i < iAccountCount; i++)
		{
			// resolve the SID to an account name for display purposes
			WCHAR sName[MAX_PATH] = {};
			DWORD iNameSize = MAX_PATH;
			WCHAR sDomainName[MAX_PATH] = {};
			DWORD iDomainNameSize = MAX_PATH;
			SID_NAME_USE tSidType;
			LookupAccountSid(nullptr, pAccounts[i].Sid, sName, &iNameSize, sDomainName, &iDomainNameSize, &tSidType);
			ClearAccount(pAccounts[i].Sid, sDomainName[0] == L'\0' ? sName : std::wstring(sDomainName) + L"\\" + sName);
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

BOOL GrantAllRights(const std::wstring& sAccountName)
{
	// enumerate all privileges defined on the system
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, OpenLocalPolicy(POLICY_VIEW_LOCAL_INFORMATION));
	if (!hPolicy) return FALSE;
	std::vector<std::wstring> vRightsToGrant;
	LSA_ENUMERATION_HANDLE hEnum = 0;
	ULONG iCount = 0;
	NTSTATUS iResult = STATUS_SUCCESS;
	SmartPointer<PPOLICY_PRIVILEGE_DEFINITION> pPrivs(LsaFreeMemory, nullptr);
	while ((iResult = LsaEnumeratePrivileges(hPolicy, &hEnum,
		reinterpret_cast<PVOID*>(&pPrivs), ULONG_MAX, &iCount)) == STATUS_SUCCESS || iResult == STATUS_MORE_ENTRIES)
	{
		for (ULONG i = 0; i < iCount; i++)
			vRightsToGrant.emplace_back(pPrivs[i].Name.Buffer, pPrivs[i].Name.Length / sizeof(WCHAR));
		pPrivs.Cleanup();
	}
	if (iResult != STATUS_NO_MORE_ENTRIES)
	{
		PrintMessage(L"ERROR: Could not enumerate system privileges: %lu\n", LsaNtStatusToWinError(iResult));
		return FALSE;
	}

	// append all allow-logon rights (these are not returned by LsaEnumeratePrivileges)
	vRightsToGrant.insert(vRightsToGrant.end(), g_vLogonRights.begin(), g_vLogonRights.end());
	return ModifyAccountRights(sAccountName, vRightsToGrant, TRUE);
}

void KillProcess(const std::wstring& sProcessName, DWORD iSessionId)
{
	// use the caller's own session id if no explicit session was specified
	if (iSessionId == MAXDWORD && ProcessIdToSessionId(GetCurrentProcessId(), &iSessionId) == 0) return;

	// enumerate all processes, looking for match by name
	PROCESSENTRY32 tEntry{ .dwSize = sizeof(PROCESSENTRY32) };
	SmartPointer<HANDLE> hSnapshot(CloseHandle, CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));
	for (BOOL bValid = Process32First(hSnapshot, &tEntry); bValid; bValid = Process32Next(hSnapshot, &tEntry))
	{
		// skip process if not the target session id or session id lookup fails
		DWORD iProcessSessionId = 0;
		if (_wcsicmp(tEntry.szExeFile, sProcessName.c_str()) != 0 ||
			ProcessIdToSessionId(tEntry.th32ProcessID, &iProcessSessionId) == 0 ||
			iProcessSessionId != iSessionId) continue;

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
