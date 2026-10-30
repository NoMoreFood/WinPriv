//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivLibrary.h"

#define _NTDEF_
using PNTSTATUS = NTSTATUS*;
#include <NTSecAPI.h>

#pragma comment(lib, "advapi32.lib")

static auto TrueCreateProcessWithLogonW = &CreateProcessWithLogonW;

static DWORD LogonInteractiveUser(LPCWSTR sUser, LPCWSTR sDomain, LPCWSTR sPassword, PHANDLE pToken)
{
	// Authenticate first, changing policy only when the account lacks this logon right.
	if (LogonUserW(sUser, sDomain, sPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, pToken))
		return ERROR_SUCCESS;
	const DWORD iLogonError = GetLastError();
	if (iLogonError != ERROR_LOGON_TYPE_NOT_GRANTED) return iLogonError;

	// Resolve the account before granting rights in the local security policy.
	const std::wstring sAccount = sDomain != nullptr && *sDomain != L'\0'
		? std::wstring(sDomain) + L"\\" + sUser : sUser;
	DWORD iSidSize = 0, iDomainSize = 0;
	SID_NAME_USE eUse{};
	LookupAccountNameW(nullptr, sAccount.c_str(), nullptr, &iSidSize, nullptr, &iDomainSize, &eUse);
	if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) return GetLastError();
	std::vector<BYTE> vSid(iSidSize);
	std::vector<WCHAR> vDomain(iDomainSize);
	if (!LookupAccountNameW(nullptr, sAccount.c_str(), vSid.data(), &iSidSize,
		vDomain.data(), &iDomainSize, &eUse)) return GetLastError();
	LSA_OBJECT_ATTRIBUTES tAttributes{};
	SmartPointer<LSA_HANDLE> hPolicy(LsaClose, nullptr);
	NTSTATUS iStatus = LsaOpenPolicy(nullptr, &tAttributes, POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT, &hPolicy);
	if (iStatus < 0) return LsaNtStatusToWinError(iStatus);

	// Preserve existing assignments, including when an explicit deny prevents logon.
	WCHAR sRight[] = SE_INTERACTIVE_LOGON_NAME;
	LSA_UNICODE_STRING tRight{ sizeof(sRight) - sizeof(WCHAR), sizeof(sRight), sRight };
	SmartPointer<PLSA_UNICODE_STRING> pRights(LsaFreeMemory, nullptr);
	ULONG iCount = 0;
	iStatus = LsaEnumerateAccountRights(hPolicy, vSid.data(), &pRights, &iCount);
	if (iStatus < 0 && iStatus != STATUS_OBJECT_NAME_NOT_FOUND) return LsaNtStatusToWinError(iStatus);
	for (ULONG iIndex = 0; iIndex < iCount; ++iIndex)
	{
		if (pRights[iIndex].Length == tRight.Length &&
			_wcsnicmp(pRights[iIndex].Buffer, tRight.Buffer, tRight.Length / sizeof(WCHAR)) == 0)
			return ERROR_LOGON_TYPE_NOT_GRANTED;
	}
	iStatus = LsaAddAccountRights(hPolicy, vSid.data(), &tRight, 1);
	if (iStatus < 0) return LsaNtStatusToWinError(iStatus);
	if (LogonUserW(sUser, sDomain, sPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, pToken))
		return ERROR_SUCCESS;

	// Undo only our new assignment when it does not enable this logon.
	const DWORD iRetryError = GetLastError();
	iStatus = LsaRemoveAccountRights(hPolicy, vSid.data(), FALSE, &tRight, 1);
	return iStatus < 0 ? LsaNtStatusToWinError(iStatus) : iRetryError;
}

static BOOL WINAPI DetourCreateProcessWithLogonW(LPCWSTR sUser, LPCWSTR sDomain, LPCWSTR sPassword,
	DWORD iLogonFlags, LPCWSTR sApplication, LPWSTR sCommandLine, DWORD iCreationFlags,
	LPVOID pEnvironment, LPCWSTR sDirectory, LPSTARTUPINFOW pStartup, LPPROCESS_INFORMATION pProcess)
{
	// Network-only credentials are outside this replacement's supported logon modes.
	if (sUser == nullptr || pStartup == nullptr || pProcess == nullptr ||
		(iLogonFlags != 0 && iLogonFlags != LOGON_WITH_PROFILE) ||
		pStartup->cb < ((iCreationFlags & EXTENDED_STARTUPINFO_PRESENT) ? sizeof(STARTUPINFOEXW) : sizeof(STARTUPINFOW)))
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	try
	{
		SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
		DWORD iError = LogonInteractiveUser(sUser, sDomain, sPassword, &hToken);
		BOOL bCreated = FALSE;
		if (iError == ERROR_SUCCESS)
		{
			// Preserve extended startup attributes and leave the caller's structure untouched.
			STARTUPINFOEXW tStartup{};
			tStartup.StartupInfo = *pStartup;
			if (iCreationFlags & EXTENDED_STARTUPINFO_PRESENT)
				tStartup = *reinterpret_cast<LPSTARTUPINFOEXW>(pStartup);
			WCHAR sDesktop[] = L"Default";
			if (tStartup.StartupInfo.lpDesktop == nullptr || *tStartup.StartupInfo.lpDesktop == L'\0')
				tStartup.StartupInfo.lpDesktop = sDesktop;
			bCreated = CreateProcessWithTokenW(hToken, iLogonFlags, sApplication, sCommandLine, iCreationFlags,
				pEnvironment, sDirectory, &tStartup.StartupInfo, pProcess);
			iError = GetLastError();
		}

		// Native cleanup must not replace the logon or process-creation error.
		hToken.Cleanup();
		SetLastError(iError);
		return bCreated;
	}
	catch (...)
	{
		SetLastError(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}
}

bool AttachLogonHooks()
{
	if (!VariableIsSet(WINPRIV_EV_ALLOW_CREATE_PROCESS_AS_SYSTEM, 1)) return true;

	// Only LocalSystem lacks the caller logon SID required by CreateProcessWithLogonW.
	SmartPointer<HANDLE> hToken(CloseHandle, nullptr);
	alignas(TOKEN_USER) std::array<BYTE, sizeof(TOKEN_USER) + SECURITY_MAX_SID_SIZE> vBuffer{};
	const auto pUser = reinterpret_cast<PTOKEN_USER>(vBuffer.data());
	DWORD iSize = 0;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken) ||
		!GetTokenInformation(hToken, TokenUser, pUser, static_cast<DWORD>(vBuffer.size()), &iSize)) return false;
	if (IsWellKnownSid(pUser->User.Sid, WinLocalSystemSid))
		AttachDetour(TrueCreateProcessWithLogonW, DetourCreateProcessWithLogonW);
	return true;
}
