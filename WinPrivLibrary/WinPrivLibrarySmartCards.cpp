//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivLibrary.h"
#include <intrin.h>
#include <ncrypt.h>
#include <wincred.h>
#include <wtsapi32.h>

#pragma comment(lib, "ncrypt.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "wtsapi32.lib")

static BOOLEAN (WINAPI* TrueWinStationGetCurrentSessionCapabilities)(DWORD, DWORD*) = nullptr;
static auto TrueNCryptSignHash = &NCryptSignHash;

static BOOLEAN WINAPI DetourWinStationGetCurrentSessionCapabilities(DWORD iCapability, DWORD* pValue)
{
	const BOOLEAN bResult = TrueWinStationGetCurrentSessionCapabilities(iCapability, pValue);
	if (!bResult || iCapability != 1 || pValue == nullptr || *pValue == 0) return bResult;

	// Only WinSCard's reader-routing query should see a local session.
	const DWORD iError = GetLastError();
	HMODULE hCaller = nullptr;
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(_ReturnAddress()), &hCaller) && hCaller == GetModuleHandleW(L"winscard.dll"))
		*pValue = 0;
	SetLastError(iError);
	return bResult;
}

static bool IsSmartCardKey(NCRYPT_KEY_HANDLE hKey)
{
	// The provider handle is a new reference owned by the caller.
	NCRYPT_PROV_HANDLE hProvider = 0;
	DWORD iSize = 0;
	if (NCryptGetProperty(hKey, NCRYPT_PROVIDER_HANDLE_PROPERTY, reinterpret_cast<PBYTE>(&hProvider),
		sizeof(hProvider), &iSize, 0) != ERROR_SUCCESS || iSize != sizeof(hProvider)) return false;

	WCHAR sProvider[128]{};
	const bool bSmartCard = NCryptGetProperty(hProvider, NCRYPT_NAME_PROPERTY, reinterpret_cast<PBYTE>(sProvider),
		sizeof(sProvider) - sizeof(WCHAR), &iSize, 0) == ERROR_SUCCESS &&
		wcscmp(sProvider, MS_SMART_CARD_KEY_STORAGE_PROVIDER) == 0;
	NCryptFreeObject(hProvider);
	return bSmartCard;
}

static bool IsRemoteSession()
{
	// Recheck the connection so console/RDP reconnects take effect in the same process.
	SmartPointer<LPWSTR> pProtocol(WTSFreeMemory, nullptr);
	DWORD iSize = 0;
	return WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION,
		WTSClientProtocolType, &pProtocol, &iSize) && pProtocol != nullptr &&
		iSize >= sizeof(USHORT) && *pProtocol != 0;
}

static SECURITY_STATUS WINAPI DetourNCryptSignHash(NCRYPT_KEY_HANDLE hKey, VOID* pPaddingInfo,
	PBYTE pHash, DWORD iHashSize, PBYTE pSignature, DWORD iSignatureSize, DWORD* pResultSize, DWORD iFlags)
{
	// Local sessions, other providers, and explicitly silent requests keep their normal signing behavior.
	if ((iFlags & NCRYPT_SILENT_FLAG) != 0 || !IsSmartCardKey(hKey) || !IsRemoteSession())
		return TrueNCryptSignHash(hKey, pPaddingInfo, pHash, iHashSize,
			pSignature, iSignatureSize, pResultSize, iFlags);

	// The normal smart-card credential provider validates the PIN in a separate, unhooked process.
	SECURITY_STATUS iStatus = TrueNCryptSignHash(hKey, pPaddingInfo, pHash, iHashSize,
		pSignature, iSignatureSize, pResultSize, iFlags | NCRYPT_SILENT_FLAG);
	if (iStatus != NTE_SILENT_CONTEXT) return iStatus;

	CREDUI_INFOW tInfo{ sizeof(tInfo) };
	tInfo.pszCaptionText = L"Hardware Token";
	tInfo.pszMessageText = L"Enter your hardware token PIN in the password field.";
	WCHAR sUser[CREDUI_MAX_USERNAME_LENGTH + 1] = L"Hardware Token";
	WCHAR sPin[CREDUI_MAX_PASSWORD_LENGTH + 1]{};

	// Prefill the account label so the Windows dialog only needs the token PIN.
	BYTE aInput[256];
	DWORD iInputSize = sizeof(aInput);
	if (!CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, sUser, sPin, aInput, &iInputSize))
		return HRESULT_FROM_WIN32(GetLastError());

	// Generic credentials leave PIN validation in the hooked signing process.
	ULONG iAuthPackage = 0;
	ULONG iOutputSize = 0;
	SmartPointer<PVOID> pOutput([&](PVOID p) { SecureZeroMemory(p, iOutputSize); CoTaskMemFree(p); }, nullptr);
	DWORD iPromptFlags = CREDUIWIN_GENERIC;
	BOOL bWow64 = FALSE;
	if (IsWow64Process(GetCurrentProcess(), &bWow64) && bWow64) iPromptFlags |= CREDUIWIN_PACK_32_WOW;
	DWORD iPromptStatus = CredUIPromptForWindowsCredentialsW(&tInfo, 0, &iAuthPackage, aInput, iInputSize,
		&pOutput, &iOutputSize, nullptr, iPromptFlags);
	DWORD iUserLength = ARRAYSIZE(sUser);
	DWORD iPinLength = ARRAYSIZE(sPin);
	if (iPromptStatus == ERROR_SUCCESS && !CredUnPackAuthenticationBufferW(0, pOutput, iOutputSize,
		sUser, &iUserLength, nullptr, nullptr, sPin, &iPinLength)) iPromptStatus = GetLastError();
	pOutput.Cleanup();
	iStatus = iPromptStatus == ERROR_SUCCESS
		? NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, reinterpret_cast<PBYTE>(sPin),
			static_cast<DWORD>((wcslen(sPin) + 1) * sizeof(WCHAR)), NCRYPT_SILENT_FLAG)
		: iPromptStatus == ERROR_CANCELLED ? NTE_USER_CANCELLED : HRESULT_FROM_WIN32(iPromptStatus);
	SecureZeroMemory(sPin, sizeof(sPin));
	if (iStatus != ERROR_SUCCESS) return iStatus;

	// Make one authenticated attempt; a wrong PIN must not trigger automatic retries.
	return TrueNCryptSignHash(hKey, pPaddingInfo, pHash, iHashSize,
		pSignature, iSignatureSize, pResultSize, iFlags | NCRYPT_SILENT_FLAG);
}

bool AttachSmartCardHooks(winpriv::detours::transaction& transaction)
{
	if (!VariableIsSet(WINPRIV_EV_CONSOLE_TOKEN, 1)) return true;

	// Keep the system module loaded for the lifetime of the hook.
	const HMODULE hWinStation = LoadLibraryExW(L"winsta.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (hWinStation == nullptr) return false;
	TrueWinStationGetCurrentSessionCapabilities =
		reinterpret_cast<decltype(TrueWinStationGetCurrentSessionCapabilities)>(
			GetProcAddress(hWinStation, "WinStationGetCurrentSessionCapabilities"));
	if (TrueWinStationGetCurrentSessionCapabilities == nullptr) return false;

	// shortcut: WinSCard's capability query is undocumented, recheck it if Windows changes reader routing.
	transaction.attach(TrueWinStationGetCurrentSessionCapabilities, DetourWinStationGetCurrentSessionCapabilities);
	transaction.attach(TrueNCryptSignHash, DetourNCryptSignHash);
	return true;
}
