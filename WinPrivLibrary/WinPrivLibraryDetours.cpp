//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define _WINSOCKAPI_
#include "WinPrivLibrary.h"
#include <cstdio>
#include <conio.h>
#include <ShlObj.h>
#include <LM.h>
#include <WinSock2.h>
#include <iphlpapi.h>
#include <ws2ipdef.h>
#include <WS2tcpip.h>
#include <mstcpip.h>
#include <wincrypt.h>
#include <sqlext.h>
#include <amsi.h>
#include <wldp.h>
#include <winsafer.h>

#define _NTDEF_
#include <NTSecAPI.h>

#include <algorithm>
#include <string>
#include <vector>
#include <regex>
#include <atomic>
#include <array>
#include <cerrno>
#include <limits>
#include <memory>

#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"amsi.lib")
#pragma comment(lib,"wldp.lib")

//   __   ___  __     __  ___  __          __   ___       __
//  |__) |__  / _` | /__`  |  |__) \ /    |__) |__   /\  |  \
//  |  \ |___ \__> | .__/  |  |  \  |     |  \ |___ /~~\ |__/
//

typedef struct RegInterceptInfo
{
	UNICODE_STRING RegKeyName;
	UNICODE_STRING RegValueName;
	DWORD RegValueType;
	DWORD RegValueDataSize;
	PVOID RegValueData;
}
RegInterceptInfo;

static constexpr DWORD REG_BLOCK = (std::numeric_limits<DWORD>::max)();

static void FreeRegInterceptInfo(RegInterceptInfo* tInterceptInfo)
{
	if (tInterceptInfo == nullptr) return;
	free(tInterceptInfo->RegKeyName.Buffer);
	free(tInterceptInfo->RegValueName.Buffer);
	free(tInterceptInfo->RegValueData);
	free(tInterceptInfo);
}

static bool UnicodeStringEquals(const UNICODE_STRING& sLeft, const UNICODE_STRING* sRight)
{
	if (sRight == nullptr || sLeft.Length != sRight->Length) return false;
	if (sLeft.Length == 0) return true;
	return sLeft.Buffer != nullptr && sRight->Buffer != nullptr && CompareStringOrdinal(sLeft.Buffer,
		sLeft.Length / sizeof(WCHAR), sRight->Buffer, sRight->Length / sizeof(WCHAR), TRUE) == CSTR_EQUAL;
}

static bool RegistryKeyIsSameOrDescendant(const UNICODE_STRING& sParent, const UNICODE_STRING& sKey)
{
	if (sParent.Length > sKey.Length || sParent.Buffer == nullptr || sKey.Buffer == nullptr)
		return false;

	const int iParentChars = sParent.Length / sizeof(WCHAR);
	if (CompareStringOrdinal(sParent.Buffer, iParentChars, sKey.Buffer, iParentChars, TRUE) != CSTR_EQUAL) return false;
	return sParent.Length == sKey.Length || sKey.Buffer[iParentChars] == L'\\';
}

template <typename Integer>
static bool ParseRegistryInteger(LPCWSTR sData, Integer& iValue)
{
	// accept decimal, hexadecimal, or octal notation that fits the value type
	if (sData == nullptr || *sData == L'\0') return false;
	errno = 0;
	LPWSTR sEnd = nullptr;
	unsigned __int64 iParsed = 0;
	if constexpr (sizeof(Integer) == sizeof(DWORD)) iParsed = wcstoul(sData, &sEnd, 0);
	else iParsed = _wcstoui64(sData, &sEnd, 0);
	if (errno == ERANGE || sEnd == sData || *sEnd != L'\0') return false;
	iValue = static_cast<Integer>(iParsed);
	return true;
}

static bool DecodeHex(std::wstring_view sText, PBYTE pBytes)
{
	// decode pairs of hexadecimal digits into the caller's buffer of sText.size() / 2 bytes
	const auto HexDigitValue = [](const WCHAR iChar)
	{
		if (iChar >= L'0' && iChar <= L'9') return iChar - L'0';
		if (iChar >= L'a' && iChar <= L'f') return iChar - L'a' + 10;
		if (iChar >= L'A' && iChar <= L'F') return iChar - L'A' + 10;
		return -1;
	};
	for (size_t iByte = 0; iByte < sText.size() / 2; iByte++)
	{
		const int iHigh = HexDigitValue(sText[iByte * 2]);
		const int iLow = HexDigitValue(sText[iByte * 2 + 1]);
		if (iHigh < 0 || iLow < 0) return false;
		pBytes[iByte] = static_cast<BYTE>((iHigh << 4) | iLow);
	}
	return true;
}

static NTSTATUS RegistryBufferStatus(PVOID pBuffer, ULONG iLength,
	ULONG iFixedHeader, ULONG iRequired)
{
	if (pBuffer != nullptr && iLength >= iRequired) return STATUS_SUCCESS;
	return pBuffer != nullptr && iLength >= iFixedHeader
		? STATUS_BUFFER_OVERFLOW : STATUS_BUFFER_TOO_SMALL;
}

static NTSTATUS WriteRegistryOverride(const RegInterceptInfo& tOverride,
	KEY_VALUE_INFORMATION_CLASS iInformationClass, PVOID pInformation,
	ULONG iLength, PULONG iResultLength)
{
	const bool bFull = iInformationClass == KeyValueFullInformation ||
		iInformationClass == KeyValueFullInformationAlign64;
	const bool bPartial = iInformationClass == KeyValuePartialInformation ||
		iInformationClass == KeyValuePartialInformationAlign64;
	if (!bFull && !bPartial && iInformationClass != KeyValueBasicInformation) return STATUS_NOT_SUPPORTED;
	if (pInformation != nullptr)
	{
		const UINT_PTR iRequiredAlignment =
			(iInformationClass == KeyValueFullInformationAlign64 ||
			 iInformationClass == KeyValuePartialInformationAlign64) ? 8 : 4;
		if ((reinterpret_cast<UINT_PTR>(pInformation) &
			(iRequiredAlignment - 1)) != 0)
			return STATUS_DATATYPE_MISALIGNMENT;
	}

	// copy as much of a field as fits; the status reports any truncation
	const auto CopyField = [&](ULONG iOffset, const void* pSource, ULONG iSize)
	{
		if (iLength > iOffset && iSize != 0)
			memcpy(static_cast<PBYTE>(pInformation) + iOffset, pSource, (std::min)(iLength - iOffset, iSize));
	};

	if (iInformationClass == KeyValueBasicInformation)
	{
		const ULONG iNameOffset = static_cast<ULONG>(offsetof(KEY_VALUE_BASIC_INFORMATION, Name));
		const ULONG iRequired = iNameOffset + tOverride.RegValueName.Length;
		*iResultLength = iRequired;
		const NTSTATUS iStatus = RegistryBufferStatus(pInformation, iLength, iNameOffset, iRequired);
		if (iStatus == STATUS_BUFFER_TOO_SMALL) return iStatus;

		const PKEY_VALUE_BASIC_INFORMATION tKeyInfo = static_cast<PKEY_VALUE_BASIC_INFORMATION>(pInformation);
		tKeyInfo->TitleIndex = 0;
		tKeyInfo->Type = tOverride.RegValueType;
		tKeyInfo->NameLength = tOverride.RegValueName.Length;
		CopyField(iNameOffset, tOverride.RegValueName.Buffer, tOverride.RegValueName.Length);
		return iStatus;
	}

	if (iInformationClass == KeyValueFullInformation ||
		iInformationClass == KeyValueFullInformationAlign64)
	{
		constexpr ULONG iDataAlignment = 8;
		const ULONG iNameOffset = static_cast<ULONG>(offsetof(KEY_VALUE_FULL_INFORMATION, Name));
		const ULONG iNameEnd = iNameOffset + tOverride.RegValueName.Length;
		const ULONG iDataOffset = (iNameEnd + iDataAlignment - 1) & ~(iDataAlignment - 1);
		const ULONG iRequired = iDataOffset + tOverride.RegValueDataSize;
		*iResultLength = iRequired;

		const NTSTATUS iStatus = RegistryBufferStatus(pInformation, iLength,
			iNameOffset, iRequired);
		if (iStatus == STATUS_BUFFER_TOO_SMALL) return iStatus;

		const PKEY_VALUE_FULL_INFORMATION tKeyInfo =
			static_cast<PKEY_VALUE_FULL_INFORMATION>(pInformation);
		tKeyInfo->TitleIndex = 0;
		tKeyInfo->Type = tOverride.RegValueType;
		tKeyInfo->DataOffset = iDataOffset;
		tKeyInfo->DataLength = tOverride.RegValueDataSize;
		tKeyInfo->NameLength = tOverride.RegValueName.Length;
		CopyField(iNameOffset, tOverride.RegValueName.Buffer, tOverride.RegValueName.Length);
		CopyField(iDataOffset, tOverride.RegValueData, tOverride.RegValueDataSize);
		return iStatus;
	}

	if (iInformationClass == KeyValuePartialInformation)
	{
		const ULONG iDataOffset = static_cast<ULONG>(offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data));
		const ULONG iRequired = iDataOffset + tOverride.RegValueDataSize;
		*iResultLength = iRequired;
		const NTSTATUS iStatus = RegistryBufferStatus(pInformation, iLength,
			iDataOffset, iRequired);
		if (iStatus == STATUS_BUFFER_TOO_SMALL) return iStatus;

		const PKEY_VALUE_PARTIAL_INFORMATION tKeyInfo =
			static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(pInformation);
		tKeyInfo->TitleIndex = 0;
		tKeyInfo->Type = tOverride.RegValueType;
		tKeyInfo->DataLength = tOverride.RegValueDataSize;
		CopyField(iDataOffset, tOverride.RegValueData, tOverride.RegValueDataSize);
		return iStatus;
	}

	if (iInformationClass == KeyValuePartialInformationAlign64)
	{
		// KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 deliberately omits TitleIndex.
		// Its payload begins at offset 8 on every supported architecture.
		constexpr ULONG iTypeOffset = 0;
		constexpr ULONG iDataLengthOffset = sizeof(ULONG);
		constexpr ULONG iDataOffset = sizeof(ULONG) * 2;
		const ULONG iRequired = iDataOffset + tOverride.RegValueDataSize;
		*iResultLength = iRequired;
		const NTSTATUS iStatus = RegistryBufferStatus(pInformation, iLength,
			iDataOffset, iRequired);
		if (iStatus == STATUS_BUFFER_TOO_SMALL) return iStatus;

		const PBYTE pBytes = static_cast<PBYTE>(pInformation);
		*reinterpret_cast<PULONG>(pBytes + iTypeOffset) = tOverride.RegValueType;
		*reinterpret_cast<PULONG>(pBytes + iDataLengthOffset) = tOverride.RegValueDataSize;
		CopyField(iDataOffset, tOverride.RegValueData, tOverride.RegValueDataSize);
		return iStatus;
	}

	return STATUS_NOT_SUPPORTED;
}

static NTSTATUS(WINAPI* TrueNtQueryValueKey)(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName, _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
											 _Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length, _Out_ PULONG ResultLength) = (decltype(TrueNtQueryValueKey))
	GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryValueKey");

static std::vector<RegInterceptInfo*> vRegInterceptList;
static bool bRegInterceptBlocks = false;

static void InitializeRegistryOverrides()
{
	// parse the parameters to create the intercept list
	int iParams = 0;
	SmartPointer<LPWSTR*> sParams(LocalFree, CommandLineToArgvW(_wgetenv(WINPRIV_EV_REG_OVERRIDE), &iParams));
	if (sParams == nullptr) return;
	for (int iParam = 0; iParam + 3 < iParams; iParam += 4)
	{
		// entries that cannot be fully decoded are released and skipped
		std::unique_ptr<RegInterceptInfo, decltype(&FreeRegInterceptInfo)> tInterceptInfo(
			static_cast<RegInterceptInfo*>(calloc(1, sizeof(RegInterceptInfo))), &FreeRegInterceptInfo);
		if (tInterceptInfo == nullptr) continue;

		// split the first argument into a root name and subkey name
		const std::wstring sKeyPath(sParams[iParam]);
		const size_t iSeparator = sKeyPath.find(L'\\');
		const std::wstring sRootKeyName = sKeyPath.substr(0, iSeparator);
		const std::wstring sSubKeyName = iSeparator == std::wstring::npos
			? L"" : sKeyPath.substr(iSeparator + 1);

		// match the aesthetic name to the builtin roots
		HKEY hRootKey = nullptr;
		if (_wcsicmp(sRootKeyName.c_str(), L"HKLM") == 0 || _wcsicmp(sRootKeyName.c_str(), L"HKEY_LOCAL_MACHINE") == 0)
			hRootKey = HKEY_LOCAL_MACHINE;
		else if (_wcsicmp(sRootKeyName.c_str(), L"HKCU") == 0 || _wcsicmp(sRootKeyName.c_str(), L"HKEY_CURRENT_USER") == 0)
			hRootKey = HKEY_CURRENT_USER;
		else if (_wcsicmp(sRootKeyName.c_str(), L"HKCR") == 0 || _wcsicmp(sRootKeyName.c_str(), L"HKEY_CLASSES_ROOT") == 0)
			hRootKey = HKEY_CLASSES_ROOT;
		else if (_wcsicmp(sRootKeyName.c_str(), L"HKU") == 0 || _wcsicmp(sRootKeyName.c_str(), L"HKEY_USERS") == 0)
			hRootKey = HKEY_USERS;
		else continue;

		// lookup the real key name after all redirection has been done
		SmartPointer<HKEY> hKey(RegCloseKey, nullptr);
		if (RegOpenKeyEx(hRootKey, sSubKeyName.empty() ? nullptr : sSubKeyName.c_str(),
			0, KEY_READ, &hKey) == ERROR_SUCCESS)
		{
			DWORD iSize = 0;
			const NTSTATUS iSizeStatus = NtQueryKey(hKey, KeyNameInformation, nullptr, 0, &iSize);
			if ((iSizeStatus == STATUS_BUFFER_TOO_SMALL || iSizeStatus == STATUS_BUFFER_OVERFLOW) &&
				iSize >= offsetof(KEY_NAME_INFORMATION, Name))
			{
				SmartPointer<PKEY_NAME_INFORMATION> pNameInfo(free,
					static_cast<PKEY_NAME_INFORMATION>(malloc(iSize)));
				if (pNameInfo != nullptr &&
					NtQueryKey(hKey, KeyNameInformation, pNameInfo, iSize, &iSize) == STATUS_SUCCESS &&
					pNameInfo->NameLength <=
						(std::numeric_limits<USHORT>::max)() - sizeof(WCHAR))
				{
					const size_t iNameBytes = pNameInfo->NameLength;
					const PWSTR sNameCopy = static_cast<PWSTR>(malloc(iNameBytes + sizeof(WCHAR)));
					if (sNameCopy != nullptr)
					{
						memcpy(sNameCopy, pNameInfo->Name, iNameBytes);
						sNameCopy[iNameBytes / sizeof(WCHAR)] = L'\0';
						tInterceptInfo->RegKeyName = { static_cast<USHORT>(iNameBytes),
							static_cast<USHORT>(iNameBytes + sizeof(WCHAR)), sNameCopy };
					}
				}
			}
		}
		if (tInterceptInfo->RegKeyName.Length == 0) continue;

		// fetch value name
		const LPWSTR sValueName = sParams[iParam + 1];
		const size_t iValueNameBytes = wcslen(sValueName) * sizeof(WCHAR);
		if (iValueNameBytes > (std::numeric_limits<USHORT>::max)() - sizeof(WCHAR)) continue;
		tInterceptInfo->RegValueName = { static_cast<USHORT>(iValueNameBytes),
			static_cast<USHORT>(iValueNameBytes + sizeof(WCHAR)), _wcsdup(sValueName) };
		if (tInterceptInfo->RegValueName.Buffer == nullptr) continue;

		// match the aesthetic types to the typed enumerations
		const LPWSTR sType = sParams[iParam + 2];
		DWORD& iType = tInterceptInfo->RegValueType;
		if (_wcsicmp(sType, L"REG_DWORD") == 0) iType = REG_DWORD;
		else if (_wcsicmp(sType, L"REG_QWORD") == 0) iType = REG_QWORD;
		else if (_wcsicmp(sType, L"REG_SZ") == 0) iType = REG_SZ;
		else if (_wcsicmp(sType, L"REG_BINARY") == 0) iType = REG_BINARY;
		else if (_wcsicmp(sType, L"REG_BLOCK") == 0) iType = REG_BLOCK;
		else continue;

		// decode the value string to a data blob
		const auto StoreData = [&](const void* pSource, size_t iSize)
		{
			tInterceptInfo->RegValueDataSize = static_cast<DWORD>(iSize);
			tInterceptInfo->RegValueData = iSize == 0 ? nullptr : malloc(iSize);
			if (tInterceptInfo->RegValueData != nullptr && pSource != nullptr)
				memcpy(tInterceptInfo->RegValueData, pSource, iSize);
			return iSize == 0 || tInterceptInfo->RegValueData != nullptr;
		};
		const LPWSTR sData = sParams[iParam + 3];
		const size_t iDataChars = wcslen(sData);
		DWORD iDword = 0;
		unsigned __int64 iQword = 0;
		if (iType == REG_DWORD && !(ParseRegistryInteger(sData, iDword) && StoreData(&iDword, sizeof(iDword)))) continue;
		if (iType == REG_QWORD && !(ParseRegistryInteger(sData, iQword) && StoreData(&iQword, sizeof(iQword)))) continue;
		if (iType == REG_SZ && !StoreData(sData, (iDataChars + 1) * sizeof(WCHAR))) continue;
		if (iType == REG_BINARY && (iDataChars % 2 != 0 || !StoreData(nullptr, iDataChars / 2) ||
			!DecodeHex(sData, static_cast<PBYTE>(tInterceptInfo->RegValueData)))) continue;

		// fully processed entry
		bRegInterceptBlocks |= iType == REG_BLOCK;
		vRegInterceptList.push_back(tInterceptInfo.get());
		(void)tInterceptInfo.release();
	}
}

static const RegInterceptInfo* FindRegistryIntercept(HANDLE KeyHandle, PUNICODE_STRING ValueName)
{
	// Only blocks and overrides for this value name require the key name.
	if (!bRegInterceptBlocks && std::ranges::none_of(vRegInterceptList, [&](const RegInterceptInfo* tInfo) {
		return UnicodeStringEquals(tInfo->RegValueName, ValueName); })) return nullptr;

	// Read the key name on the stack, using the heap only for unusually deep keys.
	alignas(KEY_NAME_INFORMATION) BYTE aNameBuffer[1024];
	PKEY_NAME_INFORMATION pNameInfo = reinterpret_cast<PKEY_NAME_INFORMATION>(aNameBuffer);
	ULONG iNameSize = 0;
	NTSTATUS iStatus = NtQueryKey(KeyHandle, KeyNameInformation, pNameInfo, sizeof(aNameBuffer), &iNameSize);
	SmartPointer<PKEY_NAME_INFORMATION> pLargeNameInfo(free, iStatus == STATUS_BUFFER_OVERFLOW ||
		iStatus == STATUS_BUFFER_TOO_SMALL ? static_cast<PKEY_NAME_INFORMATION>(malloc(iNameSize)) : nullptr);
	if (pLargeNameInfo != nullptr)
	{
		pNameInfo = pLargeNameInfo;
		iStatus = NtQueryKey(KeyHandle, KeyNameInformation, pNameInfo, iNameSize, &iNameSize);
	}
	if (iStatus != STATUS_SUCCESS || pNameInfo->NameLength > (std::numeric_limits<USHORT>::max)()) return nullptr;
	const UNICODE_STRING sKeyName = { static_cast<USHORT>(pNameInfo->NameLength),
		static_cast<USHORT>(pNameInfo->NameLength), pNameInfo->Name };

	// A block hides every value beneath its key; otherwise the last matching override wins.
	const RegInterceptInfo* tMatch = nullptr;
	for (const RegInterceptInfo* tInfo : vRegInterceptList)
	{
		if (tInfo->RegValueType == REG_BLOCK && RegistryKeyIsSameOrDescendant(tInfo->RegKeyName, sKeyName))
			return tInfo;
		if (UnicodeStringEquals(tInfo->RegKeyName, &sKeyName) && UnicodeStringEquals(tInfo->RegValueName, ValueName))
			tMatch = tInfo;
	}
	return tMatch;
}

EXTERN_C NTSTATUS WINAPI DetourNtQueryValueKey(_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName, _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length, _Out_ PULONG ResultLength)
{
	// sanity check
	if (ResultLength == nullptr)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// report blocked values as missing and return overrides in the requested layout
	const RegInterceptInfo* tInfo = FindRegistryIntercept(KeyHandle, ValueName);
	if (tInfo != nullptr && tInfo->RegValueType == REG_BLOCK)
	{
		*ResultLength = 0;
		return STATUS_OBJECT_NAME_NOT_FOUND;
	}
	const NTSTATUS iStatus = tInfo == nullptr ? STATUS_NOT_SUPPORTED :
		WriteRegistryOverride(*tInfo, KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	// return the real value if no match was found or the information class is not supported
	return iStatus != STATUS_NOT_SUPPORTED ? iStatus : TrueNtQueryValueKey(KeyHandle, ValueName,
		KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

static NTSTATUS(WINAPI* TrueNtEnumerateValueKey)(_In_ HANDLE KeyHandle, _In_ ULONG Index,
												 _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, _Out_opt_ PVOID KeyValueInformation,
												 _In_ ULONG Length, _Out_ PULONG ResultLength) = (decltype(TrueNtEnumerateValueKey))
	GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtEnumerateValueKey");

EXTERN_C NTSTATUS WINAPI DetourNtEnumerateValueKey(_In_ HANDLE KeyHandle, _In_ ULONG Index,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, _Out_opt_ PVOID KeyValueInformation,
	_In_ ULONG Length, _Out_ PULONG ResultLength)
{
	if (ResultLength == nullptr || KeyValueInformationClass < KeyValueBasicInformation ||
		KeyValueInformationClass >= MaxKeyValueInfoClass)
	{
		return TrueNtEnumerateValueKey(KeyHandle, Index,
			KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
	}

	// Read the value name on the stack, using the heap only for unusually long names.
	alignas(KEY_VALUE_BASIC_INFORMATION) BYTE aNameBuffer[512];
	PKEY_VALUE_BASIC_INFORMATION tKeyInfo = reinterpret_cast<PKEY_VALUE_BASIC_INFORMATION>(aNameBuffer);
	std::unique_ptr<void, decltype(&free)> pLargeKeyInfo(nullptr, free);
	ULONG iRequired = 0;
	NTSTATUS iStatus = TrueNtEnumerateValueKey(KeyHandle, Index,
		KeyValueBasicInformation, tKeyInfo, sizeof(aNameBuffer), &iRequired);
	while (iStatus == STATUS_BUFFER_TOO_SMALL || iStatus == STATUS_BUFFER_OVERFLOW)
	{
		pLargeKeyInfo.reset(malloc(iRequired));
		if (pLargeKeyInfo == nullptr) return STATUS_NO_MEMORY;
		tKeyInfo = static_cast<PKEY_VALUE_BASIC_INFORMATION>(pLargeKeyInfo.get());
		iStatus = TrueNtEnumerateValueKey(KeyHandle, Index,
			KeyValueBasicInformation, tKeyInfo, iRequired, &iRequired);
	}

	if (iStatus != STATUS_SUCCESS) return iStatus;

	UNICODE_STRING sValue = { static_cast<USHORT>(tKeyInfo->NameLength),
		static_cast<USHORT>(tKeyInfo->NameLength), tKeyInfo->Name };
	return DetourNtQueryValueKey(KeyHandle, &sValue,
		KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
}

//   __   __   __   __   ___  __   __      ___       ___
//  |__) |__) /  \ /  ` |__  /__` /__`    |__  \_/ |  |
//  |    |  \ \__/ \__, |___ .__/ .__/    |___ / \ |  |
//

VOID(NTAPI* TrueRtlExitUserProcess)(_In_ NTSTATUS 	ExitStatus) =
(decltype(TrueRtlExitUserProcess))GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlExitUserProcess");

VOID NTAPI DetourRtlExitUserProcess(_In_ NTSTATUS ExitStatus)
{
	if (GetConsoleWindow() != nullptr && VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		wprintf(L"\n\nWinPriv target process has finished execution. Press any key to exit this window.\n");
		(void)_getch();
	}

	TrueRtlExitUserProcess(ExitStatus);
}

//              __           __   __   __   ___  __   __
//   |\/|  /\  /  `     /\  |  \ |  \ |__) |__  /__` /__`
//   |  | /~~\ \__,    /~~\ |__/ |__/ |  \ |___ .__/ .__/
//

struct MacOverrideInfo
{
	std::array<BYTE, MAX_ADAPTER_ADDRESS_LENGTH> Address{};
	size_t Length = 0;
	std::wstring Text;
	bool Valid = false;
};

static const MacOverrideInfo& GetMacOverrideInfo()
{
	static const MacOverrideInfo tOverride = []
	{
		MacOverrideInfo tResult;
		const LPCWSTR sOverride = _wgetenv(WINPRIV_EV_MAC_OVERRIDE);
		if (sOverride == nullptr) return tResult;

		tResult.Text = sOverride;
		if (tResult.Text.empty() || (tResult.Text.length() % 2) != 0 ||
			tResult.Text.length() > tResult.Address.size() * 2)
			return tResult;

		tResult.Valid = DecodeHex(tResult.Text, tResult.Address.data());
		tResult.Length = tResult.Valid ? tResult.Text.length() / 2 : 0;
		return tResult;
	}();
	return tOverride;
}

static decltype(&NetWkstaTransportEnum) TrueNetWkstaTransportEnum = NetWkstaTransportEnum;

EXTERN_C NET_API_STATUS NET_API_FUNCTION DetourNetWkstaTransportEnum(
	_In_opt_ LPTSTR servername, _In_ DWORD level, LPBYTE* bufptr, _In_ DWORD prefmaxlen,
	_Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_opt_ LPDWORD resume_handle)
{
	NET_API_STATUS iRet = TrueNetWkstaTransportEnum(servername, level,
		bufptr, prefmaxlen, entriesread, totalentries, resume_handle);

	const MacOverrideInfo& tOverride = GetMacOverrideInfo();
	if (tOverride.Valid && level == 0 && bufptr != nullptr && *bufptr != nullptr &&
		entriesread != nullptr &&
		(iRet == NERR_Success || iRet == NERR_BufTooSmall || iRet == ERROR_MORE_DATA))
	{
		const PWKSTA_TRANSPORT_INFO_0 tInfo = (PWKSTA_TRANSPORT_INFO_0)*bufptr;
		for (DWORD iEntry = 0; iEntry < *entriesread; iEntry++)
		{
			LPWSTR sDestination = tInfo[iEntry].wkti0_transport_address;
			if (sDestination == nullptr) continue;
			const size_t iDestinationLength = wcslen(sDestination);
			if (tOverride.Text.length() <= iDestinationLength)
			{
				wcscpy_s(sDestination, iDestinationLength + 1, tOverride.Text.c_str());
			}
		}
	}

	return iRet;
}

static decltype(&GetAdaptersInfo) TrueGetAdaptersInfo = GetAdaptersInfo;

static ULONG WINAPI DetourGetAdaptersInfo(_Out_ PIP_ADAPTER_INFO AdapterInfo, _Inout_ PULONG SizePointer)
{
	const ULONG iRet = TrueGetAdaptersInfo(AdapterInfo, SizePointer);

	// return immediately upon error
	if (iRet != ERROR_SUCCESS) return iRet;

	const MacOverrideInfo& tOverride = GetMacOverrideInfo();
	if (!tOverride.Valid) return iRet;

	// enumerate each adapter and replace the MAC data
	for (PIP_ADAPTER_INFO pInfo = AdapterInfo; pInfo != nullptr; pInfo = pInfo->Next)
	{
		memcpy(pInfo->Address, tOverride.Address.data(), tOverride.Length);
		pInfo->AddressLength = static_cast<UINT>(tOverride.Length);
	}

	return iRet;
}

static decltype(&GetAdaptersAddresses) TrueGetAdaptersAddresses = GetAdaptersAddresses;

static ULONG WINAPI DetourGetAdaptersAddresses(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved,
											   _Out_ PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer)
{
	const ULONG iRet = TrueGetAdaptersAddresses(Family, Flags,
		Reserved, AdapterAddresses, SizePointer);

	// return immediately upon error
	if (iRet != ERROR_SUCCESS) return iRet;

	const MacOverrideInfo& tOverride = GetMacOverrideInfo();
	if (!tOverride.Valid) return iRet;

	// enumerate each adapter and replace the MAC data
	for (PIP_ADAPTER_ADDRESSES pInfo = AdapterAddresses; pInfo != nullptr; pInfo = pInfo->Next)
	{
		memcpy(pInfo->PhysicalAddress, tOverride.Address.data(), tOverride.Length);
		pInfo->PhysicalAddressLength = static_cast<ULONG>(tOverride.Length);
	}

	return iRet;
}

//              __        __     __        __        ___
//   /\   |\/| /__` |    |  \ | /__`  /\  |__) |    |__
//  /~~\  |  | .__/ |    |__/ | .__/ /~~\ |__) |___ |___
//

static decltype(&AmsiScanBuffer) TrueAmsiScanBuffer = AmsiScanBuffer;

static HRESULT WINAPI DetourAmsiScanBuffer(_In_  HAMSICONTEXT amsiContext, _In_reads_bytes_(length) PVOID buffer, _In_  ULONG length,
									_In_opt_  LPCWSTR contentName, _In_opt_  HAMSISESSION amsiSession, _Out_ AMSI_RESULT* result)
{
	if (result == nullptr) return E_INVALIDARG;
	*result = AMSI_RESULT_CLEAN;
	return S_OK;
}

static decltype(&AmsiScanString) TrueAmsiScanString = AmsiScanString;

static HRESULT WINAPI DetourAmsiScanString(_In_  HAMSICONTEXT amsiContext, _In_  LPCWSTR string, _In_opt_  LPCWSTR contentName,
									_In_opt_  HAMSISESSION amsiSession, _Out_ AMSI_RESULT* result)
{
	if (result == nullptr) return E_INVALIDARG;
	*result = AMSI_RESULT_CLEAN;
	return S_OK;
}

//   __        __   __
//  /  \ |    |  \ |__)
//  \__/ |___ |__/ |
//

static decltype(&WldpGetLockdownPolicy) TrueWldpGetLockdownPolicy = WldpGetLockdownPolicy;

static HRESULT WINAPI DetourWldpGetLockdownPolicy(
	_In_opt_ PWLDP_HOST_INFORMATION hostInformation,
	_Out_ PDWORD pdwLockdownState,
	_In_ DWORD dwFlags)
{
	if (hostInformation == nullptr || hostInformation->dwHostId != WLDP_HOST_ID_POWERSHELL)
		return TrueWldpGetLockdownPolicy(hostInformation, pdwLockdownState, dwFlags);
	if (pdwLockdownState == nullptr) return E_INVALIDARG;

	if (VariableIsSet(WINPRIV_EV_CLM, 1))
	{
		*pdwLockdownState = WLDP_LOCKDOWN_ENFORCE;
		return S_OK;
	}
	if (VariableIsSet(WINPRIV_EV_CLM, 0))
	{
		*pdwLockdownState = WLDP_LOCKDOWN_OFF;
		return S_OK;
	}
	return TrueWldpGetLockdownPolicy(hostInformation, pdwLockdownState, dwFlags);
}

static decltype(&WldpCanExecuteFile) TrueWldpCanExecuteFile = nullptr;

static HRESULT WINAPI DetourWldpCanExecuteFile(
	_In_ REFGUID host,
	_In_ WLDP_EXECUTION_EVALUATION_OPTIONS options,
	_In_ HANDLE fileHandle,
	_In_opt_ PCWSTR auditInfo,
	_Out_ WLDP_EXECUTION_POLICY* result)
{
	static constexpr GUID powershellHost{
		0x8e9aaa7c, 0x198b, 0x4879, { 0xae, 0x41, 0xa5, 0x0d, 0x47, 0xad, 0x64, 0x58 } };
	if (host != powershellHost) return TrueWldpCanExecuteFile(host, options, fileHandle, auditInfo, result);
	if (result == nullptr) return E_INVALIDARG;

	if (VariableIsSet(WINPRIV_EV_CLM, 1))
	{
		*result = WLDP_EXECUTION_POLICY_REQUIRE_SANDBOX;
		return S_OK;
	}
	if (VariableIsSet(WINPRIV_EV_CLM, 0))
	{
		*result = WLDP_EXECUTION_POLICY_ALLOWED;
		return S_OK;
	}
	return TrueWldpCanExecuteFile(host, options, fileHandle, auditInfo, result);
}

static decltype(&WldpIsClassInApprovedList) TrueWldpIsClassInApprovedList = WldpIsClassInApprovedList;

static HRESULT WINAPI DetourWldpIsClassInApprovedList(
	_In_ REFCLSID classID,
	_In_ PWLDP_HOST_INFORMATION hostInformation,
	_Out_ PBOOL isApproved,
	_In_ DWORD optionalFlags)
{
	if (hostInformation == nullptr || hostInformation->dwHostId != WLDP_HOST_ID_POWERSHELL)
		return TrueWldpIsClassInApprovedList(classID, hostInformation, isApproved, optionalFlags);
	if (isApproved == nullptr) return E_INVALIDARG;

	if (VariableIsSet(WINPRIV_EV_CLM, 1))
	{
		*isApproved = FALSE;
		return S_OK;
	}
	if (VariableIsSet(WINPRIV_EV_CLM, 0))
	{
		*isApproved = TRUE;
		return S_OK;
	}
	return TrueWldpIsClassInApprovedList(classID, hostInformation, isApproved, optionalFlags);
}

static decltype(&SaferIdentifyLevel) TrueSaferIdentifyLevel = SaferIdentifyLevel;

static BOOL WINAPI DetourSaferIdentifyLevel(
	_In_ DWORD dwNumProperties,
	_In_reads_opt_(dwNumProperties) PSAFER_CODE_PROPERTIES pCodeProperties,
	_Outptr_ SAFER_LEVEL_HANDLE* pLevelHandle,
	_In_opt_ LPVOID lpReserved)
{
	if (lpReserved == nullptr || wcscmp(static_cast<LPCWSTR>(lpReserved), SRP_POLICY_SCRIPT) != 0 ||
		!VariableIsSet(WINPRIV_EV_CLM, 0))
		return TrueSaferIdentifyLevel(dwNumProperties, pCodeProperties, pLevelHandle, lpReserved);

	if (pLevelHandle == nullptr)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	// Override script classification while leaving token creation and handle lifetime to Windows.
	return SaferCreateLevel(SAFER_SCOPEID_USER, SAFER_LEVELID_FULLYTRUSTED, SAFER_LEVEL_OPEN, pLevelHandle, nullptr);
}

//        __                           __   ___  __   __   __            ___  ___
//   /\  |  \  |\/| | |\ |    |  |\/| |__) |__  |__) /__` /  \ |\ |  /\   |  |__
//  /~~\ |__/  |  | | | \|    |  |  | |    |___ |  \ .__/ \__/ | \| /~~\  |  |___
//

static decltype(&IsUserAnAdmin) TrueIsUserAnAdmin = IsUserAnAdmin;

static BOOL __stdcall DetourIsUserAnAdmin()
{
	return TRUE;
}

static decltype(&CheckTokenMembership) TrueCheckTokenMembership = CheckTokenMembership;

static PSID GetLocalAdministratorsGroup()
{
	// fetch and allocate the local admin structure (once)
	static SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	static SmartPointer<PSID> LocalAdministratorsGroup(FreeSid, []() -> PSID {
		PSID pSid = nullptr;
		AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid);
		return pSid;
	}());

	return LocalAdministratorsGroup;
}

static BOOL APIENTRY DetourCheckTokenMembership(_In_opt_ HANDLE TokenHandle,
	_In_ PSID SidToCheck, _Out_ PBOOL IsMember)
{
	// get the real value of the function - return if failure
	const BOOL bRealResult = TrueCheckTokenMembership(TokenHandle, SidToCheck, IsMember);
	if (bRealResult == 0) return bRealResult;

	// check if the local admin group is being requested
	const PSID administrators = GetLocalAdministratorsGroup();
	if (administrators != nullptr && EqualSid(SidToCheck, administrators))
	{
		// unconditionally say this user is running as an admin
		*IsMember = TRUE;
	}

	return bRealResult;
}

//   __   ___  __        ___  __      ___  __    ___    __
//  /__` |__  |__) \  / |__  |__)    |__  |  \ |  |  | /  \ |\ |
//  .__/ |___ |  \  \/  |___ |  \    |___ |__/ |  |  | \__/ | \|
//

static decltype(&GetVersionExW) TrueGetVersionExW = GetVersionExW;

static BOOL WINAPI DetourGetVersionExW(_Inout_ LPOSVERSIONINFOW lpVersionInformation)
{
	const BOOL bResult = TrueGetVersionExW(lpVersionInformation);
	if (bResult == 0) return bResult;

	if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXW))
	{
		const LPOSVERSIONINFOEXW pVersionInfo = (LPOSVERSIONINFOEXW)lpVersionInformation;
		pVersionInfo->wProductType = VER_NT_SERVER;
	}

	return bResult;
}

static decltype(&GetVersionExA) TrueGetVersionExA = GetVersionExA;

static BOOL WINAPI DetourGetVersionExA(_Inout_ LPOSVERSIONINFOA lpVersionInformation)
{
	const BOOL bResult = TrueGetVersionExA(lpVersionInformation);
	if (bResult == 0) return bResult;

	if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXA))
	{
		const LPOSVERSIONINFOEXA pVersionInfo = (LPOSVERSIONINFOEXA)lpVersionInformation;
		pVersionInfo->wProductType = VER_NT_SERVER;
	}

	return bResult;
}

static decltype(&VerifyVersionInfoW) TrueVerifyVersionInfoW = VerifyVersionInfoW;

static BOOL WINAPI DetourVerifyVersionInfoW(_Inout_ LPOSVERSIONINFOEXW lpVersionInformation, _In_ DWORD dwTypeMask, _In_ DWORDLONG dwlConditionMask)
{
	if ((dwTypeMask & VER_PRODUCT_TYPE) != 0 && lpVersionInformation != nullptr)
	{
		// quit early if actually running on a server
		OSVERSIONINFOEXW tInfo = {};
		tInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		if (!TrueGetVersionExW((LPOSVERSIONINFOW)&tInfo) ||
			tInfo.wProductType != VER_NT_WORKSTATION)
		{
			return TrueVerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask);
		}

		// VerifyVersionInfo treats the structure as input. Use a private copy to
		// translate product-type comparisons to the real workstation value while
		// leaving every caller-owned field unchanged. Other requested fields and
		// their condition-mask entries remain intact for combined comparisons.
		OSVERSIONINFOEXW tRequested = *lpVersionInformation;
		if (tRequested.wProductType == VER_NT_SERVER)
		{
			tRequested.wProductType = VER_NT_WORKSTATION;
		}
		else if (tRequested.wProductType == VER_NT_WORKSTATION)
		{
			tRequested.wProductType = VER_NT_SERVER;
		}
		return TrueVerifyVersionInfoW(&tRequested, dwTypeMask, dwlConditionMask);
	}

	return TrueVerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask);
}

//   __   __       __  ___  __      __   ___       __
//  /  ` |__) \ / |__)  |  /  \    |__) |__   /\  |  \
//  \__, |  \  |  |     |  \__/    |  \ |___ /~~\ |__/
//

static std::wstring IntToString(int iValue, size_t iPadding = 5)
{
	const std::wstring sValue = std::to_wstring(iValue);
	if (sValue.length() >= iPadding) return sValue;
	return std::wstring(iPadding - sValue.length(), '0') + sValue;
}

static void RecordCryptoData(LPCWSTR sFunction, PUCHAR pData, DWORD iDataLen) noexcept
{
	// Several crypto APIs support size-query calls with a null data buffer.
	// Those calls contain no plaintext to record and must remain side-effect free.
	if (sFunction == nullptr || pData == nullptr || iDataLen == 0) return;

	// Recording must not change the crypto operation's error state or leak allocation failures to its caller.
	const DWORD iLastError = GetLastError();
	try
	{
		SmartPointer<const DWORD*> tErrorCleanup([](const DWORD* pError) { SetLastError(*pError); }, &iLastError);

		// remove 'Detour' from the function name
		sFunction = &sFunction[wcslen(L"Detour")];

		// decide whether to output to console or file system
		const LPWSTR sCryptoValue = _wgetenv(WINPRIV_EV_RECORD_CRYPTO);
		if (sCryptoValue == nullptr || *sCryptoValue == L'\0') return;
		if (_wcsicmp(sCryptoValue, L"SHOW") == 0)
		{
			if (IsTextUnicode(pData, iDataLen, nullptr))
			{
				PrintMessage(L"Function: %s\nGuessed Encoding: %s\nLength In Bytes: %d\nData:%.*s\n",
					sFunction, L"Unicode", iDataLen, (int)(iDataLen / sizeof(WCHAR)), (LPWSTR)pData);
			}
			else
			{
				PrintMessage(L"Function: %s\nGuessed Encoding: %s\nLength In Bytes: %d\nData:%.*S\n",
					sFunction, L"Multibyte", iDataLen, (int)iDataLen, pData);
			}
		}
		else
		{
			// formulate the file name to write to
			static std::atomic<int> iOrder = 0;
			const std::wstring sFilePath = std::wstring(sCryptoValue) + L"\\" + IntToString(iOrder++) + L"-PID"
				+ IntToString(GetCurrentProcessId()) + L"-TID" + IntToString(GetCurrentThreadId())
				+ L"-" + sFunction + L".bin";

			// create the crypto data file
			DWORD iSizeWritten = 0;
			SmartPointer<HANDLE> hFile(CloseHandle, CreateFile(sFilePath.c_str(), GENERIC_ALL,
				FILE_SHARE_WRITE, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
			if (hFile == INVALID_HANDLE_VALUE ||
				WriteFile(hFile, pData, iDataLen, &iSizeWritten, nullptr) == 0 ||
				iDataLen != iSizeWritten)
			{
				PrintMessage(L"ERROR: Problem committing data to crypto data file.\n");
			}
		}
	}
	catch (...)
	{
		SetLastError(iLastError);
	}
}

static decltype(&BCryptEncrypt) TrueBCryptEncrypt = BCryptEncrypt;

static NTSTATUS WINAPI DetourBCryptEncrypt(_Inout_ BCRYPT_KEY_HANDLE hKey, _In_reads_bytes_opt_(cbInput) PUCHAR pbInput, _In_ ULONG cbInput, _In_opt_ VOID* pPaddingInfo, _Inout_updates_bytes_opt_(cbIV) PUCHAR pbIV, _In_ ULONG cbIV, _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput, _In_ ULONG cbOutput, _Out_ ULONG* pcbResult, _In_ ULONG dwFlags)
{
	RecordCryptoData(__FUNCTIONW__, pbInput, cbInput);
	return TrueBCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

static decltype(&BCryptDecrypt) TrueBCryptDecrypt = BCryptDecrypt;

static NTSTATUS WINAPI DetourBCryptDecrypt(_Inout_ BCRYPT_KEY_HANDLE hKey, _In_reads_bytes_opt_(cbInput) PUCHAR pbInput, _In_ ULONG cbInput, _In_opt_ VOID* pPaddingInfo, _Inout_updates_bytes_opt_(cbIV) PUCHAR pbIV, _In_ ULONG cbIV, _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput, _In_ ULONG cbOutput, _Out_ ULONG* pcbResult, _In_ ULONG dwFlags)
{
	const NTSTATUS iResult = TrueBCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
	if (iResult == STATUS_SUCCESS && pbOutput != nullptr && pcbResult != nullptr &&
		*pcbResult <= cbOutput)
	{
		RecordCryptoData(__FUNCTIONW__, pbOutput, *pcbResult);
	}
	return iResult;
}

static decltype(&CryptEncrypt) TrueCryptEncrypt = CryptEncrypt;

static BOOL WINAPI DetourCryptEncrypt(_In_ HCRYPTKEY hKey, _In_ HCRYPTHASH  hHash, _In_ BOOL Final, _In_ DWORD dwFlags, _Inout_updates_bytes_to_opt_(dwBufLen, *pdwDataLen) BYTE* pbData, _Inout_ DWORD* pdwDataLen, _In_ DWORD dwBufLen)
{
	// Preserve a bounded plaintext snapshot until the API confirms that the
	// encryption operation succeeded. Invalid length pairs are passed through
	// without letting the recorder read outside the caller's buffer.
	std::vector<BYTE> vPlaintext;
	if (pbData != nullptr && pdwDataLen != nullptr && *pdwDataLen <= dwBufLen)
	{
		try
		{
			vPlaintext.assign(pbData, pbData + *pdwDataLen);
		}
		catch (...)
		{
			vPlaintext.clear();
		}
	}
	const BOOL iResult = TrueCryptEncrypt(hKey, hHash, Final, dwFlags,
		pbData, pdwDataLen, dwBufLen);
	if (iResult == TRUE && !vPlaintext.empty())
		RecordCryptoData(__FUNCTIONW__, vPlaintext.data(),
			static_cast<DWORD>(vPlaintext.size()));
	return iResult;
}

static decltype(&CryptDecrypt) TrueCryptDecrypt = CryptDecrypt;

static BOOL WINAPI DetourCryptDecrypt(_In_ HCRYPTKEY hKey, _In_ HCRYPTHASH hHash, _In_ BOOL Final, _In_ DWORD dwFlags, _Inout_updates_bytes_to_(*pdwDataLen, *pdwDataLen) BYTE* pbData, _Inout_ DWORD* pdwDataLen)
{
	const BOOL iResult = TrueCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
	if (iResult == TRUE && pdwDataLen != nullptr)
		RecordCryptoData(__FUNCTIONW__, pbData, *pdwDataLen);
	return iResult;
}

static decltype(&RtlEncryptMemory) TrueRtlEncryptMemory = RtlEncryptMemory;

static NTSTATUS __stdcall DetourRtlEncryptMemory(_Inout_updates_bytes_(MemorySize) PVOID Memory, _In_ ULONG MemorySize, _In_ ULONG OptionFlag)
{
	RecordCryptoData(__FUNCTIONW__, static_cast<PUCHAR>(Memory), MemorySize);
	return TrueRtlEncryptMemory(Memory, MemorySize, OptionFlag);
}

static decltype(&RtlDecryptMemory) TrueRtlDecryptMemory = RtlDecryptMemory;

static NTSTATUS __stdcall DetourRtlDecryptMemory(_Inout_updates_bytes_(MemorySize) PVOID Memory, _In_ ULONG MemorySize, _In_ ULONG OptionFlags)
{
	const NTSTATUS iResult = TrueRtlDecryptMemory(Memory, MemorySize, OptionFlags);
	if (iResult == STATUS_SUCCESS) RecordCryptoData(__FUNCTIONW__, static_cast<PUCHAR>(Memory), MemorySize);
	return iResult;
}

//   __   __           __   __             ___  __  ___
//  /__` /  \ |       /  ` /  \ |\ | |\ | |__  /  `  |
//  .__/ \__X |___    \__, \__/ | \| | \| |___ \__,  |
//

static bool TryRegexReplace(const std::wstring& sInput, LPCWSTR sSearch,
	LPCWSTR sReplace, std::wstring& sResult) noexcept
{
	if (sSearch == nullptr || sReplace == nullptr) return false;
	try
	{
		sResult = std::regex_replace(sInput, std::wregex(sSearch), sReplace);
		return true;
	}
	catch (...)
	{
		// Invalid patterns and allocation failures must not cross an ODBC or COM ABI boundary.
		return false;
	}
}

static LPCWSTR GetSqlConnectReplacement() noexcept
{
	const LPCWSTR sReplacement = _wgetenv(WINPRIV_EV_SQL_CONNECT_REPLACE);
	return sReplacement == nullptr ? L"" : sReplacement;
}

static decltype(&SQLDriverConnectW) TrueSQLDriverConnectW = SQLDriverConnectW;

static SQLRETURN SQL_API DetourSQLDriverConnectW(SQLHDBC hdbc, SQLHWND hwnd, _In_reads_(cchConnStrIn) SQLWCHAR* szConnStrIn,
												 SQLSMALLINT cchConnStrIn, _Out_writes_opt_(cchConnStrOutMax) SQLWCHAR* szConnStrOut, SQLSMALLINT cchConnStrOutMax,
												 _Out_opt_ SQLSMALLINT* pcchConnStrOut, SQLUSMALLINT fDriverCompletion)
{
	LPWSTR szAllocatedConnStr = nullptr;
	const SQLWCHAR* const szOriginalConnStr = szConnStrIn;
	const SQLSMALLINT cchOriginalConnStr = cchConnStrIn;
	const bool bInspectableInput = szConnStrIn != nullptr &&
		(cchConnStrIn == SQL_NTS || cchConnStrIn >= 0);
	try
	{
		if (bInspectableInput)
		{
			const size_t iConnectionLength = cchConnStrIn == SQL_NTS
				? wcslen(szConnStrIn) : static_cast<size_t>(cchConnStrIn);
			const std::wstring sPassedConnection(szConnStrIn, iConnectionLength);

			// handle search and replace
			if (VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
			{
				std::wstring sModifiedConnection;
				if (TryRegexReplace(sPassedConnection,
					_wgetenv(WINPRIV_EV_SQL_CONNECT_SEARCH),
					GetSqlConnectReplacement(),
					sModifiedConnection))
				{
					szAllocatedConnStr = _wcsdup(sModifiedConnection.c_str());
					if (szAllocatedConnStr != nullptr)
					{
						szConnStrIn = szAllocatedConnStr;
						cchConnStrIn = SQL_NTS;
					}
				}
			}

			// handle show after any successful replacement
			if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1))
			{
				const size_t iShownLength = cchConnStrIn == SQL_NTS
					? wcslen(szConnStrIn) : static_cast<size_t>(cchConnStrIn);
				const std::wstring sShownConnection(szConnStrIn, iShownLength);
				PrintMessage(L"SQL Connection String: %s\n", sShownConnection.c_str());
			}
		}
	}
	catch (...)
	{
		free(szAllocatedConnStr);
		szAllocatedConnStr = nullptr;
		szConnStrIn = const_cast<SQLWCHAR*>(szOriginalConnStr);
		cchConnStrIn = cchOriginalConnStr;
	}

	const SQLRETURN iResult = TrueSQLDriverConnectW(hdbc, hwnd, szConnStrIn, cchConnStrIn, szConnStrOut,
		cchConnStrOutMax, pcchConnStrOut, fDriverCompletion);
	free(szAllocatedConnStr);
	return iResult;
}

//   __   __            __   ___ ___  __        __   __
//  /  ` /  \  |\/|    |  \ |__   |  /  \ |  | |__) /__`
//  \__, \__/  |  |    |__/ |___  |  \__/ \__/ |  \ .__/
//

static std::atomic<bool> bComDetoursNeedToBeInitialized = true;
static DWORD iComInitializationSlot = TLS_OUT_OF_INDEXES;
static DWORD iAdoRewriteSlot = TLS_OUT_OF_INDEXES;
static SRWLOCK tComDetourInitializationLock = SRWLOCK_INIT;

using AdoConnectionOpen = HRESULT(STDMETHODCALLTYPE*)(IUnknown*, BSTR, BSTR, BSTR, LONG);
static AdoConnectionOpen TrueAdoConnectionOpen = nullptr;
static PVOID pAdoConnectionOpenTarget = nullptr;
static HMODULE hAdoConnectionOpenModule = nullptr;
static bool bAdoDispatchAttached = false;

// Connection15 inherits IDispatch (slots 0-6), then _ADO::Properties (7), connection members (8-14),
// Close/Execute/transaction methods (15-19), and Open at slot 20.
constexpr size_t iConnectionOpenVtableIndex = 20;

#if !defined(_M_IX86)
using AdoDispatchInvoke = HRESULT(STDMETHODCALLTYPE*)(IDispatch*, DISPID,
	REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
static AdoDispatchInvoke TrueAdoDispatchInvoke = nullptr;
static PVOID pAdoDispatchInvokeTarget = nullptr;
static HMODULE hAdoDispatchModule = nullptr;
static DISPID iAdoOpenDispatchId = DISPID_UNKNOWN;
static DISPID iAdoConnectionStringDispatchId = DISPID_UNKNOWN;
#endif

static bool InitializeHookThreadState()
{
	// Dynamic slots support threads created after the in-memory library is initialized.
	iComInitializationSlot = TlsAlloc();
	iAdoRewriteSlot = TlsAlloc();
	if (iComInitializationSlot != TLS_OUT_OF_INDEXES && iAdoRewriteSlot != TLS_OUT_OF_INDEXES) return true;
	if (iComInitializationSlot != TLS_OUT_OF_INDEXES) TlsFree(iComInitializationSlot);
	if (iAdoRewriteSlot != TLS_OUT_OF_INDEXES) TlsFree(iAdoRewriteSlot);
	return false;
}

static ULONG_PTR GetHookThreadValue(DWORD slot)
{
	const DWORD error = GetLastError();
	const auto value = reinterpret_cast<ULONG_PTR>(TlsGetValue(slot));
	SetLastError(error);
	return value;
}

class ComDetourInitializationScope final
{
public:
	explicit ComDetourInitializationScope(SRWLOCK* pLock) noexcept : pLock_(pLock)
	{
		TlsSetValue(iComInitializationSlot, reinterpret_cast<PVOID>(1));
	}

	~ComDetourInitializationScope() noexcept
	{
		ReleaseSRWLockExclusive(pLock_);
		TlsSetValue(iComInitializationSlot, nullptr);
	}

	ComDetourInitializationScope(const ComDetourInitializationScope&) = delete;
	ComDetourInitializationScope& operator=(const ComDetourInitializationScope&) = delete;

private:
	SRWLOCK* pLock_;
};

class AdoRewriteScope final
{
public:
	AdoRewriteScope()
	{
		TlsSetValue(iAdoRewriteSlot, reinterpret_cast<PVOID>(GetHookThreadValue(iAdoRewriteSlot) + 1));
	}
	~AdoRewriteScope()
	{
		TlsSetValue(iAdoRewriteSlot, reinterpret_cast<PVOID>(GetHookThreadValue(iAdoRewriteSlot) - 1));
	}
	AdoRewriteScope(const AdoRewriteScope&) = delete;
	AdoRewriteScope& operator=(const AdoRewriteScope&) = delete;
};

static constexpr IID IID_WinPrivConnection15 =
	{ 0x00000515, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };
static constexpr CLSID CLSID_WinPrivAdoConnection =
	{ 0x00000514, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };

static BSTR GetStoredAdoConnectionString(IUnknown* pConnection)
{
	using AdoGetConnectionString = HRESULT(STDMETHODCALLTYPE*)(IUnknown*, BSTR*);
	PVOID* pVtable = *reinterpret_cast<PVOID**>(pConnection);
	const auto pGetConnectionString = reinterpret_cast<AdoGetConnectionString>(pVtable[8]);
	BSTR sStoredString = nullptr;
	if (SUCCEEDED(pGetConnectionString(pConnection, &sStoredString))) return sStoredString;
	SysFreeString(sStoredString);
	return nullptr;
}

static BSTR PrepareAdoConnectionString(BSTR sPassedString) noexcept
{
	if (sPassedString == nullptr) return nullptr;
	BSTR sReplacement = nullptr;
	try
	{
		const std::wstring sPassed(sPassedString, SysStringLen(sPassedString));
		std::wstring sRevised = sPassed;
		if (VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
		{
			std::wstring sCandidate;
			if (TryRegexReplace(sPassed, _wgetenv(WINPRIV_EV_SQL_CONNECT_SEARCH),
				GetSqlConnectReplacement(), sCandidate))
			{
				sReplacement = SysAllocStringLen(sCandidate.data(),
					static_cast<UINT>(sCandidate.length()));
				if (sReplacement != nullptr) sRevised = std::move(sCandidate);
			}
		}
		if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1))
		{
			PrintMessage(L"SQL Connection String: %s\n", sRevised.c_str());
		}
	}
	catch (...)
	{
		if (sReplacement != nullptr) SysFreeString(sReplacement);
		return nullptr;
	}
	return sReplacement;
}

static HRESULT STDMETHODCALLTYPE DetourAdoConnectionOpen(IUnknown* pConnection,
	BSTR sConnectionString, BSTR sUserId, BSTR sPassword, LONG iOptions)
{
	if (TrueAdoConnectionOpen == nullptr) return E_UNEXPECTED;
	if (GetHookThreadValue(iAdoRewriteSlot) != 0)
	{
		return TrueAdoConnectionOpen(pConnection, sConnectionString, sUserId,
			sPassword, iOptions);
	}

	AdoRewriteScope tScope;
	BSTR sStoredString = SysStringLen(sConnectionString) == 0
		? GetStoredAdoConnectionString(pConnection) : nullptr;
	BSTR sReplacement = PrepareAdoConnectionString(sStoredString == nullptr ? sConnectionString : sStoredString);
	SysFreeString(sStoredString);
	const HRESULT iResult = TrueAdoConnectionOpen(pConnection,
		sReplacement == nullptr ? sConnectionString : sReplacement,
		sUserId, sPassword, iOptions);
	if (sReplacement != nullptr) SysFreeString(sReplacement);
	return iResult;
}

#if !defined(_M_IX86)
static BSTR GetVariantString(VARIANTARG* pArgument)
{
	if (pArgument == nullptr) return nullptr;
	if (V_VT(pArgument) == VT_BSTR) return V_BSTR(pArgument);
	if (V_VT(pArgument) == (VT_BSTR | VT_BYREF) && V_BSTRREF(pArgument) != nullptr)
		return *V_BSTRREF(pArgument);
	if (V_VT(pArgument) == (VT_VARIANT | VT_BYREF))
		return GetVariantString(V_VARIANTREF(pArgument));
	return nullptr;
}

static HRESULT STDMETHODCALLTYPE DetourAdoDispatchInvoke(IDispatch* pDispatch,
	DISPID iMember, REFIID iInterface, LCID iLocale, WORD iFlags,
	DISPPARAMS* pParameters, VARIANT* pResult, EXCEPINFO* pException,
	UINT* pArgumentError)
{
	if (TrueAdoDispatchInvoke == nullptr) return E_UNEXPECTED;
	if (iMember != iAdoOpenDispatchId ||
		(iFlags & DISPATCH_METHOD) == 0 || pParameters == nullptr ||
		(pParameters->cArgs != 0 && pParameters->rgvarg == nullptr) ||
		pParameters->cNamedArgs > pParameters->cArgs ||
		(pParameters->cNamedArgs != 0 && pParameters->rgdispidNamedArgs == nullptr))
	{
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}
	if (GetHookThreadValue(iAdoRewriteSlot) != 0)
	{
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}
	AdoRewriteScope tScope;

	// The implementation can share an Invoke entry point with other ADO
	// automation objects. Only rewrite objects that expose Connection15.
	IUnknown* pConnection = nullptr;
	if (FAILED(pDispatch->QueryInterface(IID_WinPrivConnection15,
		reinterpret_cast<void**>(&pConnection))))
	{
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}
	// Named arguments occupy the leading VARIANTARG slots. Prefer the parameter
	// DISPID returned by GetIDsOfNames; otherwise use Automation's reverse-order
	// positional layout, where Open's first argument is the final slot.
	VARIANTARG* pConnectionString = nullptr;
	if (pParameters->rgdispidNamedArgs != nullptr)
	{
		const UINT iNamedCount = pParameters->cNamedArgs < pParameters->cArgs
			? pParameters->cNamedArgs : pParameters->cArgs;
		for (UINT iArgument = 0; iArgument < iNamedCount; iArgument++)
		{
			if (pParameters->rgdispidNamedArgs[iArgument] ==
				iAdoConnectionStringDispatchId)
			{
				pConnectionString = &pParameters->rgvarg[iArgument];
				break;
			}
		}
	}
	if (pConnectionString == nullptr && pParameters->cArgs > pParameters->cNamedArgs)
		pConnectionString = &pParameters->rgvarg[pParameters->cArgs - 1];
	const BSTR sPassedString = GetVariantString(pConnectionString);
	const bool bOmitted = pConnectionString == nullptr ||
		(V_VT(pConnectionString) == VT_ERROR && V_ERROR(pConnectionString) == DISP_E_PARAMNOTFOUND);
	if ((sPassedString == nullptr && !bOmitted && V_VT(pConnectionString) != VT_BSTR) ||
		(pConnectionString == nullptr && pParameters->cNamedArgs != 0 &&
			iAdoConnectionStringDispatchId == DISPID_UNKNOWN))
	{
		pConnection->Release();
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}

	BSTR sStoredString = SysStringLen(sPassedString) == 0 ? GetStoredAdoConnectionString(pConnection) : nullptr;
	pConnection->Release();
	BSTR sReplacement = PrepareAdoConnectionString(sStoredString == nullptr ? sPassedString : sStoredString);
	SysFreeString(sStoredString);
	if (sReplacement == nullptr)
	{
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}

	DISPPARAMS tParameters = *pParameters;
	DISPPARAMS* pPassedParameters = pParameters;
	std::vector<VARIANTARG> vArguments;
	std::vector<DISPID> vNamedArguments;
	try
	{
		if (pParameters->cArgs != 0)
			vArguments.assign(pParameters->rgvarg, pParameters->rgvarg + pParameters->cArgs);
		VARIANTARG tArgument{};
		V_VT(&tArgument) = VT_BSTR;
		V_BSTR(&tArgument) = sReplacement;
		if (pConnectionString != nullptr)
		{
			vArguments[pConnectionString - pParameters->rgvarg] = tArgument;
		}
		else
		{
			vArguments.insert(vArguments.begin(), tArgument);
			tParameters.cArgs++;
			if (pParameters->cNamedArgs != 0)
			{
				vNamedArguments.push_back(iAdoConnectionStringDispatchId);
				vNamedArguments.insert(vNamedArguments.end(), pParameters->rgdispidNamedArgs,
					pParameters->rgdispidNamedArgs + pParameters->cNamedArgs);
				tParameters.rgdispidNamedArgs = vNamedArguments.data();
				tParameters.cNamedArgs++;
			}
		}
		tParameters.rgvarg = vArguments.data();
		pPassedParameters = &tParameters;
	}
	catch (...)
	{
		// Preserve the original call if formatting or allocation fails.
	}

	const HRESULT iResult = TrueAdoDispatchInvoke(pDispatch, iMember,
		iInterface, iLocale, iFlags, pPassedParameters, pResult, pException,
		pArgumentError);
	if ((iResult == DISP_E_TYPEMISMATCH || iResult == DISP_E_PARAMNOTFOUND) &&
		pPassedParameters == &tParameters && pConnectionString == nullptr &&
		pArgumentError != nullptr && *pArgumentError != 0)
		--*pArgumentError;
	SysFreeString(sReplacement);
	return iResult;
}

#if defined(_M_X64)
class AdoVtableWriteScope final
{
public:
	explicit AdoVtableWriteScope(PVOID* pSlot) noexcept : pSlot_(pSlot)
	{
		bWritable_ = VirtualProtect(pSlot_, sizeof(*pSlot_), PAGE_READWRITE, &iProtection_) != FALSE;
	}

	~AdoVtableWriteScope() noexcept
	{
		DWORD iIgnored = 0;
		if (bWritable_) VirtualProtect(pSlot_, sizeof(*pSlot_), iProtection_, &iIgnored);
	}

	explicit operator bool() const noexcept { return bWritable_; }
	AdoVtableWriteScope(const AdoVtableWriteScope&) = delete;
	AdoVtableWriteScope& operator=(const AdoVtableWriteScope&) = delete;

private:
	PVOID* pSlot_;
	DWORD iProtection_ = 0;
	bool bWritable_ = false;
};

static bool AttachAdoVtableDetours(PVOID* pInvokeSlot, PVOID* pOpenSlot) noexcept
{
	const AdoVtableWriteScope tInvokeWrite(pInvokeSlot);
	if (!tInvokeWrite) return false;
	const AdoVtableWriteScope tOpenWrite(pOpenSlot);
	if (!tOpenWrite) return false;

	const PVOID pInvokeDetour = reinterpret_cast<PVOID>(DetourAdoDispatchInvoke);
	const PVOID pOpenDetour = reinterpret_cast<PVOID>(DetourAdoConnectionOpen);
	if (InterlockedCompareExchangePointer(pInvokeSlot, pInvokeDetour,
		pAdoDispatchInvokeTarget) != pAdoDispatchInvokeTarget) return false;
	if (InterlockedCompareExchangePointer(pOpenSlot, pOpenDetour,
		pAdoConnectionOpenTarget) == pAdoConnectionOpenTarget) return true;

	InterlockedCompareExchangePointer(pInvokeSlot, pAdoDispatchInvokeTarget, pInvokeDetour);
	return false;
}
#endif

static void AttachAdoDispatchDetour()
{
	if (bAdoDispatchAttached) return;

	IDispatch* pDispatch = nullptr;
	IUnknown* pConnection = nullptr;
	const HRESULT iCreateResult = CoCreateInstance(CLSID_WinPrivAdoConnection,
		nullptr, CLSCTX_INPROC_SERVER, IID_IDispatch,
		reinterpret_cast<void**>(&pDispatch));
	if (SUCCEEDED(iCreateResult) && pDispatch != nullptr &&
		SUCCEEDED(pDispatch->QueryInterface(IID_WinPrivConnection15,
			reinterpret_cast<void**>(&pConnection))) && pConnection != nullptr)
	{
		LPOLESTR sNames[] = { const_cast<LPOLESTR>(L"Open"),
			const_cast<LPOLESTR>(L"ConnectionString") };
		DISPID iDispatchIds[] = { DISPID_UNKNOWN, DISPID_UNKNOWN };
		HRESULT iNameResult = pDispatch->GetIDsOfNames(IID_NULL, sNames,
			ARRAYSIZE(sNames), LOCALE_USER_DEFAULT, iDispatchIds);
		if (FAILED(iNameResult))
		{
			iDispatchIds[1] = DISPID_UNKNOWN;
			iNameResult = pDispatch->GetIDsOfNames(IID_NULL, sNames, 1,
				LOCALE_USER_DEFAULT, iDispatchIds);
		}
		if (SUCCEEDED(iNameResult))
		{
			PVOID* pVtable = *reinterpret_cast<PVOID**>(pDispatch);
			PVOID* pConnectionVtable = *reinterpret_cast<PVOID**>(pConnection);
			pAdoDispatchInvokeTarget = pVtable[6];
			TrueAdoDispatchInvoke =
				reinterpret_cast<AdoDispatchInvoke>(pAdoDispatchInvokeTarget);
			pAdoConnectionOpenTarget =
				pConnectionVtable[iConnectionOpenVtableIndex];
			TrueAdoConnectionOpen =
				reinterpret_cast<AdoConnectionOpen>(pAdoConnectionOpenTarget);
			iAdoOpenDispatchId = iDispatchIds[0];
			iAdoConnectionStringDispatchId = iDispatchIds[1];

			const bool bTargetPinned = GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
				reinterpret_cast<LPCWSTR>(pAdoDispatchInvokeTarget),
				&hAdoDispatchModule) != FALSE;
			const bool bOpenTargetPinned = GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
				reinterpret_cast<LPCWSTR>(pAdoConnectionOpenTarget),
				&hAdoConnectionOpenModule) != FALSE;
			const bool bTargetsReady = bTargetPinned && bOpenTargetPinned &&
				pAdoConnectionOpenTarget != pAdoDispatchInvokeTarget;
#if defined(_M_X64)
			USHORT iProcessMachine = IMAGE_FILE_MACHINE_UNKNOWN;
			USHORT iNativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
			if (IsWow64Process2(GetCurrentProcess(), &iProcessMachine, &iNativeMachine) &&
				iNativeMachine == IMAGE_FILE_MACHINE_ARM64)
			{
				// Emulated x64 COM vtables can point directly to ARM64EC instructions.
				// Slot replacement preserves the platform's cross-architecture call thunks.
				bAdoDispatchAttached = bTargetsReady && AttachAdoVtableDetours(
					&pVtable[6], &pConnectionVtable[iConnectionOpenVtableIndex]);
			}
			else
#endif
			{
				winpriv::detours::transaction tTransaction;
				if (bTargetsReady && tTransaction &&
					tTransaction.attach(
						TrueAdoDispatchInvoke, DetourAdoDispatchInvoke) == NO_ERROR &&
					tTransaction.attach(
						TrueAdoConnectionOpen, DetourAdoConnectionOpen) == NO_ERROR &&
					tTransaction.commit() == NO_ERROR)
				{
					bAdoDispatchAttached = true;
				}
			}
		}
	}
	if (pConnection != nullptr) pConnection->Release();
	if (pDispatch != nullptr) pDispatch->Release();
}
#else
static void AttachAdoOpenDetour()
{
	// x86 targets hook Connection15::Open directly.
	if (bAdoDispatchAttached) return;
	IUnknown* pConnection = nullptr;
	if (FAILED(CoCreateInstance(CLSID_WinPrivAdoConnection, nullptr, CLSCTX_INPROC_SERVER,
		IID_WinPrivConnection15, reinterpret_cast<void**>(&pConnection))) || pConnection == nullptr) return;
	pAdoConnectionOpenTarget = (*reinterpret_cast<PVOID**>(pConnection))[iConnectionOpenVtableIndex];
	TrueAdoConnectionOpen = reinterpret_cast<AdoConnectionOpen>(pAdoConnectionOpenTarget);
	winpriv::detours::transaction tTransaction;
	bAdoDispatchAttached = GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
		reinterpret_cast<LPCWSTR>(pAdoConnectionOpenTarget), &hAdoConnectionOpenModule) && tTransaction &&
		tTransaction.attach(TrueAdoConnectionOpen, DetourAdoConnectionOpen) == NO_ERROR &&
		tTransaction.commit() == NO_ERROR;
	pConnection->Release();
}
#endif

static void InitializeComDetoursForCurrentThread()
{
	if (GetHookThreadValue(iComInitializationSlot) != 0) return;
	if (!TryAcquireSRWLockExclusive(&tComDetourInitializationLock)) return;
	const ComDetourInitializationScope tInitializationScope(
		&tComDetourInitializationLock);
	try
	{
#if defined(_M_IX86)
		AttachAdoOpenDetour();
#else
		// x64 and ARM64 need both late-bound Invoke and direct Connection15::Open coverage;
		// the two hooks share a thread-local rewrite guard.
		AttachAdoDispatchDetour();
#endif
	}
	catch (...)
	{
		// COM hooks may be entered through ABI boundaries. Initialization is
		// opportunistic, so an unexpected C++ exception must not escape or leave
		// the process-wide initialization gate owned.
	}
}

static decltype(&CoInitializeEx) TrueCoInitializeEx = CoInitializeEx;

EXTERN_C HRESULT STDAPICALLTYPE DetourCoInitializeEx(_In_opt_ LPVOID pvReserved, _In_ DWORD dwCoInit)
{
	const HRESULT iResult = TrueCoInitializeEx(pvReserved, dwCoInit);
	if ((iResult == S_OK || iResult == S_FALSE) && bComDetoursNeedToBeInitialized.exchange(false))
	{
		// attach com-based detours
		InitializeComDetoursForCurrentThread();
	}
	return iResult;
}

static decltype(&CoInitialize) TrueCoInitialize = CoInitialize;

EXTERN_C HRESULT STDAPICALLTYPE DetourCoInitialize(_In_opt_ LPVOID pvReserved)
{
	const HRESULT iResult = TrueCoInitialize(pvReserved);
	if ((iResult == S_OK || iResult == S_FALSE) && bComDetoursNeedToBeInitialized.exchange(false))
	{
		// attach com-based detours
		InitializeComDetoursForCurrentThread();
	}
	return iResult;
}

static decltype(&CoCreateInstance) TrueCoCreateInstance = CoCreateInstance;

static HRESULT STDAPICALLTYPE DetourCoCreateInstance(_In_ REFCLSID rclsid,
	_In_opt_ LPUNKNOWN pUnkOuter, _In_ DWORD dwClsContext, _In_ REFIID riid,
	_COM_Outptr_ LPVOID* ppv)
{
	// Some runtimes initialize COM before WinPriv is injected, so no later
	// CoInitialize call is available to trigger the ADO vtable hook. Object
	// activation is the last safe point before Connection::Open can be called.
	InitializeComDetoursForCurrentThread();
	const HRESULT iResult = TrueCoCreateInstance(rclsid, pUnkOuter,
		dwClsContext, riid, ppv);
	// A cross-apartment callback may have skipped the nonblocking gate while
	// another thread initialized. Retry once after activation completes.
	InitializeComDetoursForCurrentThread();
	return iResult;
}

static decltype(&CoCreateInstanceEx) TrueCoCreateInstanceEx = CoCreateInstanceEx;

static HRESULT STDAPICALLTYPE DetourCoCreateInstanceEx(_In_ REFCLSID Clsid,
	_In_opt_ IUnknown* punkOuter, _In_ DWORD dwClsCtx,
	_In_opt_ COSERVERINFO* pServerInfo, _In_ DWORD dwCount,
	_Inout_updates_(dwCount) MULTI_QI* pResults)
{
	InitializeComDetoursForCurrentThread();
	const HRESULT iResult = TrueCoCreateInstanceEx(Clsid, punkOuter, dwClsCtx,
		pServerInfo, dwCount, pResults);
	InitializeComDetoursForCurrentThread();
	return iResult;
}

//   __   ___ ___  __        __   __                           __   ___        ___      ___
//  |  \ |__   |  /  \ |  | |__) /__`     |\/|  /\  |\ |  /\  / _` |__   |\/| |__  |\ |  |
//  |__/ |___  |  \__/ \__/ |  \ .__/     |  | /~~\ | \| /~~\ \__> |___  |  | |___ | \|  |

bool AttachExtraHooks()
{
	// Skip if this is the parent process
	if (VariableIsSet(WINPRIV_EV_PARENT_PID, GetCurrentProcessId()))
	{
		return true;
	}

	if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		AttachDetour(TrueRtlExitUserProcess, DetourRtlExitUserProcess);
	}

	if (VariableNotEmpty(WINPRIV_EV_MOCK_TIME))
	{
		AttachTimeHooks();
	}

	if (VariableNotEmpty(WINPRIV_EV_MAC_OVERRIDE))
	{
		(void)GetMacOverrideInfo();
		AttachDetour(TrueNetWkstaTransportEnum, DetourNetWkstaTransportEnum);
		AttachDetour(TrueGetAdaptersInfo, DetourGetAdaptersInfo);
		AttachDetour(TrueGetAdaptersAddresses, DetourGetAdaptersAddresses);
	}

	if (VariableNotEmpty(WINPRIV_EV_REG_OVERRIDE))
	{
		// Emulated x86 threads can query the registry before their static TLS is initialized.
		InitializeRegistryOverrides();
		AttachDetour(TrueNtQueryValueKey, DetourNtQueryValueKey);
		AttachDetour(TrueNtEnumerateValueKey, DetourNtEnumerateValueKey);
	}

	if (VariableIsSet(WINPRIV_EV_DISABLE_AMSI, 1))
	{
		AttachDetour(TrueAmsiScanBuffer, DetourAmsiScanBuffer);
		AttachDetour(TrueAmsiScanString, DetourAmsiScanString);
	}

	if (VariableNotEmpty(WINPRIV_EV_CLM))
	{
		AttachDetour(TrueWldpGetLockdownPolicy, DetourWldpGetLockdownPolicy);
		TrueWldpCanExecuteFile = reinterpret_cast<decltype(TrueWldpCanExecuteFile)>(
			GetProcAddress(GetModuleHandleW(L"wldp.dll"), "WldpCanExecuteFile"));
		if (TrueWldpCanExecuteFile != nullptr)
			AttachDetour(TrueWldpCanExecuteFile, DetourWldpCanExecuteFile);
		AttachDetour(TrueWldpIsClassInApprovedList, DetourWldpIsClassInApprovedList);
		AttachDetour(TrueSaferIdentifyLevel, DetourSaferIdentifyLevel);
	}

	if (!AttachHostHooks()) return false;

	if (!AttachFileHooks()) return false;

	if (VariableIsSet(WINPRIV_EV_ADMIN_IMPERSONATE, 1))
	{
		(void)GetLocalAdministratorsGroup();
		AttachDetour(TrueIsUserAnAdmin, DetourIsUserAnAdmin);
		AttachDetour(TrueCheckTokenMembership, DetourCheckTokenMembership);
	}

	if (VariableIsSet(WINPRIV_EV_SERVER_EDITION, 1))
	{
		AttachDetour(TrueGetVersionExW, DetourGetVersionExW);
		AttachDetour(TrueGetVersionExA, DetourGetVersionExA);
		AttachDetour(TrueVerifyVersionInfoW, DetourVerifyVersionInfoW);
	}

	if (VariableNotEmpty(WINPRIV_EV_RECORD_CRYPTO))
	{
		AttachDetour(TrueBCryptEncrypt, DetourBCryptEncrypt);
		AttachDetour(TrueBCryptDecrypt, DetourBCryptDecrypt);
		AttachDetour(TrueCryptEncrypt, DetourCryptEncrypt);
		AttachDetour(TrueCryptDecrypt, DetourCryptDecrypt);
		AttachDetour(TrueRtlEncryptMemory, DetourRtlEncryptMemory);
		AttachDetour(TrueRtlDecryptMemory, DetourRtlDecryptMemory);
	}

	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		if (!InitializeHookThreadState()) return false;
		AttachDetour(TrueSQLDriverConnectW, DetourSQLDriverConnectW);
	}

	if (VariableNotEmpty(WINPRIV_EV_PRIVLIST))
	{
		// enable the comma-delimited privileges inherited from the launcher
		std::vector<std::wstring> vPrivs;
		for (const auto sPriv : std::wstring_view(_wgetenv(WINPRIV_EV_PRIVLIST)) | std::views::split(L','))
			vPrivs.emplace_back(sPriv.begin(), sPriv.end());
		if (!EnablePrivs(vPrivs).empty()) PrintMessage(L"%s", L"ERROR: Could not enable privileges in subprocess.\n");
	}

	// special handling for com-based detours
	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		AttachDetour(TrueCoInitializeEx, DetourCoInitializeEx);
		AttachDetour(TrueCoInitialize, DetourCoInitialize);
		AttachDetour(TrueCoCreateInstance, DetourCoCreateInstance);
		AttachDetour(TrueCoCreateInstanceEx, DetourCoCreateInstanceEx);
	}
	return true;
}
