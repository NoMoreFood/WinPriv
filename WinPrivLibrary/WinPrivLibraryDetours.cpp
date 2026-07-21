//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#define _WINSOCKAPI_
#include <Windows.h>
#include <winternl.h>
#include "WinPrivDetoursFork.h"
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

#define _NTDEF_
#include <NTSecAPI.h>

#include <string>
#include <vector>
#include <regex>
#include <atomic>
#include <array>
#include <cerrno>
#include <limits>

#include "WinPrivShared.h"
#include "WinPrivLibrary.h"

#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"amsi.lib")

//   ___         ___     __   __   ___
//  |__  | |    |__     /  \ |__) |__  |\ |
//  |    | |___ |___    \__/ |    |___ | \|
//

static bool CloseFileHandle(PUNICODE_STRING sFileNameUnicodeString)
{
	// valid path formats
	static const std::wregex tRegexLocal(LR"(\\\?\?\\(.*))", std::wregex::optimize);
	static const std::wregex tRegexUnc(LR"(\\\?\?\\UNC\\([^\\]+?)\\([^\\]+?)\\(.*))", std::wregex::optimize);

	std::wstring sComputerName;
	std::wstring sPath;

	const std::wstring sFileName(sFileNameUnicodeString->Buffer, sFileNameUnicodeString->Length / sizeof(WCHAR));

	// see if the path looks like a unc path
	std::wsmatch tMatches;
	if (std::regex_match(sFileName, tMatches, tRegexUnc))
	{
		// extract the important parts of the regular expression result
		sComputerName = tMatches[1].str();
		const std::wstring sShareName = tMatches[2].str();
		const std::wstring sLocalPath = tMatches[3].str();

		// get the real path name using the computer and share name
		SmartPointer<PSHARE_INFO_502> tShareInfo(NetApiBufferFree, nullptr);
		if (NetShareGetInfo((LPWSTR)sComputerName.c_str(), (LPWSTR)sShareName.c_str(), 502, (LPBYTE*)&tShareInfo) != NERR_Success || tShareInfo == nullptr)
			return false;
		const size_t iSharePathLength = tShareInfo->shi502_path == nullptr ? 0 : wcslen(tShareInfo->shi502_path);
		if (iSharePathLength == 0) return false;
		const bool bNeedsBackslash = tShareInfo->shi502_path[iSharePathLength - 1] != L'\\';
		sPath = std::wstring(tShareInfo->shi502_path) + ((bNeedsBackslash) ? L"\\" : L"") + sLocalPath;
	}

	// see if the path looks like a local path
	else if (std::regex_match(sFileName, tMatches, tRegexLocal))
	{
		sPath = tMatches[1].str();
	}

	// unrecognized path type
	else
	{
		return false;
	}

	// loop through the files matching the path
	DWORD iClosedFiles = 0;
	DWORD iStatus = 0;
	DWORD iEntriesRead = 0;
	DWORD iReturned = 0;
	DWORD_PTR hHandle = 0;
	std::vector<DWORD> tFileIds;
	SmartPointer<PFILE_INFO_3> tFileInfo(NetApiBufferFree, nullptr);
	while ((iStatus = NetFileEnum(sComputerName.empty() ? nullptr : (LPWSTR)sComputerName.c_str(),
		(LPWSTR)sPath.c_str(), nullptr, 3, (LPBYTE*)&tFileInfo,
		MAX_PREFERRED_LENGTH, &iEntriesRead, &iReturned, &hHandle)) == NERR_Success || iStatus == ERROR_MORE_DATA)
	{
		if (iEntriesRead == 0) break;

		// put the files into a vector so we can close them all at once and not
		// interrupt the enumeration operation
		for (DWORD iEntry = 0; iEntry < iEntriesRead; iEntry++)
		{
			if (tFileInfo[iEntry].fi3_pathname != nullptr &&
				CompareStringOrdinal(tFileInfo[iEntry].fi3_pathname, -1,
					sPath.c_str(), -1, TRUE) == CSTR_EQUAL)
			{
				tFileIds.push_back(tFileInfo[iEntry].fi3_id);
			}
		}
		tFileInfo.Cleanup();
	}

	// close the open files
	for (const DWORD iFileId : tFileIds)
	{
		if (NetFileClose(sComputerName.empty() ? nullptr : (LPWSTR)sComputerName.c_str(),
			iFileId) == NERR_Success)
		{
			iClosedFiles++;
		}
	}
	return iClosedFiles > 0;
}

static decltype(&NtOpenFile) TrueNtOpenFile = (decltype(&NtOpenFile))
GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtOpenFile");
static decltype(&NtCreateFile) TrueNtCreateFile = (decltype(&NtCreateFile))
GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtCreateFile");

EXTERN_C NTSTATUS NTAPI DetourNtOpenFile(OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess, IN ULONG OpenOptions)
{
	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1))
	{
		OpenOptions |= FILE_OPEN_FOR_BACKUP_INTENT;
	}

	NTSTATUS iStatus = TrueNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
		IoStatusBlock, ShareAccess, OpenOptions);

	if (VariableIsSet(WINPRIV_EV_BREAK_LOCKS, 1))
	{
		if (iStatus == STATUS_SHARING_VIOLATION || iStatus == STATUS_ACCESS_DENIED)
		{
			if (CloseFileHandle(ObjectAttributes->ObjectName))
			{
				// try operation again now that file is closed
				iStatus = TrueNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes,
					IoStatusBlock, ShareAccess, OpenOptions);
			}
		}
	}

	return iStatus;
}

EXTERN_C NTSTATUS NTAPI DetourNtCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer OPTIONAL, IN ULONG EaLength)
{
	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1))
	{
		CreateOptions |= FILE_OPEN_FOR_BACKUP_INTENT;
	}

	NTSTATUS iStatus = TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

	if (VariableIsSet(WINPRIV_EV_BREAK_LOCKS, 1))
	{
		if (iStatus == STATUS_SHARING_VIOLATION || iStatus == STATUS_ACCESS_DENIED)
		{
			if (CloseFileHandle(ObjectAttributes->ObjectName))
			{
				// try operation again now that file is closed
				iStatus = TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
					FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
			}
		}
	}

	return iStatus;
}

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
	return sLeft.Buffer != nullptr && sRight->Buffer != nullptr &&
		_wcsnicmp(sLeft.Buffer, sRight->Buffer, sLeft.Length / sizeof(WCHAR)) == 0;
}

static bool RegistryKeyIsSameOrDescendant(const UNICODE_STRING& sParent, const UNICODE_STRING& sKey)
{
	if (sParent.Length > sKey.Length || sParent.Buffer == nullptr || sKey.Buffer == nullptr)
		return false;

	const size_t iParentChars = sParent.Length / sizeof(WCHAR);
	if (_wcsnicmp(sParent.Buffer, sKey.Buffer, iParentChars) != 0) return false;
	return sParent.Length == sKey.Length || sKey.Buffer[iParentChars] == L'\\';
}

static bool ParseRegistryDword(LPCWSTR sData, DWORD& iValue)
{
	if (sData == nullptr || *sData == L'\0') return false;
	errno = 0;
	LPWSTR sEnd = nullptr;
	const unsigned long iParsed = wcstoul(sData, &sEnd, 0);
	if (errno == ERANGE || sEnd == sData || *sEnd != L'\0') return false;
	iValue = static_cast<DWORD>(iParsed);
	return true;
}

static bool ParseRegistryQword(LPCWSTR sData, unsigned __int64& iValue)
{
	if (sData == nullptr || *sData == L'\0') return false;
	errno = 0;
	LPWSTR sEnd = nullptr;
	const unsigned __int64 iParsed = _wcstoui64(sData, &sEnd, 0);
	if (errno == ERANGE || sEnd == sData || *sEnd != L'\0') return false;
	iValue = iParsed;
	return true;
}

static int HexDigitValue(const WCHAR iChar)
{
	if (iChar >= L'0' && iChar <= L'9') return iChar - L'0';
	if (iChar >= L'a' && iChar <= L'f') return iChar - L'a' + 10;
	if (iChar >= L'A' && iChar <= L'F') return iChar - L'A' + 10;
	return -1;
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
	if (!bFull && !bPartial) return STATUS_NOT_SUPPORTED;
	if (pInformation != nullptr)
	{
		const UINT_PTR iRequiredAlignment =
			(iInformationClass == KeyValueFullInformationAlign64 ||
			 iInformationClass == KeyValuePartialInformationAlign64) ? 8 : 4;
		if ((reinterpret_cast<UINT_PTR>(pInformation) &
			(iRequiredAlignment - 1)) != 0)
			return STATUS_DATATYPE_MISALIGNMENT;
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
		if (iLength > iNameOffset && tOverride.RegValueName.Length != 0)
		{
			const ULONG iAvailable = iLength - iNameOffset;
			const ULONG iCopyLength = iAvailable < tOverride.RegValueName.Length
				? iAvailable : tOverride.RegValueName.Length;
			memcpy(tKeyInfo->Name, tOverride.RegValueName.Buffer,
				iCopyLength);
		}
		if (iLength > iDataOffset && tOverride.RegValueDataSize != 0)
		{
			const ULONG iAvailable = iLength - iDataOffset;
			const ULONG iCopyLength = iAvailable < tOverride.RegValueDataSize
				? iAvailable : tOverride.RegValueDataSize;
			memcpy(static_cast<PBYTE>(pInformation) + iDataOffset,
				tOverride.RegValueData, iCopyLength);
		}
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
		if (iLength > iDataOffset && tOverride.RegValueDataSize != 0)
		{
			const ULONG iAvailable = iLength - iDataOffset;
			const ULONG iCopyLength = iAvailable < tOverride.RegValueDataSize
				? iAvailable : tOverride.RegValueDataSize;
			memcpy(tKeyInfo->Data, tOverride.RegValueData, iCopyLength);
		}
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
		if (iLength > iDataOffset && tOverride.RegValueDataSize != 0)
		{
			const ULONG iAvailable = iLength - iDataOffset;
			const ULONG iCopyLength = iAvailable < tOverride.RegValueDataSize
				? iAvailable : tOverride.RegValueDataSize;
			memcpy(pBytes + iDataOffset, tOverride.RegValueData, iCopyLength);
		}
		return iStatus;
	}

	return STATUS_NOT_SUPPORTED;
}

static NTSTATUS(WINAPI* TrueNtQueryValueKey)(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName, _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
											 _Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length, _Out_ PULONG ResultLength) = (decltype(TrueNtQueryValueKey))
	GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryValueKey");

EXTERN_C NTSTATUS WINAPI DetourNtQueryValueKey(_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName, _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length, _Out_ PULONG ResultLength)
{
	static const std::vector<RegInterceptInfo*> vRegInterceptList = []
	{
		std::vector<RegInterceptInfo*> vResult;

		// parse the parameters to create the intercept list
		int iParams = 0;
		SmartPointer<LPWSTR*> sParams(LocalFree,
			CommandLineToArgvW(_wgetenv(WINPRIV_EV_REG_OVERRIDE), &iParams));
		if (sParams == nullptr) return vResult;
		for (int iParam = 0; iParam + 3 < iParams; iParam += 4)
		{
			RegInterceptInfo* tInterceptInfo = static_cast<RegInterceptInfo*>(calloc(1, sizeof(RegInterceptInfo)));
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
			else
			{
				FreeRegInterceptInfo(tInterceptInfo);
				continue;
			}

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

			// verify key name lookup succeeded
			if (tInterceptInfo->RegKeyName.Length == 0)
			{
				FreeRegInterceptInfo(tInterceptInfo);
				continue;
			}

			// fetch value name
			const LPWSTR sValueName = sParams[iParam + 1];
			const size_t iValueNameBytes = wcslen(sValueName) * sizeof(WCHAR);
			if (iValueNameBytes >
				(std::numeric_limits<USHORT>::max)() - sizeof(WCHAR))
			{
				FreeRegInterceptInfo(tInterceptInfo);
				continue;
			}
			tInterceptInfo->RegValueName = { static_cast<USHORT>(wcslen(sValueName) * sizeof(WCHAR)),
				static_cast<USHORT>(iValueNameBytes + sizeof(WCHAR)), _wcsdup(sValueName) };
			if (tInterceptInfo->RegValueName.Buffer == nullptr)
			{
				FreeRegInterceptInfo(tInterceptInfo);
				continue;
			}

			// match the aesthetic types to the typed enumerations
			const LPWSTR sType = sParams[iParam + 2];
			if (_wcsicmp(sType, L"REG_DWORD") == 0) tInterceptInfo->RegValueType = REG_DWORD;
			else if (_wcsicmp(sType, L"REG_QWORD") == 0) tInterceptInfo->RegValueType = REG_QWORD;
			else if (_wcsicmp(sType, L"REG_SZ") == 0) tInterceptInfo->RegValueType = REG_SZ;
			else if (_wcsicmp(sType, L"REG_BINARY") == 0) tInterceptInfo->RegValueType = REG_BINARY;
			else if (_wcsicmp(sType, L"REG_BLOCK") == 0) tInterceptInfo->RegValueType = REG_BLOCK;
			else
			{
				FreeRegInterceptInfo(tInterceptInfo);
				continue;
			}

			// decode the value string to a data blob
			const LPWSTR sData = sParams[iParam + 3];
			if (tInterceptInfo->RegValueType == REG_DWORD)
			{
				DWORD iValue = 0;
				if (!ParseRegistryDword(sData, iValue))
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
				tInterceptInfo->RegValueData = malloc(sizeof(iValue));
				if (tInterceptInfo->RegValueData == nullptr)
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
				memcpy(tInterceptInfo->RegValueData, &iValue, sizeof(iValue));
				tInterceptInfo->RegValueDataSize = sizeof(DWORD);
			}
			else if (tInterceptInfo->RegValueType == REG_QWORD)
			{
				unsigned __int64 iValue = 0;
				if (!ParseRegistryQword(sData, iValue))
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
				tInterceptInfo->RegValueData = malloc(sizeof(iValue));
				if (tInterceptInfo->RegValueData == nullptr)
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
				memcpy(tInterceptInfo->RegValueData, &iValue, sizeof(iValue));
				tInterceptInfo->RegValueDataSize = sizeof(unsigned __int64);
			}
			else if (tInterceptInfo->RegValueType == REG_SZ)
			{
				tInterceptInfo->RegValueData = _wcsdup(sData);
				if (tInterceptInfo->RegValueData == nullptr)
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
				tInterceptInfo->RegValueDataSize =
					static_cast<DWORD>((wcslen(sData) + 1) * sizeof(WCHAR));
			}
			else if (tInterceptInfo->RegValueType == REG_BINARY)
			{
				const size_t iDataChars = wcslen(sData);
				if ((iDataChars % 2) != 0)
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
				tInterceptInfo->RegValueDataSize = static_cast<DWORD>(iDataChars / 2);
				if (tInterceptInfo->RegValueDataSize != 0)
				{
					tInterceptInfo->RegValueData = malloc(tInterceptInfo->RegValueDataSize);
					if (tInterceptInfo->RegValueData == nullptr)
					{
						FreeRegInterceptInfo(tInterceptInfo);
						continue;
					}
				}
				bool bValid = true;
				for (size_t iByte = 0; iByte < tInterceptInfo->RegValueDataSize; iByte++)
				{
					const int iHigh = HexDigitValue(sData[iByte * 2]);
					const int iLow = HexDigitValue(sData[iByte * 2 + 1]);
					if (iHigh < 0 || iLow < 0)
					{
						bValid = false;
						break;
					}
					static_cast<PBYTE>(tInterceptInfo->RegValueData)[iByte] =
						static_cast<BYTE>((iHigh << 4) | iLow);
				}
				if (!bValid)
				{
					FreeRegInterceptInfo(tInterceptInfo);
					continue;
				}
			}
			else if (tInterceptInfo->RegValueType == REG_BLOCK)
			{
				tInterceptInfo->RegValueData = nullptr;
				tInterceptInfo->RegValueDataSize = 0;
			}

			// fully processed entry - continue
			vResult.push_back(tInterceptInfo);
		}
		return vResult;
	}();

	// sanity check
	if (ResultLength == nullptr)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// lookup the size for the key name so we can allocate space for it
	DWORD iKeyNameSize;
	const NTSTATUS iKeyStatus = NtQueryKey(KeyHandle, KeyNameInformation, nullptr, 0, &iKeyNameSize);
	if (iKeyStatus != STATUS_BUFFER_TOO_SMALL)
	{
		return iKeyStatus;
	}

	// allocate space for name and lookup
	bool bIntercepted = false;
	NTSTATUS iStatus = STATUS_UNSUCCESSFUL;
	SmartPointer<PKEY_NAME_INFORMATION> pNameInfo(free, static_cast<PKEY_NAME_INFORMATION>(malloc(iKeyNameSize)));
	if (pNameInfo != nullptr && NtQueryKey(KeyHandle, KeyNameInformation, pNameInfo,
		iKeyNameSize, &iKeyNameSize) == STATUS_SUCCESS)
	{
		// convert to unicode string structure for quick comparisons
		const UNICODE_STRING sKeyName = { static_cast<USHORT>(pNameInfo->NameLength),
			static_cast<USHORT>(pNameInfo->NameLength), pNameInfo->Name };

		for (const RegInterceptInfo* tRegOverrideInfo : vRegInterceptList)
		{
			// handle registry block
			if (RegistryKeyIsSameOrDescendant(tRegOverrideInfo->RegKeyName, sKeyName) &&
				tRegOverrideInfo->RegValueType == REG_BLOCK)
			{
				*ResultLength = 0;
				bIntercepted = true;
				iStatus = STATUS_OBJECT_NAME_NOT_FOUND;
				break;
			}

			// handle registry override
			if (UnicodeStringEquals(tRegOverrideInfo->RegKeyName, &sKeyName) &&
				UnicodeStringEquals(tRegOverrideInfo->RegValueName, ValueName))
			{
				iStatus = WriteRegistryOverride(*tRegOverrideInfo,
					KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
				if (iStatus != STATUS_NOT_SUPPORTED) bIntercepted = true;
			}
		}
	}

	// return the real value if no match was found
	if (!bIntercepted)
	{
		iStatus = TrueNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
			KeyValueInformation, Length, ResultLength);
	}

	return iStatus;
}

static NTSTATUS(WINAPI* TrueNtEnumerateValueKey)(_In_ HANDLE KeyHandle, _In_ ULONG Index,
												 _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, _Out_opt_ PVOID KeyValueInformation,
												 _In_ ULONG Length, _Out_ PULONG ResultLength) = (decltype(TrueNtEnumerateValueKey))
	GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtEnumerateValueKey");

EXTERN_C NTSTATUS WINAPI DetourNtEnumerateValueKey(_In_ HANDLE KeyHandle, _In_ ULONG Index,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, _Out_opt_ PVOID KeyValueInformation,
	_In_ ULONG Length, _Out_ PULONG ResultLength)
{
	NTSTATUS iStatus = TrueNtEnumerateValueKey(KeyHandle, Index,
		KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	if (iStatus == STATUS_SUCCESS && KeyValueInformation != nullptr &&
		(KeyValueInformationClass == KeyValueFullInformation ||
			KeyValueInformationClass == KeyValueFullInformationAlign64))
	{
		const PKEY_VALUE_FULL_INFORMATION tKeyInfo = static_cast<PKEY_VALUE_FULL_INFORMATION>(KeyValueInformation);
		UNICODE_STRING sValue = { static_cast<USHORT>(tKeyInfo->NameLength), static_cast<USHORT>(tKeyInfo->NameLength), tKeyInfo->Name };
		iStatus = DetourNtQueryValueKey(KeyHandle, &sValue,
			KeyValueInformationClass, KeyValueInformation, Length, ResultLength);
		return iStatus;
	}

	return iStatus;
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

		tResult.Length = tResult.Text.length() / 2;
		for (size_t iByte = 0; iByte < tResult.Length; iByte++)
		{
			const int iHigh = HexDigitValue(tResult.Text[iByte * 2]);
			const int iLow = HexDigitValue(tResult.Text[iByte * 2 + 1]);
			if (iHigh < 0 || iLow < 0)
			{
				tResult.Length = 0;
				return tResult;
			}
			tResult.Address[iByte] = static_cast<BYTE>((iHigh << 4) | iLow);
		}
		tResult.Valid = true;
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
	*result = AMSI_RESULT_CLEAN;
	return S_OK;
}

static decltype(&AmsiScanString) TrueAmsiScanString = AmsiScanString;

static HRESULT WINAPI DetourAmsiScanString(_In_  HAMSICONTEXT amsiContext, _In_  LPCWSTR string, _In_opt_  LPCWSTR contentName,
									_In_opt_  HAMSISESSION amsiSession, _Out_ AMSI_RESULT* result)
{
	*result = AMSI_RESULT_CLEAN;
	return S_OK;
}

//        __   __  ___     __        ___  __   __     __   ___
//  |__| /  \ /__`  |     /  \ \  / |__  |__) |__) | |  \ |__
//  |  | \__/ .__/  |     \__/  \/  |___ |  \ |  \ | |__/ |___
//
//

static bool GetHostOverrideAddress(_In_ LPCWSTR sName, _Out_ IN_ADDR& tReplacement)
{
	static INT iHostOverrideParams = 0;
	static LPWSTR* sHostOverride = CommandLineToArgvW(_wgetenv(WINPRIV_EV_HOST_OVERRIDE), &iHostOverrideParams);
	if (sName == nullptr || sHostOverride == nullptr) return false;

	// parse the parameters to create the intercept list
	for (int iParam = 0; iParam + 1 < iHostOverrideParams; iParam += 2)
	{
		if (_wcsicmp(sName, sHostOverride[iParam]) != 0) continue;

		LPCWSTR sTerm = nullptr;
		if (RtlIpv4StringToAddressW(sHostOverride[iParam + 1], TRUE,
			&sTerm, &tReplacement) == STATUS_SUCCESS && sTerm != nullptr && *sTerm == L'\0')
			return true;
	}
	return false;
}

struct HostLookupName
{
	HANDLE Lookup;
	ULONGLONG Generation;
	std::wstring Name;
};

static SRWLOCK tHostLookupNameLock = SRWLOCK_INIT;
static std::vector<HostLookupName> vHostLookupNames;
static ULONGLONG iHostLookupNameGeneration = 0;

static bool ConvertHostLookupName(_In_ LPCSTR sName, _Out_ std::wstring& sWideName) noexcept
{
	if (sName == nullptr) return false;
	const size_t iNarrowLength = strlen(sName);
	if (iNarrowLength > static_cast<size_t>((std::numeric_limits<int>::max)()))
		return false;
	if (iNarrowLength == 0)
	{
		sWideName.clear();
		return true;
	}

	const int iWideLength = MultiByteToWideChar(CP_ACP, 0, sName,
		static_cast<int>(iNarrowLength), nullptr, 0);
	if (iWideLength <= 0) return false;
	try
	{
		sWideName.resize(iWideLength);
	}
	catch (...)
	{
		return false;
	}
	return MultiByteToWideChar(CP_ACP, 0, sName,
		static_cast<int>(iNarrowLength), sWideName.data(), iWideLength) != 0;
}

static void RememberHostLookupName(_In_ HANDLE hLookup, _In_ LPCWSTR sName) noexcept
{
	if (hLookup == nullptr || sName == nullptr || *sName == L'\0') return;
	try
	{
		std::wstring sNameCopy(sName);
		AcquireSRWLockExclusive(&tHostLookupNameLock);
		try
		{
			if (++iHostLookupNameGeneration == 0) ++iHostLookupNameGeneration;
			for (HostLookupName& tLookup : vHostLookupNames)
			{
				if (tLookup.Lookup != hLookup) continue;
				tLookup.Generation = iHostLookupNameGeneration;
				tLookup.Name = std::move(sNameCopy);
				ReleaseSRWLockExclusive(&tHostLookupNameLock);
				return;
			}
			vHostLookupNames.push_back({ hLookup, iHostLookupNameGeneration,
				std::move(sNameCopy) });
		}
		catch (...)
		{
			ReleaseSRWLockExclusive(&tHostLookupNameLock);
			return;
		}
		ReleaseSRWLockExclusive(&tHostLookupNameLock);
	}
	catch (...)
	{
		// A failed bookkeeping allocation must not change Winsock behavior.
	}
}

static bool GetRememberedHostLookupName(_In_ HANDLE hLookup,
	_Out_ std::wstring& sName) noexcept
{
	AcquireSRWLockShared(&tHostLookupNameLock);
	try
	{
		for (const HostLookupName& tLookup : vHostLookupNames)
		{
			if (tLookup.Lookup != hLookup) continue;
			sName = tLookup.Name;
			ReleaseSRWLockShared(&tHostLookupNameLock);
			return true;
		}
	}
	catch (...)
	{
		ReleaseSRWLockShared(&tHostLookupNameLock);
		return false;
	}
	ReleaseSRWLockShared(&tHostLookupNameLock);
	return false;
}

static ULONGLONG GetHostLookupNameGeneration(_In_ HANDLE hLookup) noexcept
{
	AcquireSRWLockShared(&tHostLookupNameLock);
	for (const HostLookupName& tLookup : vHostLookupNames)
	{
		if (tLookup.Lookup != hLookup) continue;
		const ULONGLONG iGeneration = tLookup.Generation;
		ReleaseSRWLockShared(&tHostLookupNameLock);
		return iGeneration;
	}
	ReleaseSRWLockShared(&tHostLookupNameLock);
	return 0;
}

static void ForgetHostLookupName(_In_ HANDLE hLookup,
	_In_ ULONGLONG iGeneration) noexcept
{
	AcquireSRWLockExclusive(&tHostLookupNameLock);
	try
	{
		for (auto iLookup = vHostLookupNames.begin(); iLookup != vHostLookupNames.end(); ++iLookup)
		{
			if (iLookup->Lookup != hLookup ||
				iLookup->Generation != iGeneration) continue;
			vHostLookupNames.erase(iLookup);
			break;
		}
	}
	catch (...)
	{
		// Preserve the Winsock result even if bookkeeping cleanup fails.
	}
	ReleaseSRWLockExclusive(&tHostLookupNameLock);
}

static void UpdateIpAddress(_In_ LPCWSTR sName, _Inout_ const SOCKET_ADDRESS& tSocketAddress)
{
	if (tSocketAddress.lpSockaddr == nullptr) return;

	IN_ADDR tReplacement{};
	if (!GetHostOverrideAddress(sName, tReplacement)) return;

	if (tSocketAddress.lpSockaddr->sa_family == AF_INET6 &&
		tSocketAddress.iSockaddrLength >= static_cast<INT>(sizeof(SOCKADDR_IN6)))
	{
		SOCKADDR_IN6* pAddr = reinterpret_cast<SOCKADDR_IN6*>(tSocketAddress.lpSockaddr);
		IN6_SET_ADDR_V4MAPPED(&pAddr->sin6_addr, &tReplacement);
	}
	else if (tSocketAddress.lpSockaddr->sa_family == AF_INET &&
		tSocketAddress.iSockaddrLength >= static_cast<INT>(sizeof(SOCKADDR_IN)))
	{
		SOCKADDR_IN* pAddr = reinterpret_cast<SOCKADDR_IN*>(tSocketAddress.lpSockaddr);
		pAddr->sin_addr = tReplacement;
	}
}

static decltype(&WSALookupServiceBeginW) TrueWSALookupServiceBeginW = WSALookupServiceBeginW;

static INT WSAAPI DetourWSALookupServiceBeginW(_In_ LPWSAQUERYSETW lpqsRestrictions,
	_In_ DWORD dwControlFlags, _Out_ LPHANDLE lphLookup)
{
	const INT iRet = TrueWSALookupServiceBeginW(lpqsRestrictions,
		dwControlFlags, lphLookup);
	if (iRet != SOCKET_ERROR && lphLookup != nullptr &&
		lpqsRestrictions != nullptr)
	{
		RememberHostLookupName(*lphLookup,
			lpqsRestrictions->lpszServiceInstanceName);
	}
	return iRet;
}

static decltype(&WSALookupServiceBeginA) TrueWSALookupServiceBeginA = WSALookupServiceBeginA;

static INT WSAAPI DetourWSALookupServiceBeginA(_In_ LPWSAQUERYSETA lpqsRestrictions,
	_In_ DWORD dwControlFlags, _Out_ LPHANDLE lphLookup)
{
	const INT iRet = TrueWSALookupServiceBeginA(lpqsRestrictions,
		dwControlFlags, lphLookup);
	if (iRet != SOCKET_ERROR && lphLookup != nullptr &&
		lpqsRestrictions != nullptr)
	{
		std::wstring sWideName;
		if (ConvertHostLookupName(lpqsRestrictions->lpszServiceInstanceName,
			sWideName))
		{
			RememberHostLookupName(*lphLookup, sWideName.c_str());
		}
	}
	return iRet;
}

static decltype(&WSALookupServiceNextW) TrueWSALookupServiceNextW = WSALookupServiceNextW;

static INT WSAAPI DetourWSALookupServiceNextW(_In_ HANDLE hLookup, _In_ DWORD dwControlFlags,
											  _Inout_ LPDWORD lpdwBufferLength, _Out_ LPWSAQUERYSETW lpqsResults)
{
	// call the real lookup function and return immediately if failed
	const INT iRet = TrueWSALookupServiceNextW(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
	if (iRet == SOCKET_ERROR || lpqsResults == nullptr ||
		lpqsResults->dwNumberOfCsAddrs == 0 || lpqsResults->lpcsaBuffer == nullptr)
		return iRet;

	std::wstring sLookupName;
	const LPCWSTR sName = GetRememberedHostLookupName(hLookup, sLookupName)
		? sLookupName.c_str() : lpqsResults->lpszServiceInstanceName;

	// Inspect every returned address. DNS commonly returns both IPv4 and
	// IPv4-mapped IPv6 entries in the same result set.
	for (DWORD iAddress = 0; iAddress < lpqsResults->dwNumberOfCsAddrs; iAddress++)
	{
		UpdateIpAddress(sName,
			lpqsResults->lpcsaBuffer[iAddress].RemoteAddr);
	}

	return iRet;
}

static decltype(&WSALookupServiceNextA) TrueWSALookupServiceNextA = WSALookupServiceNextA;

static INT WSAAPI DetourWSALookupServiceNextA(_In_ HANDLE hLookup, _In_ DWORD dwControlFlags,
											  _Inout_ LPDWORD lpdwBufferLength, _Out_ LPWSAQUERYSETA lpqsResults)
{
	// call the real lookup function and return immediately if failed
	const INT iRet = TrueWSALookupServiceNextA(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
	if (iRet == SOCKET_ERROR || lpqsResults == nullptr ||
		lpqsResults->dwNumberOfCsAddrs == 0 || lpqsResults->lpcsaBuffer == nullptr)
		return iRet;

	std::wstring sQueryNameWide;
	if (!GetRememberedHostLookupName(hLookup, sQueryNameWide) &&
		!ConvertHostLookupName(lpqsResults->lpszServiceInstanceName,
			sQueryNameWide))
		return iRet;
	for (DWORD iAddress = 0; iAddress < lpqsResults->dwNumberOfCsAddrs; iAddress++)
	{
		UpdateIpAddress(sQueryNameWide.c_str(),
			lpqsResults->lpcsaBuffer[iAddress].RemoteAddr);
	}

	return iRet;
}

static decltype(&WSALookupServiceEnd) TrueWSALookupServiceEnd = WSALookupServiceEnd;

static INT WSAAPI DetourWSALookupServiceEnd(_In_ HANDLE hLookup)
{
	const ULONGLONG iGeneration = GetHostLookupNameGeneration(hLookup);
	const INT iRet = TrueWSALookupServiceEnd(hLookup);
	if (iRet != SOCKET_ERROR && iGeneration != 0)
		ForgetHostLookupName(hLookup, iGeneration);
	return iRet;
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

static BOOL APIENTRY DetourCheckTokenMembership(_In_opt_ HANDLE TokenHandle,
												_In_ PSID SidToCheck, _Out_ PBOOL IsMember)
{
	// fetch and allocate the local admin structure (once)
	static SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	static SmartPointer<PSID> LocalAdministratorsGroup(FreeSid, []() -> PSID {
		PSID pSid = nullptr;
		AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
			DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSid);
		return pSid;
	}());

	// get the real value of the function - return if failure
	const BOOL bRealResult = TrueCheckTokenMembership(TokenHandle, SidToCheck, IsMember);
	if (bRealResult == 0) return bRealResult;

	// check if the local admin group is being requested
	if (LocalAdministratorsGroup != nullptr && EqualSid(SidToCheck, LocalAdministratorsGroup))
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

static void RecordCryptoData(LPCWSTR sFunction, PUCHAR pData, DWORD iDataLen)
{
	// Several crypto APIs support size-query calls with a null data buffer.
	// Those calls contain no plaintext to record and must remain side-effect free.
	if (sFunction == nullptr || pData == nullptr || iDataLen == 0) return;

	// remove 'Detour' from the function name
	sFunction = &sFunction[wcslen(L"Detour")];

	// decide whether to output to console or file system
	static const LPWSTR sCryptoValue = _wgetenv(WINPRIV_EV_RECORD_CRYPTO);
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
			return;
		}
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
	catch (const std::regex_error&)
	{
		return false;
	}
	catch (...)
	{
		// No C++ exception may cross an ODBC or COM ABI boundary.
		return false;
	}
}

static LPCWSTR GetSqlConnectReplacement() noexcept
{
	const LPCWSTR sReplacement = _wgetenv(WINPRIV_EV_SQL_CONNECT_REPLACE);
	return sReplacement == nullptr ? L"" : sReplacement;
}

static decltype(&SQLDriverConnectA) TrueSQLDriverConnectA = SQLDriverConnectA;

static SQLRETURN SQL_API DetourSQLDriverConnectA(SQLHDBC hdbc, SQLHWND hwnd, _In_reads_(cbConnStrIn) SQLCHAR* szConnStrIn,
												 SQLSMALLINT cbConnStrIn, _Out_writes_opt_(cbConnStrOutMax) SQLCHAR* szConnStrOut, SQLSMALLINT cbConnStrOutMax,
												 _Out_opt_ SQLSMALLINT* pcbConnStrOut, SQLUSMALLINT fDriverCompletion)
{
	// internally, the ansi function is routed through the wide character function
	// so we do not need to add any handling logic here
	return TrueSQLDriverConnectA(hdbc, hwnd, szConnStrIn, cbConnStrIn, szConnStrOut,
		cbConnStrOutMax, pcbConnStrOut, fDriverCompletion);
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
				PrintMessage(L"SQL Connection String: %s", sShownConnection.c_str());
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

EXTERN_C VOID WINAPI DllExtraAttachCom(VOID);
EXTERN_C VOID WINAPI DllExtraDetachCom(VOID);
static std::atomic<bool> bComDetoursNeedToBeInitialized = true;
static thread_local bool bComDetoursAreBeingInitialized = false;

using AdoDispatchInvoke = HRESULT(STDMETHODCALLTYPE*)(IDispatch*, DISPID,
	REFIID, LCID, WORD, DISPPARAMS*, VARIANT*, EXCEPINFO*, UINT*);
using AdoConnectionOpen = HRESULT(STDMETHODCALLTYPE*)(IUnknown*, BSTR, BSTR,
	BSTR, LONG);

static AdoDispatchInvoke TrueAdoDispatchInvoke = nullptr;
static PVOID pAdoDispatchInvokeTarget = nullptr;
static AdoConnectionOpen TrueAdoConnectionOpen = nullptr;
static PVOID pAdoConnectionOpenTarget = nullptr;
static HMODULE hAdoDispatchModule = nullptr;
static HMODULE hAdoConnectionOpenModule = nullptr;
static HMODULE hWinPrivDispatchModule = nullptr;
static DISPID iAdoOpenDispatchId = DISPID_UNKNOWN;
static DISPID iAdoConnectionStringDispatchId = DISPID_UNKNOWN;
static bool bAdoDispatchAttached = false;
static SRWLOCK tComDetourInitializationLock = SRWLOCK_INIT;
static thread_local ULONG iAdoRewriteDepth = 0;

class ComDetourInitializationScope final
{
public:
	explicit ComDetourInitializationScope(SRWLOCK* pLock) noexcept : pLock_(pLock)
	{
		bComDetoursAreBeingInitialized = true;
	}

	~ComDetourInitializationScope() noexcept
	{
		ReleaseSRWLockExclusive(pLock_);
		bComDetoursAreBeingInitialized = false;
	}

	ComDetourInitializationScope(const ComDetourInitializationScope&) = delete;
	ComDetourInitializationScope& operator=(const ComDetourInitializationScope&) = delete;

private:
	SRWLOCK* pLock_;
};

class AdoRewriteScope final
{
public:
	AdoRewriteScope() { iAdoRewriteDepth++; }
	~AdoRewriteScope() { iAdoRewriteDepth--; }
	AdoRewriteScope(const AdoRewriteScope&) = delete;
	AdoRewriteScope& operator=(const AdoRewriteScope&) = delete;
};

static constexpr IID IID_WinPrivConnection15 =
	{ 0x00000515, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };
static constexpr CLSID CLSID_WinPrivAdoConnection =
	{ 0x00000514, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };

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
			PrintMessage(L"SQL Connection String: %s", sRevised.c_str());
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
	if (iAdoRewriteDepth != 0)
	{
		return TrueAdoConnectionOpen(pConnection, sConnectionString, sUserId,
			sPassword, iOptions);
	}

	AdoRewriteScope tScope;
	BSTR sReplacement = PrepareAdoConnectionString(sConnectionString);
	const HRESULT iResult = TrueAdoConnectionOpen(pConnection,
		sReplacement == nullptr ? sConnectionString : sReplacement,
		sUserId, sPassword, iOptions);
	if (sReplacement != nullptr) SysFreeString(sReplacement);
	return iResult;
}

static HRESULT STDMETHODCALLTYPE DetourAdoDispatchInvoke(IDispatch* pDispatch,
	DISPID iMember, REFIID iInterface, LCID iLocale, WORD iFlags,
	DISPPARAMS* pParameters, VARIANT* pResult, EXCEPINFO* pException,
	UINT* pArgumentError)
{
	if (TrueAdoDispatchInvoke == nullptr) return E_UNEXPECTED;
	if (iMember != iAdoOpenDispatchId ||
		(iFlags & DISPATCH_METHOD) == 0 || pParameters == nullptr ||
		pParameters->rgvarg == nullptr || pParameters->cArgs == 0)
	{
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}
	if (iAdoRewriteDepth != 0)
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
	pConnection->Release();

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
	if (sPassedString == nullptr)
	{
		return TrueAdoDispatchInvoke(pDispatch, iMember, iInterface, iLocale,
			iFlags, pParameters, pResult, pException, pArgumentError);
	}

	BSTR sReplacement = nullptr;
	VARIANTARG tOriginalArgument{};
	bool bArgumentReplaced = false;
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
				if (sReplacement != nullptr)
				{
					sRevised = std::move(sCandidate);
					tOriginalArgument = *pConnectionString;
					VariantInit(pConnectionString);
					V_VT(pConnectionString) = VT_BSTR;
					V_BSTR(pConnectionString) = sReplacement;
					bArgumentReplaced = true;
				}
			}
		}

		if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1))
		{
			PrintMessage(L"SQL Connection String: %s", sRevised.c_str());
		}
	}
	catch (...)
	{
		// Preserve the original call if formatting or allocation fails.
	}

	const HRESULT iResult = TrueAdoDispatchInvoke(pDispatch, iMember,
		iInterface, iLocale, iFlags, pParameters, pResult, pException,
		pArgumentError);
	if (bArgumentReplaced)
	{
		*pConnectionString = tOriginalArgument;
		SysFreeString(sReplacement);
	}
	return iResult;
}

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
			// Connection15 inherits IDispatch (slots 0-6), then _ADO::Properties
			// (7), connection members (8-14), Close/Execute/transaction methods
			// (15-19), and Open at slot 20.
			constexpr size_t iConnectionOpenVtableIndex = 20;
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
			const bool bWinPrivPinned = GetModuleHandleExW(
				GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
				reinterpret_cast<LPCWSTR>(reinterpret_cast<ULONG_PTR>(
					DetourAdoDispatchInvoke)), &hWinPrivDispatchModule) != FALSE;
			winpriv::detours::transaction tTransaction;
			if (bTargetPinned && bOpenTargetPinned && bWinPrivPinned &&
				pAdoConnectionOpenTarget != pAdoDispatchInvokeTarget && tTransaction &&
				tTransaction.apply(winpriv::detours::action::attach,
					TrueAdoDispatchInvoke, DetourAdoDispatchInvoke) == NO_ERROR &&
				tTransaction.apply(winpriv::detours::action::attach,
					TrueAdoConnectionOpen, DetourAdoConnectionOpen) == NO_ERROR &&
				tTransaction.commit() == NO_ERROR)
			{
				bAdoDispatchAttached = true;
			}
		}
	}
	if (pConnection != nullptr) pConnection->Release();
	if (pDispatch != nullptr) pDispatch->Release();
}

static void InitializeComDetoursForCurrentThread()
{
	if (bComDetoursAreBeingInitialized) return;
	if (!TryAcquireSRWLockExclusive(&tComDetourInitializationLock)) return;
	const ComDetourInitializationScope tInitializationScope(
		&tComDetourInitializationLock);
	try
	{
#if defined(_M_X64)
		// x64 needs both late-bound Invoke and direct Connection15::Open coverage;
		// the two C++ hooks share a thread-local rewrite guard.
		AttachAdoDispatchDetour();
#else
		DllExtraAttachCom();
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
template <winpriv::detours::function_pointer Function>
void ApplyDetour(
	winpriv::detours::action requestedAction,
	Function& target,
	Function replacement) noexcept
{
	(void)winpriv::detours::apply(requestedAction, target, replacement);
}

void DllExtraAttachDetach(winpriv::detours::action requestedAction)
{
	const bool attaching = requestedAction == winpriv::detours::action::attach;

	// Skip if this is the parent process
	if (VariableIsSet(WINPRIV_EV_PARENT_PID, GetCurrentProcessId()))
	{
		return;
	}

	if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		ApplyDetour(requestedAction, TrueRtlExitUserProcess, DetourRtlExitUserProcess);
	}

	if (VariableNotEmpty(WINPRIV_EV_MAC_OVERRIDE))
	{
		ApplyDetour(requestedAction, TrueNetWkstaTransportEnum, DetourNetWkstaTransportEnum);
		ApplyDetour(requestedAction, TrueGetAdaptersInfo, DetourGetAdaptersInfo);
		ApplyDetour(requestedAction, TrueGetAdaptersAddresses, DetourGetAdaptersAddresses);
	}

	if (VariableNotEmpty(WINPRIV_EV_REG_OVERRIDE))
	{
		ApplyDetour(requestedAction, TrueNtQueryValueKey, DetourNtQueryValueKey);
		ApplyDetour(requestedAction, TrueNtEnumerateValueKey, DetourNtEnumerateValueKey);
	}

	if (VariableIsSet(WINPRIV_EV_DISABLE_AMSI, 1))
	{
		ApplyDetour(requestedAction, TrueAmsiScanBuffer, DetourAmsiScanBuffer);
		ApplyDetour(requestedAction, TrueAmsiScanString, DetourAmsiScanString);
	}

	if (VariableNotEmpty(WINPRIV_EV_HOST_OVERRIDE))
	{
		ApplyDetour(requestedAction, TrueWSALookupServiceBeginW, DetourWSALookupServiceBeginW);
		ApplyDetour(requestedAction, TrueWSALookupServiceBeginA, DetourWSALookupServiceBeginA);
		ApplyDetour(requestedAction, TrueWSALookupServiceNextW, DetourWSALookupServiceNextW);
		ApplyDetour(requestedAction, TrueWSALookupServiceNextA, DetourWSALookupServiceNextA);
		ApplyDetour(requestedAction, TrueWSALookupServiceEnd, DetourWSALookupServiceEnd);
	}

	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1) || VariableIsSet(WINPRIV_EV_BREAK_LOCKS, 1))
	{
		ApplyDetour(requestedAction, TrueNtOpenFile, DetourNtOpenFile);
		ApplyDetour(requestedAction, TrueNtCreateFile, DetourNtCreateFile);
	}

	if (VariableIsSet(WINPRIV_EV_ADMIN_IMPERSONATE, 1))
	{
		ApplyDetour(requestedAction, TrueIsUserAnAdmin, DetourIsUserAnAdmin);
		ApplyDetour(requestedAction, TrueCheckTokenMembership, DetourCheckTokenMembership);
	}

	if (VariableIsSet(WINPRIV_EV_SERVER_EDITION, 1))
	{
		ApplyDetour(requestedAction, TrueGetVersionExW, DetourGetVersionExW);
		ApplyDetour(requestedAction, TrueGetVersionExA, DetourGetVersionExA);
		ApplyDetour(requestedAction, TrueVerifyVersionInfoW, DetourVerifyVersionInfoW);
	}

	if (VariableNotEmpty(WINPRIV_EV_RECORD_CRYPTO))
	{
		ApplyDetour(requestedAction, TrueBCryptEncrypt, DetourBCryptEncrypt);
		ApplyDetour(requestedAction, TrueBCryptDecrypt, DetourBCryptDecrypt);
		ApplyDetour(requestedAction, TrueCryptEncrypt, DetourCryptEncrypt);
		ApplyDetour(requestedAction, TrueCryptDecrypt, DetourCryptDecrypt);
		ApplyDetour(requestedAction, TrueRtlEncryptMemory, DetourRtlEncryptMemory);
		ApplyDetour(requestedAction, TrueRtlDecryptMemory, DetourRtlDecryptMemory);
	}

	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		ApplyDetour(requestedAction, TrueSQLDriverConnectA, DetourSQLDriverConnectA);
		ApplyDetour(requestedAction, TrueSQLDriverConnectW, DetourSQLDriverConnectW);
	}

	if (attaching && VariableNotEmpty(WINPRIV_EV_PRIVLIST))
	{
		// tokenize the string using ranges
		std::wstring sPrivString(_wgetenv(WINPRIV_EV_PRIVLIST));
		auto tokens = sPrivString 
			| std::views::split(L',')
			| std::views::transform([](auto&& rng) {
				return std::wstring(std::ranges::begin(rng), std::ranges::end(rng));
			});

		std::vector<std::wstring> vPrivs;
		for (auto&& token : tokens)
		{
			vPrivs.push_back(token);
		}

		// attempt to enable the privileges
		std::vector<std::wstring> tFailedPrivs = EnablePrivs(vPrivs);

		// grant any privileges that cannot be enabled
		if (!tFailedPrivs.empty())
		{
			PrintMessage(L"%s", L"ERROR: Could not enable privileges in subprocess.");
		}
	}

	// special handling for com-based detours
	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		ApplyDetour(requestedAction, TrueCoInitializeEx, DetourCoInitializeEx);
		ApplyDetour(requestedAction, TrueCoInitialize, DetourCoInitialize);
		ApplyDetour(requestedAction, TrueCoCreateInstance, DetourCoCreateInstance);
		ApplyDetour(requestedAction, TrueCoCreateInstanceEx, DetourCoCreateInstanceEx);
		if (!attaching)
		{
#if !defined(_M_X64)
			DllExtraDetachCom();
#endif
		}
	}
}

EXTERN_C LPWSTR SearchReplace(LPCWSTR sInputString, LPCWSTR sSearchString, LPCWSTR sReplaceString)
{
	const std::wstring sInput = sInputString == nullptr ? L"" : sInputString;
	std::wstring sResult;
	if (!TryRegexReplace(sInput, sSearchString, sReplaceString, sResult))
	{
		sResult = sInput;
	}
	return _wcsdup(sResult.c_str());
}
