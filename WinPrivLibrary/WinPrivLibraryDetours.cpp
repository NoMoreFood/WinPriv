//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _WINSOCKAPI_
#include <Windows.h>
#include <winternl.h>
#include <detours.h>
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
#include <VersionHelpers.h>

#define _NTDEF_
#include <NTSecAPI.h>

#include <string>
#include <vector>
#include <regex>
#include <locale>
#include <codecvt>
#include <fstream>
#include <atomic>
#include <regex>

#include "WinPrivShared.h"
#include "WinPrivLibrary.h"

#define sizereq(x,y) (offsetof(x,y) + sizeof(((x*) NULL)->y))
#define align(x,y) ((((uintptr_t) (x)) + (((y)/CHAR_BIT)-1)) & ~(((y)/CHAR_BIT)-1))

#pragma comment(lib,"crypt32.lib")
#pragma comment(lib,"bcrypt.lib")

//   ___         ___     __   __   ___
//  |__  | |    |__     /  \ |__) |__  |\ |
//  |    | |___ |___    \__/ |    |___ | \|
//

bool CloseFileHandle(PUNICODE_STRING sFileNameUnicodeString)
{
	// valid path formats
	static const std::wregex tRegexLocal(LR"(\\\?\?\\(.*))", std::wregex::optimize);
	static const std::wregex tRegexUnc(LR"(\\\?\?\\UNC\\([^\\]+?)\\([^\\]+?)\\(.*))", std::wregex::optimize);

	std::wstring sComputerName;
	std::wstring sPath;

	std::wstring sFileName(sFileNameUnicodeString->Buffer, sFileNameUnicodeString->Length / sizeof(WCHAR));

	// see if the path looks like a unc path
	std::wsmatch tMatches;
	if (std::regex_match(sFileName, tMatches, tRegexUnc))
	{
		// extract the important parts of the regular expression result
		sComputerName = tMatches[1].str();
		const std::wstring sShareName = tMatches[2].str();
		const std::wstring sLocalPath = tMatches[3].str();

		// get the real path name using the computer and share name
		PSHARE_INFO_502 tShareInfo = 0;
		NetShareGetInfo((LPWSTR)sComputerName.c_str(), (LPWSTR)sShareName.c_str(), 502, (LPBYTE*)& tShareInfo);
		bool bNeedsBackslash = tShareInfo->shi502_path[wcslen(tShareInfo->shi502_path) - 1] != L'\\';
		sPath = std::wstring(tShareInfo->shi502_path) + ((bNeedsBackslash) ? L"\\" : L"") + sLocalPath;
		NetApiBufferFree(tShareInfo);
	}

	// see if the path looks like a local path
	else if (std::regex_match(sFileName, tMatches, tRegexLocal))
	{
		wprintf(L"Local Path %s!\r\n", tMatches[1].str().c_str());
		sPath = tMatches[1].str();
	}

	// unrecognized path type
	else
	{
		wprintf(L"Unrecognized Path: %s!\r\n", sFileName.c_str());
		return false;
	}

	// loop through the files matching the path
	DWORD iClosedFiles = 0;
	DWORD iStatus = 0;
	DWORD iEntriesRead = 0;
	DWORD iReturned = 0;
	DWORD_PTR hHandle = 0;
	std::vector<DWORD> tFileIds;
	PFILE_INFO_3 tFileInfo;
	while ((iStatus = NetFileEnum(sComputerName.length() == 0 ? NULL : (LPWSTR)sComputerName.c_str(),
		(LPWSTR)sPath.c_str(), NULL, 3, (LPBYTE*) &tFileInfo,
		MAX_PREFERRED_LENGTH, &iEntriesRead, &iReturned, &hHandle)) == NERR_Success || iStatus == ERROR_MORE_DATA)
	{
		if (iEntriesRead == 0) break;

		// put the files into a vector so we can close them all at once and not
		// interrupt the enumeration operation
		for (DWORD iEntry = 0; iEntry < iEntriesRead; iEntry++)
		{
			tFileIds.push_back(tFileInfo[iEntry].fi3_id);
		}

		NetApiBufferFree(tFileInfo);
	}

	// close the open files
	for (DWORD iFileId : tFileIds)
	{
		if (NetFileClose(sComputerName.length() == 0 ? NULL : (LPWSTR)sComputerName.c_str(),
			iFileId) == NERR_Success)
		{
			iClosedFiles++;
		}
	}

	return iClosedFiles > 0;
}

decltype(&NtOpenFile) TrueNtOpenFile = (decltype(&NtOpenFile))
GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtOpenFile");
decltype(&NtCreateFile) TrueNtCreateFile = (decltype(&NtCreateFile))
GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtCreateFile");

EXTERN_C NTSTATUS NTAPI DetourNtOpenFile(OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess, IN ULONG OpenOptions)
{
	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1))
	{
		OpenOptions |= FILE_OPEN_FOR_BACKUP_INTENT;
	}

	DWORD iStatus = TrueNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, 
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

NTSTATUS(WINAPI * TrueNtQueryValueKey)(_In_ HANDLE KeyHandle, _In_ PUNICODE_STRING ValueName, _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length, _Out_ PULONG ResultLength) = (decltype(TrueNtQueryValueKey))
	GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtQueryValueKey");

EXTERN_C NTSTATUS WINAPI DetourNtQueryValueKey(_In_ HANDLE KeyHandle,
	_In_ PUNICODE_STRING ValueName, _In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	_Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length, _Out_ PULONG ResultLength)
{
	static std::vector<RegInterceptInfo *> * vRegInterceptList = NULL;
	if (vRegInterceptList == NULL)
	{
		// allocate space to hold our list
		vRegInterceptList = new std::vector<RegInterceptInfo *>();

		// parse the parameters to create the intercept list
		int iParams = 0;
		LPWSTR * sParams = CommandLineToArgvW(_wgetenv(WINPRIV_EV_REG_OVERRIDE), &iParams);
		for (int iParam = 0; iParam < iParams; iParam += 4)
		{
			RegInterceptInfo * tInterceptInfo = (RegInterceptInfo *)calloc(1, sizeof(RegInterceptInfo));

			// split the first argument into a root name and subkey name
			LPWSTR sRootKeyName = sParams[iParam];
			LPWSTR sSubKeyName = wcschr(sParams[iParam], L'\\');
			if (sSubKeyName != NULL) *sSubKeyName++ = '\0';

			// match the aesthetic name to the builtin roots
			HKEY hRootKey = NULL;
			if (_wcsicmp(sRootKeyName, L"HKLM") == 0 || _wcsicmp(sRootKeyName, L"HKEY_LOCAL_MACHINE") == 0)
				hRootKey = HKEY_LOCAL_MACHINE;
			else if (_wcsicmp(sRootKeyName, L"HKCU") == 0 || _wcsicmp(sRootKeyName, L"HKEY_CURRENT_USER") == 0)
				hRootKey = HKEY_CURRENT_USER;
			else if (_wcsicmp(sRootKeyName, L"HKCR") == 0 || _wcsicmp(sRootKeyName, L"HKEY_CLASSES_ROOT") == 0)
				hRootKey = HKEY_CLASSES_ROOT;
			else if (_wcsicmp(sRootKeyName, L"HKU") == 0 || _wcsicmp(sRootKeyName, L"HKEY_USERS") == 0)
				hRootKey = HKEY_USERS;
			else break;

			// lookup the real key name after all redirection has been done
			HKEY hKey;
			if (RegOpenKeyEx(hRootKey, sSubKeyName, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
			{
				DWORD iSize;
				if (NtQueryKey(hKey, KeyNameInformation, NULL, 0, &iSize) == STATUS_BUFFER_TOO_SMALL)
				{
					PKEY_NAME_INFORMATION pNameInfo = (PKEY_NAME_INFORMATION)malloc(iSize);
					if (NtQueryKey(hKey, KeyNameInformation, pNameInfo, iSize, &iSize) == STATUS_SUCCESS)
					{
						tInterceptInfo->RegKeyName = { (USHORT)pNameInfo->NameLength,
							(USHORT)pNameInfo->NameLength, pNameInfo->Name };
					}
				}
				CloseHandle(hKey);
			}

			// verify key name lookup succeeded
			if (tInterceptInfo->RegKeyName.Length == NULL) break;

			// fetch value name
			LPWSTR sValueName = sParams[iParam + 1];
			tInterceptInfo->RegValueName = { (USHORT)wcslen(sValueName) * sizeof(WCHAR),
				(USHORT)wcslen(sValueName) * sizeof(WCHAR), _wcsdup(sValueName) };

			// match the aesthetic types to the typed enumerations
			LPWSTR sType = sParams[iParam + 2];
			if (_wcsicmp(sType, L"REG_DWORD") == 0) tInterceptInfo->RegValueType = REG_DWORD;
			else if (_wcsicmp(sType, L"REG_QWORD") == 0) tInterceptInfo->RegValueType = REG_QWORD;
			else if (_wcsicmp(sType, L"REG_SZ") == 0) tInterceptInfo->RegValueType = REG_SZ;
			else if (_wcsicmp(sType, L"REG_BINARY") == 0) tInterceptInfo->RegValueType = REG_BINARY;
			else if (_wcsicmp(sType, L"REG_BLOCK") == 0) tInterceptInfo->RegValueType = -1;
			else break;

			// decode the value string to a data blob
			LPWSTR sData = sParams[iParam + 3];
			if (tInterceptInfo->RegValueType == REG_DWORD)
			{
				tInterceptInfo->RegValueData = (DWORD *)malloc(sizeof(DWORD));
				swscanf(sData, L"%li", (DWORD *)tInterceptInfo->RegValueData);
				tInterceptInfo->RegValueDataSize = sizeof(DWORD);
			}
			else if (tInterceptInfo->RegValueType == REG_QWORD)
			{
				tInterceptInfo->RegValueData = (unsigned __int64 *)malloc(sizeof(unsigned __int64));
				swscanf(sData, L"%lli", (unsigned __int64 *)tInterceptInfo->RegValueData);
				tInterceptInfo->RegValueDataSize = sizeof(unsigned __int64);
			}
			else if (tInterceptInfo->RegValueType == REG_SZ)
			{
				tInterceptInfo->RegValueData = _wcsdup(sData);
				tInterceptInfo->RegValueDataSize = (DWORD)wcslen(sData) * sizeof(WCHAR);
			}
			else if (tInterceptInfo->RegValueType == REG_BINARY)
			{
				tInterceptInfo->RegValueData = malloc(wcslen(sData) / 2);
				for (size_t iChar = 0; iChar < wcslen(sData) / 2; iChar++)
					swscanf(&sData[iChar*2], L"%02hhX", &(((PBYTE)tInterceptInfo->RegValueData)[iChar]));
				tInterceptInfo->RegValueDataSize = (DWORD) (wcslen(sData) / 2);
			}
			else if (tInterceptInfo->RegValueType == -1)
			{
				tInterceptInfo->RegValueData = NULL;
				tInterceptInfo->RegValueDataSize = 0;
			}
			else break;

			// fully processed entry - continue
			vRegInterceptList->push_back(tInterceptInfo);
		}
		LocalFree(sParams);
	}

	// sanity check
	if (ResultLength == NULL)
	{
		return STATUS_INVALID_PARAMETER;
	}

	// lookup the size for the key name so we can allocate space for it
	DWORD iKeyNameSize;
	if (NtQueryKey(KeyHandle, KeyNameInformation, NULL, 0, &iKeyNameSize) != STATUS_BUFFER_TOO_SMALL)
	{
		// should never happen
		return STATUS_INVALID_PARAMETER;
	}

	// allocate space for name and lookup
	NTSTATUS iStatus = -1;
	PKEY_NAME_INFORMATION pNameInfo = (PKEY_NAME_INFORMATION)malloc(iKeyNameSize);
	if (pNameInfo != NULL && NtQueryKey(KeyHandle, KeyNameInformation, pNameInfo,
		iKeyNameSize, &iKeyNameSize) == STATUS_SUCCESS)
	{
		// convert to unicode string structure for quick comparisons
		UNICODE_STRING sKeyName = { (USHORT)pNameInfo->NameLength,
			(USHORT)pNameInfo->NameLength, pNameInfo->Name };

		for (RegInterceptInfo * tRegOverrideInfo : *vRegInterceptList)
		{
			// handle registry block
			if (UnicodeStringPrefix(&tRegOverrideInfo->RegKeyName, &sKeyName) &&
				tRegOverrideInfo->RegValueType == -1)
			{
				*ResultLength = 0;
				iStatus = STATUS_OBJECT_NAME_NOT_FOUND;
				break;
			}

			// handle registry override
			if (UnicodeStringsEqual(&tRegOverrideInfo->RegKeyName, &sKeyName) &&
				UnicodeStringsEqual(&tRegOverrideInfo->RegValueName, ValueName))
			{
				if (KeyValueInformationClass == KeyValueFullInformation ||
					KeyValueInformationClass == KeyValueFullInformationAlign64)
				{
					const UINT_PTR alignment = (KeyValueInformationClass == KeyValueFullInformation) ? 32 : 64;
					iStatus = Length >= sizeof(ULONG) ? STATUS_BUFFER_OVERFLOW : STATUS_BUFFER_TOO_SMALL;
					*ResultLength = (ULONG)align(offsetof(KEY_VALUE_FULL_INFORMATION, Name) +
						tRegOverrideInfo->RegValueName.Length + tRegOverrideInfo->RegValueDataSize, alignment);

					PKEY_VALUE_FULL_INFORMATION tKeyInfo = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;

					if (sizereq(KEY_VALUE_FULL_INFORMATION, TitleIndex) <= Length)
					{
						tKeyInfo->TitleIndex = 0;
					}
					if (sizereq(KEY_VALUE_FULL_INFORMATION, Type) <= Length)
					{
						tKeyInfo->Type = tRegOverrideInfo->RegValueType;
					}
					if (sizereq(KEY_VALUE_FULL_INFORMATION, NameLength) <= Length)
					{
						tKeyInfo->NameLength = tRegOverrideInfo->RegValueName.Length;
					}
					if (sizereq(KEY_VALUE_FULL_INFORMATION, DataLength) <= Length)
					{
						tKeyInfo->DataLength = tRegOverrideInfo->RegValueDataSize;
					}

					// copy name payload
					const ULONG iNameRequiredSize = (ULONG)offsetof(KEY_VALUE_FULL_INFORMATION, Name) + tKeyInfo->NameLength;
					if (iNameRequiredSize <= Length)
					{
						memcpy(tKeyInfo->Name, tRegOverrideInfo->RegValueName.Buffer, tKeyInfo->NameLength);
					}

					// copy data payload
					const ULONG iDataRequiredSize = (ULONG)align(iNameRequiredSize + tKeyInfo->DataLength, alignment);
					if (iDataRequiredSize <= Length)
					{
						tKeyInfo->DataOffset = (ULONG)align(iNameRequiredSize, alignment);
						LPVOID pData = (LPVOID)align(((LPBYTE)KeyValueInformation + tKeyInfo->DataOffset), alignment);
						memcpy(pData, tRegOverrideInfo->RegValueData, tKeyInfo->DataLength);
						iStatus = STATUS_SUCCESS;
					}
				}
				else if (KeyValueInformationClass == KeyValuePartialInformation ||
					KeyValueInformationClass == KeyValuePartialInformationAlign64)
				{
					// calculate required size and set default status
					const UINT_PTR alignment = (KeyValueInformationClass == KeyValuePartialInformation) ? 32 : 64;
					iStatus = Length >= sizeof(ULONG) ? STATUS_BUFFER_OVERFLOW : STATUS_BUFFER_TOO_SMALL;
					*ResultLength = (ULONG)align(offsetof(KEY_VALUE_PARTIAL_INFORMATION, Data) +
						tRegOverrideInfo->RegValueDataSize, alignment);

					PKEY_VALUE_PARTIAL_INFORMATION tKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;

					if (sizereq(KEY_VALUE_PARTIAL_INFORMATION, TitleIndex) <= Length)
					{
						tKeyInfo->TitleIndex = 0;
					}
					if (sizereq(KEY_VALUE_PARTIAL_INFORMATION, Type) <= Length)
					{
						tKeyInfo->Type = tRegOverrideInfo->RegValueType;
					}
					if (sizereq(KEY_VALUE_PARTIAL_INFORMATION, DataLength) <= Length)
					{
						tKeyInfo->DataLength = tRegOverrideInfo->RegValueDataSize;
					}

					// copy data payload
					if (*ResultLength <= Length)
					{
						memcpy((PVOID)align(tKeyInfo->Data, alignment),
							tRegOverrideInfo->RegValueData, tKeyInfo->DataLength);
						iStatus = STATUS_SUCCESS;
					}
				}
			}
		}
	}

	// cleanup
	if (pNameInfo != NULL) free(pNameInfo);

	// return the real value if no match was found
	if (iStatus == -1)
	{
		iStatus = TrueNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
			KeyValueInformation, Length, ResultLength);
	}

	return iStatus;
}

NTSTATUS(WINAPI * TrueNtEnumerateValueKey)(_In_ HANDLE KeyHandle, _In_ ULONG Index,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, _Out_opt_ PVOID KeyValueInformation,
	_In_ ULONG Length, _Out_ PULONG ResultLength) = (decltype(TrueNtEnumerateValueKey))
	GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtEnumerateValueKey");

EXTERN_C NTSTATUS WINAPI DetourNtEnumerateValueKey(_In_ HANDLE KeyHandle, _In_ ULONG Index,
	_In_ KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, _Out_opt_ PVOID KeyValueInformation,
	_In_ ULONG Length, _Out_ PULONG ResultLength)
{
	NTSTATUS iStatus = TrueNtEnumerateValueKey(KeyHandle, Index,
		KeyValueInformationClass, KeyValueInformation, Length, ResultLength);

	if (iStatus == STATUS_SUCCESS && KeyValueInformation != NULL &&
		(KeyValueInformationClass == KeyValueFullInformation ||
			KeyValueInformationClass == KeyValueFullInformationAlign64))
	{
		PKEY_VALUE_FULL_INFORMATION tKeyInfo = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;
		UNICODE_STRING sValue = { (USHORT)tKeyInfo->NameLength, (USHORT)tKeyInfo->NameLength, tKeyInfo->Name };
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

VOID(NTAPI * TrueRtlExitUserProcess)(_In_ NTSTATUS 	ExitStatus) =
(decltype(TrueRtlExitUserProcess))GetProcAddress(LoadLibrary(L"ntdll.dll"), "RtlExitUserProcess");

DECLSPEC_NORETURN EXTERN_C VOID NTAPI DetourRtlExitUserProcess(_In_ NTSTATUS ExitStatus)
{
	if (GetConsoleWindow() != NULL && VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		wprintf(L"\n\nWinPriv target process has finished execution. Please any key to exit this window.\n");
		(void) _getch();
	}

	TrueRtlExitUserProcess(ExitStatus);
}

//              __           __   __   __   ___  __   __
//   |\/|  /\  /  `     /\  |  \ |  \ |__) |__  /__` /__`
//   |  | /~~\ \__,    /~~\ |__/ |__/ |  \ |___ .__/ .__/
//

decltype(&NetWkstaTransportEnum) TrueNetWkstaTransportEnum = NetWkstaTransportEnum;

EXTERN_C NET_API_STATUS NET_API_FUNCTION DetourNetWkstaTransportEnum(
	_In_opt_ LPTSTR servername, _In_ DWORD level, LPBYTE *bufptr, _In_ DWORD prefmaxlen,
	_Out_ LPDWORD entriesread, _Out_ LPDWORD totalentries, _Inout_opt_ LPDWORD resume_handle)
{
	NET_API_STATUS iRet = TrueNetWkstaTransportEnum(servername, level,
		bufptr, prefmaxlen, entriesread, totalentries, resume_handle);

	if (level == 0 && (iRet == NERR_Success || iRet == NERR_BufTooSmall || iRet == ERROR_MORE_DATA))
	{
		PWKSTA_TRANSPORT_INFO_0 tInfo = (PWKSTA_TRANSPORT_INFO_0)*bufptr;
		for (DWORD iEntry = 0; iEntry < *entriesread; iEntry++)
		{
			wcscpy(tInfo[iEntry].wkti0_transport_address, _wgetenv(WINPRIV_EV_MAC_OVERRIDE));
		}
	}

	return iRet;
}

decltype(&GetAdaptersInfo) TrueGetAdaptersInfo = GetAdaptersInfo;

ULONG WINAPI DetourGetAdaptersInfo(_Out_ PIP_ADAPTER_INFO AdapterInfo, _Inout_ PULONG SizePointer)
{
	ULONG iRet = TrueGetAdaptersInfo(AdapterInfo, SizePointer);

	// return immediately upon error
	if (iRet != ERROR_SUCCESS) return iRet;

	// enumerate each adapter and replace the max data
	for (PIP_ADAPTER_INFO pInfo = AdapterInfo; pInfo != NULL; pInfo = pInfo->Next)
	{
		LPWSTR sAddressString = _wgetenv(WINPRIV_EV_MAC_OVERRIDE);
		for (size_t iByte = 0; iByte < wcslen(sAddressString) / 2 &&
			iByte < MAX_ADAPTER_ADDRESS_LENGTH; iByte++)
		{
			swscanf(&sAddressString[iByte * 2], L"%2hhx", &pInfo->Address[iByte]);
			pInfo->AddressLength = (UINT)(iByte + 1);
		}
	}

	return iRet;
}

decltype(&GetAdaptersAddresses) TrueGetAdaptersAddresses = GetAdaptersAddresses;

ULONG WINAPI DetourGetAdaptersAddresses(_In_ ULONG Family, _In_ ULONG Flags, _Reserved_ PVOID Reserved,
	_Out_ PIP_ADAPTER_ADDRESSES AdapterAddresses, _Inout_ PULONG SizePointer)
{
	ULONG iRet = TrueGetAdaptersAddresses(Family, Flags,
		Reserved, AdapterAddresses, SizePointer);

	// return immediately upon error
	if (iRet != ERROR_SUCCESS) return iRet;

	// enumerate each adapter and replace the max data
	for (PIP_ADAPTER_ADDRESSES pInfo = AdapterAddresses; pInfo != NULL; pInfo = pInfo->Next)
	{
		LPWSTR sAddressString = _wgetenv(WINPRIV_EV_MAC_OVERRIDE);
		for (size_t iByte = 0; iByte < wcslen(sAddressString) / 2 &&
			iByte < MAX_ADAPTER_ADDRESS_LENGTH; iByte++)
		{
			swscanf(&sAddressString[iByte * 2], L"%2hhx", &pInfo->PhysicalAddress[iByte]);
			pInfo->PhysicalAddressLength = (ULONG)(iByte + 1);
		}
	}

	return iRet;
}

//        __   __  ___     __        ___  __   __     __   ___
//  |__| /  \ /__`  |     /  \ \  / |__  |__) |__) | |  \ |__
//  |  | \__/ .__/  |     \__/  \/  |___ |  \ |  \ | |__/ |___
//
// 

void UpdateIpAddress(_In_ LPCWSTR sName, _Inout_ LPSOCKADDR tSockToUpdate)
{
	static INT iHostOverrideParams = 0;
	static LPWSTR * sHostOverride = CommandLineToArgvW(_wgetenv(WINPRIV_EV_HOST_OVERRIDE), &iHostOverrideParams);

	// parse the parameters to create the intercept list
	for (int iParam = 0; iParam < iHostOverrideParams; iParam += 2)
	{
		if (_wcsicmp(sName, sHostOverride[iParam]) != 0) continue;

		IN_ADDR tReplace;
		LPCWSTR sTerm = NULL;
		RtlIpv4StringToAddressW(sHostOverride[iParam + 1], TRUE, &sTerm, &tReplace);

		if (tSockToUpdate->sa_family == AF_INET6)
		{
			SOCKADDR_IN6 * pAddr = (SOCKADDR_IN6 *)tSockToUpdate;
			IN6_SET_ADDR_V4MAPPED((PIN6_ADDR) &(pAddr->sin6_addr), &tReplace);
		}
		else if (tSockToUpdate->sa_family == AF_INET)
		{
			SOCKADDR_IN * pAddr = (SOCKADDR_IN *)tSockToUpdate;
			memcpy(&(pAddr->sin_addr), &tReplace, sizeof(IN_ADDR));
		}
	}
}

decltype(&WSALookupServiceNextW) TrueWSALookupServiceNextW = WSALookupServiceNextW;

INT WSAAPI DetourWSALookupServiceNextW(_In_ HANDLE hLookup, _In_ DWORD dwControlFlags,
	_Inout_ LPDWORD lpdwBufferLength, _Out_ LPWSAQUERYSETW lpqsResults)
{
	// call the real lookup function and return immediately if failed
	INT iRet = TrueWSALookupServiceNextW(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
	if (iRet == -1 || lpqsResults->dwNumberOfCsAddrs == 0) return iRet;

	//  inspect the packet and update the address
	UpdateIpAddress(lpqsResults->lpszServiceInstanceName,
		((PCSADDR_INFO)lpqsResults->lpcsaBuffer)->RemoteAddr.lpSockaddr);

	return iRet;
}

decltype(&WSALookupServiceNextA) TrueWSALookupServiceNextA = WSALookupServiceNextA;

INT WSAAPI DetourWSALookupServiceNextA(_In_ HANDLE hLookup, _In_ DWORD dwControlFlags,
	_Inout_ LPDWORD lpdwBufferLength, _Out_ LPWSAQUERYSETA lpqsResults)
{
	// call the real lookup function and return immediately if failed
	INT iRet = TrueWSALookupServiceNextA(hLookup, dwControlFlags, lpdwBufferLength, lpqsResults);
	if (iRet == -1 || lpqsResults->dwNumberOfCsAddrs == 0) return iRet;

	// inspect the packet and update the address
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> tConverter;
	std::wstring sQueryNameWide = tConverter.from_bytes(lpqsResults->lpszServiceInstanceName);
	UpdateIpAddress(sQueryNameWide.c_str(),
		((PCSADDR_INFO)lpqsResults->lpcsaBuffer)->RemoteAddr.lpSockaddr);

	return iRet;
}

//        __                           __   ___  __   __   __            ___  ___ 
//   /\  |  \  |\/| | |\ |    |  |\/| |__) |__  |__) /__` /  \ |\ |  /\   |  |__  
//  /~~\ |__/  |  | | | \|    |  |  | |    |___ |  \ .__/ \__/ | \| /~~\  |  |___ 
//     

decltype(&IsUserAnAdmin) TrueIsUserAnAdmin = IsUserAnAdmin;

BOOL __stdcall DetourIsUserAnAdmin()
{
	return TRUE;
}

decltype(&CheckTokenMembership) TrueCheckTokenMembership = CheckTokenMembership;

BOOL APIENTRY DetourCheckTokenMembership(_In_opt_ HANDLE TokenHandle, 
	_In_ PSID SidToCheck, _Out_ PBOOL IsMember)
{
	// fetch and allocate the local admin structure
	static SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	static PSID LocalAdministratorsGroup = NULL;
	AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &LocalAdministratorsGroup);

	// get the real value of the function - return if failure 
	BOOL bRealResult = TrueCheckTokenMembership(TokenHandle, SidToCheck, IsMember);
	if (bRealResult == 0) return bRealResult;

	// check if the local admin group is being requested
	if (EqualSid(SidToCheck, LocalAdministratorsGroup))
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

decltype(&GetVersionExW) TrueGetVersionExW = GetVersionExW;

BOOL WINAPI DetourGetVersionExW(_Inout_ LPOSVERSIONINFOW lpVersionInformation)
{
	BOOL bResult = TrueGetVersionExW(lpVersionInformation);
	if (bResult == 0) return bResult;
	
	if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXW))
	{
		LPOSVERSIONINFOEXW pVersionInfo = (LPOSVERSIONINFOEXW) lpVersionInformation;
		pVersionInfo->wProductType |= VER_NT_SERVER;
		pVersionInfo->wProductType &= ~VER_NT_WORKSTATION;
	}

	return bResult;
}

decltype(&GetVersionExA) TrueGetVersionExA = GetVersionExA;

BOOL WINAPI DetourGetVersionExA(_Inout_ LPOSVERSIONINFOA lpVersionInformation)
{
	BOOL bResult = TrueGetVersionExA(lpVersionInformation);
	if (bResult == 0) return bResult;

	if (lpVersionInformation->dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXA))
	{
		LPOSVERSIONINFOEXA pVersionInfo = (LPOSVERSIONINFOEXA)lpVersionInformation;
		pVersionInfo->wProductType |= VER_NT_SERVER;
		pVersionInfo->wProductType &= ~VER_NT_WORKSTATION;
	}

	return bResult;
}

decltype(&VerifyVersionInfoW) TrueVerifyVersionInfoW = VerifyVersionInfoW;

BOOL WINAPI DetourVerifyVersionInfoW(_Inout_ LPOSVERSIONINFOEXW lpVersionInformation, _In_ DWORD dwTypeMask, _In_ DWORDLONG dwlConditionMask)
{
	if (dwTypeMask == VER_PRODUCT_TYPE)
	{
		// quit early if actually running on a server
		OSVERSIONINFOEXW tInfo;
		tInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		TrueGetVersionExW((LPOSVERSIONINFOW) &tInfo);
		if ((tInfo.wProductType & VER_NT_WORKSTATION) == 0)
		{
			return TrueVerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask);
		}

		// if we are testing for workstation, then just change the comparison value
		// so the test actually fails, indicating it is not a workstation  
		LPOSVERSIONINFOEXW pVersionInfo = (LPOSVERSIONINFOEXW)lpVersionInformation;
		if (pVersionInfo->wProductType == VER_NT_WORKSTATION)
		{
			pVersionInfo->wProductType = VER_NT_SERVER;
		}

		// if we are testing for server and we actually are a workstation then just
		// change the test such that it tests for a workstation so call will succeed 
		// and the caller will believe the system is a server
		else if (pVersionInfo->wProductType == VER_NT_SERVER)
		{
			pVersionInfo->wProductType = VER_NT_WORKSTATION;
		}
	}

	return TrueVerifyVersionInfoW(lpVersionInformation, dwTypeMask, dwlConditionMask);
}

//   __   __       __  ___  __      __   ___       __  
//  /  ` |__) \ / |__)  |  /  \    |__) |__   /\  |  \ 
//  \__, |  \  |  |     |  \__/    |  \ |___ /~~\ |__/ 
//                                                     

std::wstring IntToString(int iValue, int iPadding = 5)
{
	std::wstring sValue = std::to_wstring(iValue);
	return std::wstring(iPadding - sValue.length(), '0') + sValue;
}

void RecordCryptoData(LPCWSTR sFunction, PUCHAR pData, DWORD iDataLen)
{
	// remove 'Detour' from the function name
	sFunction = &sFunction[wcslen(L"Detour")];

	// decide whether to output to console or file system
	LPWSTR sCryptoValue = _wgetenv(WINPRIV_EV_RECORD_CRYPTO);
	if (_wcsicmp(sCryptoValue, L"SHOW") == 0)
	{
		if (IsTextUnicode(pData, iDataLen, NULL))
		{
			PrintMessage(L"Function: %s\nGuessed Encoding: %s\nLength In Bytes: %d\nData:%.*s\n", 
				sFunction, L"Unicode", iDataLen, (int) (iDataLen / sizeof(WCHAR)), (LPWSTR) pData);
		}
		else
		{
			PrintMessage(L"Function: %s\nGuessed Encoding: %s\nLength In Bytes: %d\nData:%.*S\n", 
				sFunction, L"Multibyte", iDataLen, (int) iDataLen, pData);
		}
	}
	else
	{
		// formulate the file name to write to
		static std::atomic<int> iOrder = 0;
		std::wstring sFilePath = std::wstring(sCryptoValue) + L"\\" + IntToString(iOrder++) + L"-PID"
			+ IntToString(GetCurrentProcessId()) + L"-TID" + IntToString(GetCurrentThreadId())
			+ L"-" + sFunction + L".bin";

		// create the crypto data file
		HANDLE hFile = CreateFile(sFilePath.c_str(), GENERIC_ALL, FILE_SHARE_WRITE,
			NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)
		{
			PrintMessage(L"ERROR: Problem opening crypto data file.\n");
			return;
		}

		// write the crypto data to the file
		DWORD iSizeWritten = 0;
		if (WriteFile(hFile, pData, iDataLen, &iSizeWritten, NULL) == 0)
		{
			PrintMessage(L"ERROR: Problem writing crypto data file.\n");
			CloseHandle(hFile);
			return;
		}

		// close the crypto data file
		if (CloseHandle(hFile) == 0)
		{
			PrintMessage(L"ERROR: Problem closing crypto data file.\n");
			return;
		}
	}
}

decltype(&BCryptEncrypt) TrueBCryptEncrypt = BCryptEncrypt;

NTSTATUS WINAPI DetourBCryptEncrypt(_Inout_ BCRYPT_KEY_HANDLE hKey, _In_reads_bytes_opt_(cbInput) PUCHAR pbInput, _In_ ULONG cbInput, _In_opt_ VOID *pPaddingInfo, _Inout_updates_bytes_opt_(cbIV) PUCHAR pbIV, _In_ ULONG cbIV, _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput, _In_ ULONG cbOutput, _Out_ ULONG *pcbResult, _In_ ULONG dwFlags)
{
	RecordCryptoData(__FUNCTIONW__, pbInput, cbInput);
	return TrueBCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
}

decltype(&BCryptDecrypt) TrueBCryptDecrypt = BCryptDecrypt;

NTSTATUS WINAPI DetourBCryptDecrypt(_Inout_ BCRYPT_KEY_HANDLE hKey, _In_reads_bytes_opt_(cbInput) PUCHAR pbInput, _In_ ULONG cbInput, _In_opt_ VOID *pPaddingInfo, _Inout_updates_bytes_opt_(cbIV) PUCHAR pbIV, _In_ ULONG cbIV, _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PUCHAR pbOutput, _In_ ULONG cbOutput, _Out_ ULONG *pcbResult, _In_ ULONG dwFlags)
{
	NTSTATUS iResult = TrueBCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo, pbIV, cbIV, pbOutput, cbOutput, pcbResult, dwFlags);
	if (iResult == STATUS_SUCCESS) RecordCryptoData(__FUNCTIONW__, pbInput, cbInput);
	return iResult;
}

decltype(&CryptEncrypt) TrueCryptEncrypt = CryptEncrypt;

BOOL WINAPI DetourCryptEncrypt(_In_ HCRYPTKEY hKey, _In_ HCRYPTHASH  hHash, _In_ BOOL Final, _In_ DWORD dwFlags, _Inout_updates_bytes_to_opt_(dwBufLen, *pdwDataLen) BYTE *pbData, _Inout_ DWORD *pdwDataLen, _In_ DWORD dwBufLen)
{
	RecordCryptoData(__FUNCTIONW__, pbData, *pdwDataLen);
	return TrueCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

decltype(&CryptDecrypt) TrueCryptDecrypt = CryptDecrypt;

BOOL WINAPI DetourCryptDecrypt(_In_ HCRYPTKEY hKey, _In_ HCRYPTHASH hHash, _In_ BOOL Final, _In_ DWORD dwFlags, _Inout_updates_bytes_to_(*pdwDataLen, *pdwDataLen) BYTE *pbData, _Inout_ DWORD *pdwDataLen)
{
	BOOL iResult = TrueCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
	if (iResult == TRUE) RecordCryptoData(__FUNCTIONW__, pbData, *pdwDataLen);
	return iResult;
}

decltype(&RtlEncryptMemory) TrueRtlEncryptMemory = RtlEncryptMemory;

NTSTATUS __stdcall DetourRtlEncryptMemory(_Inout_updates_bytes_(MemorySize) PVOID Memory, _In_ ULONG MemorySize, _In_ ULONG OptionFlag)
{
	RecordCryptoData(__FUNCTIONW__, (PUCHAR)Memory, MemorySize);
	return TrueRtlEncryptMemory(Memory, MemorySize, OptionFlag);
}

decltype(&RtlDecryptMemory) TrueRtlDecryptMemory = RtlDecryptMemory;

NTSTATUS __stdcall DetourRtlDecryptMemory(_Inout_updates_bytes_(MemorySize) PVOID Memory, _In_ ULONG MemorySize, _In_ ULONG OptionFlags)
{
	NTSTATUS iResult = TrueRtlDecryptMemory(Memory, MemorySize, OptionFlags);
	if (iResult == STATUS_SUCCESS) RecordCryptoData(__FUNCTIONW__, (PUCHAR) Memory, MemorySize);
	return iResult;
}

//   __   __           __   __             ___  __  ___ 
//  /__` /  \ |       /  ` /  \ |\ | |\ | |__  /  `  |  
//  .__/ \__X |___    \__, \__/ | \| | \| |___ \__,  |  
//                                                      

decltype(&SQLDriverConnectA) TrueSQLDriverConnectA = SQLDriverConnectA;

SQLRETURN SQL_API DetourSQLDriverConnectA(SQLHDBC hdbc, SQLHWND hwnd, _In_reads_(cbConnStrIn) SQLCHAR *szConnStrIn,
	SQLSMALLINT cbConnStrIn, _Out_writes_opt_(cbConnStrOutMax) SQLCHAR *szConnStrOut, SQLSMALLINT cbConnStrOutMax,
	_Out_opt_ SQLSMALLINT *pcbConnStrOut, SQLUSMALLINT fDriverCompletion)
{
	// internally, the ansi function is routed through the wide character function
	// so we do not need to add any handling logic here
	return TrueSQLDriverConnectA(hdbc, hwnd, szConnStrIn, cbConnStrIn, szConnStrOut,
		cbConnStrOutMax, pcbConnStrOut, fDriverCompletion);
}

decltype(&SQLDriverConnectW) TrueSQLDriverConnectW = SQLDriverConnectW;

SQLRETURN SQL_API DetourSQLDriverConnectW(SQLHDBC hdbc, SQLHWND hwnd, _In_reads_(cchConnStrIn) SQLWCHAR* szConnStrIn,
	SQLSMALLINT cchConnStrIn, _Out_writes_opt_(cchConnStrOutMax) SQLWCHAR* szConnStrOut, SQLSMALLINT cchConnStrOutMax,
	_Out_opt_ SQLSMALLINT* pcchConnStrOut, SQLUSMALLINT fDriverCompletion)
{
	// handle search and replace
	if (VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		// do search replace and create a new string from the result
		std::wstring sPassedConnection((LPWSTR)szConnStrIn, (cchConnStrIn == SQL_NTS) ? wcslen(szConnStrIn) : cchConnStrIn);
		std::wstring sModifiedConnection = std::regex_replace(sPassedConnection,
			std::wregex(_wgetenv(WINPRIV_EV_SQL_CONNECT_SEARCH)), _wgetenv(WINPRIV_EV_SQL_CONNECT_REPLACE));
		szConnStrIn = _wcsdup(sModifiedConnection.c_str());
		cchConnStrIn = SQL_NTS;
	}
	
	// handle show or complete replacement
	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1))
	{
		// decide whether to simply show the sql connection string or replace it
		std::wstring sPassedConnection((LPWSTR)szConnStrIn, (cchConnStrIn == SQL_NTS) ? wcslen(szConnStrIn) : cchConnStrIn);
		PrintMessage(L"SQL Connection String: %s", sPassedConnection.c_str());
	}

	return TrueSQLDriverConnectW(hdbc, hwnd, szConnStrIn, cchConnStrIn, szConnStrOut,
		cchConnStrOutMax, pcchConnStrOut, fDriverCompletion);
}

//   __   __            __   ___ ___  __        __   __  
//  /  ` /  \  |\/|    |  \ |__   |  /  \ |  | |__) /__` 
//  \__, \__/  |  |    |__/ |___  |  \__/ \__/ |  \ .__/ 
//  

EXTERN_C VOID WINAPI DllExtraAttachDetachCom(BOOL bAttach);
static bool bComDetoursNeedToBeInitialized = true;

decltype(&CoInitializeEx) TrueCoInitializeEx = CoInitializeEx;

EXTERN_C HRESULT STDAPICALLTYPE DetourCoInitializeEx(_In_opt_ LPVOID pvReserved, _In_ DWORD dwCoInit)
{
	HRESULT iResult = TrueCoInitializeEx(pvReserved, dwCoInit);
	if ((iResult == S_OK || iResult == S_FALSE) && bComDetoursNeedToBeInitialized)
	{
		// attach com-based detours
		bComDetoursNeedToBeInitialized = false;
		DllExtraAttachDetachCom(TRUE);
	}
	return iResult;
}

decltype(&CoInitialize) TrueCoInitialize = CoInitialize;

EXTERN_C HRESULT STDAPICALLTYPE DetourCoInitialize(_In_opt_ LPVOID pvReserved)
{
	HRESULT iResult = TrueCoInitialize(pvReserved);
	if ((iResult == S_OK || iResult == S_FALSE) && bComDetoursNeedToBeInitialized)
	{
		// attach com-based detours
		bComDetoursNeedToBeInitialized = false;
		DllExtraAttachDetachCom(TRUE);
	}
	return iResult;
}

//   __   ___ ___  __        __   __                           __   ___        ___      ___
//  |  \ |__   |  /  \ |  | |__) /__`     |\/|  /\  |\ |  /\  / _` |__   |\/| |__  |\ |  |
//  |__/ |___  |  \__/ \__/ |  \ .__/     |  | /~~\ | \| /~~\ \__> |___  |  | |___ | \|  |
//

EXTERN_C VOID WINAPI DllExtraAttachDetach(bool bAttach)
{
	decltype(&DetourAttach) AttachDetach = (bAttach) ? DetourAttach : DetourDetach;

	if (VariableIsSet(WINPRIV_EV_PARENT_PID, GetCurrentProcessId()))
	{
		return;
	}

	if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		AttachDetach(&(PVOID&)TrueRtlExitUserProcess, DetourRtlExitUserProcess);
	}

	if (VariableNotEmpty(WINPRIV_EV_MAC_OVERRIDE))
	{
		AttachDetach(&(PVOID&)TrueNetWkstaTransportEnum, DetourNetWkstaTransportEnum);
		AttachDetach(&(PVOID&)TrueGetAdaptersInfo, DetourGetAdaptersInfo);
		AttachDetach(&(PVOID&)TrueGetAdaptersAddresses, DetourGetAdaptersAddresses);
	}

	if (VariableNotEmpty(WINPRIV_EV_REG_OVERRIDE))
	{
		AttachDetach(&(PVOID&)TrueNtQueryValueKey, DetourNtQueryValueKey);
		AttachDetach(&(PVOID&)TrueNtEnumerateValueKey, DetourNtEnumerateValueKey);
	}

	if (VariableNotEmpty(WINPRIV_EV_HOST_OVERRIDE))
	{
		AttachDetach(&(PVOID&)TrueWSALookupServiceNextW, DetourWSALookupServiceNextW);
		AttachDetach(&(PVOID&)TrueWSALookupServiceNextA, DetourWSALookupServiceNextA);
	}

	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1) || VariableIsSet(WINPRIV_EV_BREAK_LOCKS, 1))
	{
		AttachDetach(&(PVOID&)TrueNtOpenFile, DetourNtOpenFile);
		AttachDetach(&(PVOID&)TrueNtCreateFile, DetourNtCreateFile);
	}

	if (VariableIsSet(WINPRIV_EV_ADMIN_IMPERSONATE, 1))
	{
		AttachDetach(&(PVOID&)TrueIsUserAnAdmin, DetourIsUserAnAdmin);
		AttachDetach(&(PVOID&)TrueCheckTokenMembership, DetourCheckTokenMembership);
	}

	if (VariableIsSet(WINPRIV_EV_SERVER_EDITION, 1))
	{
		AttachDetach(&(PVOID&)TrueGetVersionExW, DetourGetVersionExW);
		AttachDetach(&(PVOID&)TrueGetVersionExA, DetourGetVersionExA);
		AttachDetach(&(PVOID&)TrueVerifyVersionInfoW, DetourVerifyVersionInfoW);
	}

	if (VariableNotEmpty(WINPRIV_EV_RECORD_CRYPTO))
	{
		AttachDetach(&(PVOID&)TrueBCryptEncrypt, DetourBCryptEncrypt);
		AttachDetach(&(PVOID&)TrueBCryptDecrypt, DetourBCryptDecrypt);
		AttachDetach(&(PVOID&)TrueCryptEncrypt, DetourCryptEncrypt);
		AttachDetach(&(PVOID&)TrueCryptDecrypt, DetourCryptDecrypt);
		AttachDetach(&(PVOID&)TrueRtlEncryptMemory, DetourRtlEncryptMemory);
		AttachDetach(&(PVOID&)TrueRtlDecryptMemory, DetourRtlDecryptMemory);
	}

	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		AttachDetach(&(PVOID&)TrueSQLDriverConnectA, DetourSQLDriverConnectA);
		AttachDetach(&(PVOID&)TrueSQLDriverConnectW, DetourSQLDriverConnectW);
	}

	if (bAttach && VariableNotEmpty(WINPRIV_EV_PRIVLIST))
	{
		// tokenize the string
		std::wstring sPrivString(_wgetenv(WINPRIV_EV_PRIVLIST));
		std::wregex oRegex(L",");
		std::wsregex_token_iterator oFirst{ sPrivString.begin(), sPrivString.end(), oRegex, -1 }, oLast;

		// attempt to enable the privileges
		std::vector<std::wstring> tFailedPrivs = EnablePrivs(std::vector<std::wstring>({ oFirst, oLast }));

		// grant any privileges that cannot be enabled
		if (!tFailedPrivs.empty())
		{
			PrintMessage(L"%s", L"ERROR: Could not enable privileges in subprocess.");
		}
	}

	// special handling for com-based detours
	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		AttachDetach(&(PVOID&)TrueCoInitializeEx, DetourCoInitializeEx);
		AttachDetach(&(PVOID&)TrueCoInitialize, DetourCoInitialize);
		if (!bAttach) DllExtraAttachDetachCom(FALSE);
	}
}                                                                     

EXTERN_C LPWSTR SearchReplace(LPWSTR sInputString, LPWSTR sSearchString, LPWSTR sReplaceString)
{
	std::wstring sSearch(sSearchString);
	std::wstring sReplace(sReplaceString);
	std::wstring sResult = std::regex_replace(sInputString, std::wregex(sSearchString), sReplaceString);
	return _wcsdup(sResult.c_str());
}