#define UMDF_USING_NTSTATUS
#include <ntstatus.h>

#define _WINSOCKAPI_
#include <windows.h>
#include <winternl.h>
#include <detours.h>
#include <stdio.h>
#include <conio.h>
#include <lm.h>
#include <winsock2.h>
#include <iphlpapi.h>

#include <string>
#include <vector>
#include <regex>

#include "WinPrivShared.h"
#include "WinPrivLibrary.h"

//   ___         ___     __   __   ___                ___  ___  __   __   ___  __  ___ 
//  |__  | |    |__     /  \ |__) |__  |\ |    | |\ |  |  |__  |__) /  ` |__  |__)  |  
//  |    | |___ |___    \__/ |    |___ | \|    | | \|  |  |___ |  \ \__, |___ |     |  
//                                                                                     

decltype(&NtOpenFile) TrueNtOpenFile = (decltype(&NtOpenFile))
	GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtOpenFile");
decltype(&NtCreateFile) TrueNtCreateFile = (decltype(&NtCreateFile))
	GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtCreateFile");

EXTERN_C NTSTATUS NTAPI DetourNtOpenFile(OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess, IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess, IN ULONG OpenOptions)
{
	return TrueNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
		ShareAccess, OpenOptions | FILE_OPEN_FOR_BACKUP_INTENT);
}

EXTERN_C NTSTATUS NTAPI DetourNtCreateFile(OUT PHANDLE FileHandle, IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes, OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL, IN ULONG FileAttributes, IN ULONG ShareAccess,
	IN ULONG CreateDisposition, IN ULONG CreateOptions, IN PVOID EaBuffer OPTIONAL, IN ULONG EaLength)
{
	return TrueNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
		FileAttributes, ShareAccess, CreateDisposition, CreateOptions | FILE_OPEN_FOR_BACKUP_INTENT, EaBuffer, EaLength);
}

//   __   ___  __     __  ___         __   ___       __            ___  ___  __   __   ___  __  ___ 
//  |__) |__  / _` | /__`  |  \ /    |__) |__   /\  |  \    | |\ |  |  |__  |__) /  ` |__  |__)  |  
//  |  \ |___ \__> | .__/  |   |     |  \ |___ /~~\ |__/    | | \|  |  |___ |  \ \__, |___ |     |  
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
	_Out_opt_ PVOID KeyValueInformation, _In_ ULONG Length,_Out_ PULONG ResultLength
)
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
			RegInterceptInfo * tInterceptInfo = (RegInterceptInfo *) calloc(1, sizeof(RegInterceptInfo));

			// split the first argument into a root name and subkey name 
			LPWSTR sRootKeyName = sParams[iParam];
			LPWSTR sSubKeyName = wcschr(sParams[iParam], L'\\');
			*sSubKeyName++ = '\0';

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
					PKEY_NAME_INFORMATION pNameInfo = (PKEY_NAME_INFORMATION) malloc(iSize);
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
			LPWSTR sValueName = sParams[1];
			tInterceptInfo->RegValueName = { (USHORT) wcslen(sValueName) * sizeof(WCHAR), 
				(USHORT) wcslen(sValueName) * sizeof(WCHAR), sValueName };
			
			// match the aesthetic types to the typed enumerations
			LPWSTR sType = sParams[2];
			if (_wcsicmp(sType, L"REG_DWORD") == 0) tInterceptInfo->RegValueType = REG_DWORD;
			else if (_wcsicmp(sType, L"REG_SZ") == 0) tInterceptInfo->RegValueType = REG_SZ;
			else if (_wcsicmp(sType, L"REG_BLOCK") == 0) tInterceptInfo->RegValueType = -1;
			else break;

			// decode the value string to a data blob
			LPWSTR sData = sParams[3];
			if (tInterceptInfo->RegValueType == REG_DWORD)
			{
				tInterceptInfo->RegValueData = (DWORD *) malloc(sizeof(DWORD));
				swscanf(sData, L"%lu", (DWORD *) tInterceptInfo->RegValueData);
				tInterceptInfo->RegValueDataSize = sizeof(DWORD);
			}
			else if (tInterceptInfo->RegValueType == REG_SZ)
			{
				tInterceptInfo->RegValueData = sData;
				tInterceptInfo->RegValueDataSize = (DWORD) wcslen(sData) * sizeof(WCHAR);
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
	}

	// perform the real lookup
	NTSTATUS iRealReturn = TrueNtQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
		KeyValueInformation, Length, ResultLength);

	// lookup the size for the key name so we can allocate space for it
	DWORD iKeyNameSize;
	if (NtQueryKey(KeyHandle, KeyNameInformation, NULL, 0, &iKeyNameSize) != STATUS_BUFFER_TOO_SMALL)
	{
		return iRealReturn;
	}
	
	// allocate space for name and lookup 
	PKEY_NAME_INFORMATION pNameInfo = (PKEY_NAME_INFORMATION)malloc(iKeyNameSize);
	if (NtQueryKey(KeyHandle, KeyNameInformation, pNameInfo, iKeyNameSize, &iKeyNameSize) == STATUS_SUCCESS)
	{
		// convert to unicode string structure for quick comparisons
		UNICODE_STRING sKeyName = { (USHORT) pNameInfo->NameLength,
			(USHORT) pNameInfo->NameLength, pNameInfo->Name };

		for (RegInterceptInfo * tRegOverrideInfo : *vRegInterceptList)
		{
			// handle registry block
			if (UnicodeStringPrefix(&tRegOverrideInfo->RegKeyName,&sKeyName) &&
				tRegOverrideInfo->RegValueType == -1)
			{
				free(pNameInfo);
				*ResultLength = 0;
				return STATUS_OBJECT_NAME_NOT_FOUND;
			}

			// handle registry override
			if (UnicodeStringsEqual(&tRegOverrideInfo->RegKeyName, &sKeyName) &&
				UnicodeStringsEqual(&tRegOverrideInfo->RegValueName, ValueName))
			{
				if (KeyValueInformationClass == KeyValueFullInformation ||
					KeyValueInformationClass == KeyValueFullInformationAlign64)
				{
					PKEY_VALUE_FULL_INFORMATION tKeyInfo = (PKEY_VALUE_FULL_INFORMATION)KeyValueInformation;
					if (tKeyInfo->Type == tRegOverrideInfo->RegValueType)
					{
						if (tRegOverrideInfo->RegValueDataSize <= tKeyInfo->DataLength)
						{
							LPVOID pData = (DWORD *)((LPBYTE)KeyValueInformation + tKeyInfo->DataOffset);
							memcpy(pData, tRegOverrideInfo->RegValueData, tRegOverrideInfo->RegValueDataSize);
							tKeyInfo->DataLength = tRegOverrideInfo->RegValueDataSize;
						}

					}
				}
				else if (KeyValueInformationClass == KeyValuePartialInformation ||
					KeyValueInformationClass == KeyValuePartialInformationAlign64)
				{
					PKEY_VALUE_PARTIAL_INFORMATION tKeyInfo = (PKEY_VALUE_PARTIAL_INFORMATION)KeyValueInformation;
					if (tKeyInfo->Type == tRegOverrideInfo->RegValueType)
					{				
						LPVOID pData = (LPVOID)(tKeyInfo->Data);
						memcpy(pData, tRegOverrideInfo->RegValueData, tRegOverrideInfo->RegValueDataSize);
						tKeyInfo->DataLength = tRegOverrideInfo->RegValueDataSize;
					}
				}
			}
		}
	}

	free(pNameInfo);
	return iRealReturn;
}

//   __   __   __   __   ___  __   __      ___       ___           ___  ___  __   __   ___  __  ___ 
//  |__) |__) /  \ /  ` |__  /__` /__`    |__  \_/ |  |     | |\ |  |  |__  |__) /  ` |__  |__)  |  
//  |    |  \ \__/ \__, |___ .__/ .__/    |___ / \ |  |     | | \|  |  |___ |  \ \__, |___ |     |  
//                                                                                                  

VOID (NTAPI * TrueRtlExitUserProcess)(_In_ NTSTATUS 	ExitStatus) = 
	(decltype(TrueRtlExitUserProcess)) GetProcAddress(LoadLibrary(L"ntdll.dll"), "RtlExitUserProcess");

DECLSPEC_NORETURN EXTERN_C VOID NTAPI DetourRtlExitUserProcess(_In_ NTSTATUS ExitStatus)
{	
	if (GetConsoleWindow() != NULL && VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		wprintf(L"\n\nWinPriv target process has finished execution.  Please any key to exit this window.\n");
		_getch();
	}

	TrueRtlExitUserProcess(ExitStatus);
}

//              __           __   __   __   ___  __   __            ___  ___  __   __   ___  __  ___ 
//   |\/|  /\  /  `     /\  |  \ |  \ |__) |__  /__` /__`    | |\ |  |  |__  |__) /  ` |__  |__)  |  
//   |  | /~~\ \__,    /~~\ |__/ |__/ |  \ |___ .__/ .__/    | | \|  |  |___ |  \ \__, |___ |     |  
//   

decltype(&NetWkstaTransportEnum) TrueNetWkstaTransportEnum = 
	(decltype(&NetWkstaTransportEnum))GetProcAddress(LoadLibrary(L"netapi32.dll"), "NetWkstaTransportEnum");

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

decltype(&GetAdaptersInfo) TrueGetAdaptersInfo =
	(decltype(&GetAdaptersInfo))GetProcAddress(LoadLibrary(L"iphlpapi.dll"), "GetAdaptersInfo");

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
			pInfo->AddressLength = (UINT) (iByte + 1);
		}
	}

	return iRet;
}

decltype(&GetAdaptersAddresses) TrueGetAdaptersAddresses =
	(decltype(&GetAdaptersAddresses))GetProcAddress(LoadLibrary(L"iphlpapi.dll"), "GetAdaptersAddresses");

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
			pInfo->PhysicalAddressLength = (ULONG) (iByte + 1);
		}
	}

	return iRet;
}

//   __   ___ ___  __        __   __                           __   ___        ___      ___ 
//  |  \ |__   |  /  \ |  | |__) /__`     |\/|  /\  |\ |  /\  / _` |__   |\/| |__  |\ |  |  
//  |__/ |___  |  \__/ \__/ |  \ .__/     |  | /~~\ | \| /~~\ \__> |___  |  | |___ | \|  |  
//         

EXTERN_C VOID WINAPI DllExtraAttach()
{
	if (VariableIsSet(WINPRIV_EV_PARENT_PID, GetCurrentProcessId()))
	{
		return;
	}

	if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		DetourAttach(&(PVOID&)TrueRtlExitUserProcess, DetourRtlExitUserProcess);
	}

	if (VariableNotEmpty(WINPRIV_EV_MAC_OVERRIDE))
	{
		DetourAttach(&(PVOID&)TrueNetWkstaTransportEnum, DetourNetWkstaTransportEnum);
		DetourAttach(&(PVOID&)TrueGetAdaptersInfo, DetourGetAdaptersInfo);
		DetourAttach(&(PVOID&)TrueGetAdaptersAddresses, DetourGetAdaptersAddresses);
	}

	if (VariableNotEmpty(WINPRIV_EV_REG_OVERRIDE))
	{
		DetourAttach(&(PVOID&)TrueNtQueryValueKey, DetourNtQueryValueKey);
	}

	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1))
	{
		DetourAttach(&(PVOID&)TrueNtOpenFile, DetourNtOpenFile);
		DetourAttach(&(PVOID&)TrueNtCreateFile, DetourNtCreateFile);
	}

	if (VariableNotEmpty(WINPRIV_EV_PRIVLIST))
	{
		// tokenize the string
		std::wstring sPrivString(_wgetenv(WINPRIV_EV_PRIVLIST));
		std::wregex oRegex(L",");
		std::wsregex_token_iterator oFirst{ sPrivString.begin(), sPrivString.end(), oRegex, -1 }, oLast;

		// attempt to enable the privileges
		std::vector<std::wstring> tFailedPrivs = EnablePrivs(std::vector<std::wstring>({ oFirst, oLast }));

		// grant any privileges that cannot be enabled
		if (tFailedPrivs.size() > 0)
		{
			PrintMessage(L"%s", L"ERROR: Could not enable privileges in subprocess.");
		}
	}
}

EXTERN_C VOID WINAPI DllExtraDetach()
{
	if (VariableIsSet(WINPRIV_EV_PARENT_PID, GetCurrentProcessId()))
	{
		return;
	}

	if (VariableIsSet(WINPRIV_EV_RELAUNCH_MODE, 1))
	{
		DetourDetach(&(PVOID&)TrueRtlExitUserProcess, DetourRtlExitUserProcess);
	}

	if (VariableNotEmpty(WINPRIV_EV_MAC_OVERRIDE))
	{
		DetourDetach(&(PVOID&)TrueNetWkstaTransportEnum, DetourNetWkstaTransportEnum);
	}
	
	if (VariableNotEmpty(WINPRIV_EV_REG_OVERRIDE))
	{
		DetourDetach(&(PVOID&)TrueNtQueryValueKey, DetourNtQueryValueKey);
	}

	if (VariableIsSet(WINPRIV_EV_BACKUP_RESTORE, 1))
	{
		DetourDetach(&(PVOID&)TrueNtOpenFile, DetourNtOpenFile);
		DetourDetach(&(PVOID&)TrueNtCreateFile, DetourNtCreateFile);
	}
}