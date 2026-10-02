#pragma once

#define UMDF_USING_NTSTATUS
#include <ntstatus.h>
#include <Windows.h>
#include <winternl.h>
#include "WinPrivDetoursFork.h"
#include "WinPrivShared.h"

// Shared hook registration and native entry points.
bool DllExtraAttachDetach(winpriv::detours::action requestedAction);
bool DllFileAttachDetach(winpriv::detours::action requestedAction);

template <winpriv::detours::function_pointer Function>
void ApplyDetour(winpriv::detours::action requestedAction, Function& target, Function replacement) noexcept
{
	(void)winpriv::detours::apply(requestedAction, target, replacement);
}

inline const auto RtlInitUnicodeStringEx = LoadNtFunction<NTSTATUS(NTAPI*)(PUNICODE_STRING, PCWSTR)>(
	"RtlInitUnicodeStringEx");

//
// Key Name Lookup Support
//

inline const auto NtQueryKey = LoadNtFunction<NTSTATUS(NTAPI*)(HANDLE, DWORD, PVOID, ULONG, PULONG)>("NtQueryKey");

typedef enum _KEY_INFORMATION_CLASS {
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS;

typedef struct _KEY_NAME_INFORMATION {
	ULONG NameLength;
	WCHAR Name[1];
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

//
// Value Query Support
//

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_BASIC_INFORMATION
{
	ULONG TitleIndex;
	ULONG Type;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_BASIC_INFORMATION, *PKEY_VALUE_BASIC_INFORMATION;

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataOffset;
	ULONG DataLength;
	ULONG NameLength;
	WCHAR Name[1];
} KEY_VALUE_FULL_INFORMATION, *PKEY_VALUE_FULL_INFORMATION;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
	ULONG TitleIndex;
	ULONG Type;
	ULONG DataLength;
	UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, *PKEY_VALUE_PARTIAL_INFORMATION;

// Native file information classes not exposed by the user-mode SDK.
enum class FileInformationClass
{
	Rename = 10, Link = 11, RenameBypassAccessCheck = 56, LinkBypassAccessCheck = 57,
	RenameEx = 65, RenameExBypassAccessCheck = 66, LinkEx = 72, LinkExBypassAccessCheck = 73
};

using NtDuplicateObjectFunction = NTSTATUS(NTAPI*)(HANDLE, HANDLE, HANDLE, PHANDLE, ACCESS_MASK, ULONG, ULONG);
using NtFileAttributesFunction = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, PVOID);
using NtDeleteFileFunction = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES);
using NtQueryInformationByNameFunction = NTSTATUS(NTAPI*)(POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
	PVOID, ULONG, FileInformationClass);
using NtSetInformationFileFunction = NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, FileInformationClass);
