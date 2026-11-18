/*
# Microsoft Detours source subset

WinPriv includes a consolidated Microsoft Detours 4.0.1 source subset derived
from upstream commit `d644ce94e8c7f7f5a31591577c78134ea3ac1fae`, including
Microsoft's ARM64 correctness fixes. The upstream license and fork provenance
are reproduced in this file.

This source provides native DLL injection, cross-architecture helper processes,
and private process payloads for WinPriv's x86, x64, and ARM64 builds.

Upstream: https://github.com/microsoft/Detours
*/

/*
# Copyright (c) Microsoft Corporation

All rights reserved.

# MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "WinPrivDllLoader.h"
#include <winternl.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <new>
constexpr DWORD DETOUR_MAX_SUPPORTED_IMAGE_SECTION_HEADERS = 32;
constexpr SIZE_T MM_ALLOCATION_GRANULARITY = 0x10000;
constexpr DWORD DETOUR_HELPER_PROCESS_TIMEOUT_MS = 30000;
constexpr DWORD DETOUR_HELPER_TERMINATION_TIMEOUT_MS = 5000;
constexpr size_t DETOUR_MAX_DLL_PATH = sizeof(winpriv::loader::LibraryBundle::paths[0]);
constexpr DWORD_PTR DETOUR_PROC_THREAD_ATTRIBUTE_MACHINE_TYPE = 0x00020019;

#if defined(_M_IX86)
constexpr WORD DETOUR_CURRENT_PROCESS_MACHINE = IMAGE_FILE_MACHINE_I386;
#elif defined(_M_X64)
constexpr WORD DETOUR_CURRENT_PROCESS_MACHINE = IMAGE_FILE_MACHINE_AMD64;
#elif defined(_M_ARM64)
constexpr WORD DETOUR_CURRENT_PROCESS_MACHINE = IMAGE_FILE_MACHINE_ARM64;
#endif

constexpr GUID DETOUR_EXE_RESTORE_GUID = {
    0xbda26f34, 0xbc82, 0x4829,
    { 0x9e, 0x64, 0x74, 0x2c, 0x04, 0xc8, 0x4f, 0xa0 } };
constexpr GUID DETOUR_EXE_HELPER_GUID = {
    0xea0251b9, 0x5cde, 0x41b5,
    { 0x98, 0xd0, 0x2a, 0xf4, 0xa2, 0x6b, 0x0f, 0xee } };
constexpr GUID DETOUR_PAYLOAD_SIGNATURE = {
    0x34ae2a7b, 0x2f97, 0x45ed,
    { 0xa3, 0x42, 0x9f, 0xd3, 0x91, 0x52, 0xd5, 0x31 } };

#pragma pack(push, 8)
struct DETOUR_PAYLOAD_HEADER
{
    GUID signature;
    GUID guid;
    DWORD cbData;
    DWORD reserved;
};
static_assert(sizeof(DETOUR_PAYLOAD_HEADER) % alignof(UINT64) == 0);

struct DETOUR_CLR_HEADER
{
    ULONG cb;
    USHORT MajorRuntimeVersion;
    USHORT MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY MetaData;
    ULONG Flags;
};
using PDETOUR_CLR_HEADER = DETOUR_CLR_HEADER*;

struct DETOUR_EXE_RESTORE
{
    DWORD cb;
    DWORD cbinh;
    PBYTE pinh;
    PBYTE pclr;
    union
    {
        IMAGE_NT_HEADERS inh;
        IMAGE_NT_HEADERS32 inh32;
        IMAGE_NT_HEADERS64 inh64;
        BYTE raw[sizeof(IMAGE_NT_HEADERS64) +
            sizeof(IMAGE_SECTION_HEADER) * DETOUR_MAX_SUPPORTED_IMAGE_SECTION_HEADERS];
    };
    DETOUR_CLR_HEADER clr;
};
using PDETOUR_EXE_RESTORE = DETOUR_EXE_RESTORE*;

struct DETOUR_EXE_HELPER
{
    DWORD pid;
    CHAR dll[DETOUR_MAX_DLL_PATH];
};
using PDETOUR_EXE_HELPER = DETOUR_EXE_HELPER*;
#pragma pack(pop)

static_assert(sizeof(IMAGE_NT_HEADERS64) == 0x108);

_Success_(return != FALSE)
static BOOL MakeWritable(_In_ HANDLE process, _In_ PVOID address, _In_ SIZE_T size, _Out_ PDWORD oldProtection)
// Some systems do not allow executability of a page to change, so only writability is added.
// Restoring the returned protection needs no such adjustment.
{
    MEMORY_BASIC_INFORMATION memory{};
    if (VirtualQueryEx(process, address, &memory, sizeof(memory)) == 0) {
        return FALSE;
    }

    constexpr DWORD executable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    return VirtualProtectEx(process, address, size,
                            (memory.Protect & executable) != 0 ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE,
                            oldProtection);
}

//////////////////////////////////////////////////////////////////////////////
// Payload discovery and image restoration

PVOID DetourFindPayload(REFGUID guid, DWORD& dataSize)
{
    dataSize = 0;
    PBYTE address = NULL;
    MEMORY_BASIC_INFORMATION memory{};
    while (VirtualQuery(address, &memory, sizeof(memory)) == sizeof(memory)) {
        const auto next = static_cast<PBYTE>(memory.BaseAddress) + memory.RegionSize;

        if (memory.State == MEM_COMMIT &&
            memory.Type == MEM_PRIVATE &&
            memory.AllocationBase == memory.BaseAddress &&
            (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
            memory.RegionSize >= sizeof(DETOUR_PAYLOAD_HEADER)) {

            __try {
                const auto header = static_cast<const DETOUR_PAYLOAD_HEADER*>(memory.BaseAddress);
                if (header->signature == DETOUR_PAYLOAD_SIGNATURE &&
                    header->guid == guid &&
                    header->cbData <= memory.RegionSize - sizeof(*header)) {

                    dataSize = header->cbData;
                    SetLastError(NO_ERROR);
                    return const_cast<DETOUR_PAYLOAD_HEADER*>(header) + 1;
                }
            }
            __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
            }
        }

        if (next <= address) {
            break;
        }
        address = next;
    }

    SetLastError(ERROR_MOD_NOT_FOUND);
    return NULL;
}

extern "C" BOOL WINAPI DetourFreePayload(PVOID data)
{
    MEMORY_BASIC_INFORMATION memory{};
    if (data == NULL || VirtualQuery(data, &memory, sizeof(memory)) != sizeof(memory)) {
        return FALSE;
    }

    const auto base = static_cast<PBYTE>(memory.AllocationBase);
    if (static_cast<PBYTE>(data) != base + sizeof(DETOUR_PAYLOAD_HEADER)) {
        return FALSE;
    }

    const auto header = reinterpret_cast<const DETOUR_PAYLOAD_HEADER*>(base);
    if (header->signature != DETOUR_PAYLOAD_SIGNATURE) {
        return FALSE;
    }

    return VirtualFree(base, 0, MEM_RELEASE);
}

static BOOL RestoreExecutable(PDETOUR_EXE_RESTORE restore, DWORD dataSize)
{
    if (restore->cb != sizeof(*restore) || restore->cb > dataSize) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return FALSE;
    }

    DWORD ntProtection = 0;
    DWORD clrProtection = 0;
    DWORD ignored = 0;
    BOOL succeeded = FALSE;

    const bool promotedManagedImage =
        restore->pclr != NULL &&
        restore->clr.Flags != reinterpret_cast<PDETOUR_CLR_HEADER>(restore->pclr)->Flags;

    if (MakeWritable(GetCurrentProcess(), restore->pinh, restore->cbinh, &ntProtection)) {
        CopyMemory(restore->pinh, &restore->inh, restore->cbinh);

        if (restore->pclr == NULL || promotedManagedImage) {
            succeeded = TRUE;
        }
        else if (MakeWritable(GetCurrentProcess(), restore->pclr, sizeof(restore->clr), &clrProtection)) {
            CopyMemory(restore->pclr, &restore->clr, sizeof(restore->clr));
            VirtualProtect(restore->pclr, sizeof(restore->clr), clrProtection, &ignored);
            succeeded = TRUE;
        }

        VirtualProtect(restore->pinh, restore->cbinh, ntProtection, &ignored);
    }

    if (succeeded) {
        DetourFreePayload(restore);
    }
    return succeeded;
}

extern "C" BOOL WINAPI DetourRestoreAfterWith()
{
    DWORD dataSize = 0;
    PVOID data = DetourFindPayload(DETOUR_EXE_RESTORE_GUID, dataSize);
    return data != NULL && RestoreExecutable(
        static_cast<PDETOUR_EXE_RESTORE>(data), dataSize);
}

//////////////////////////////////////////////////////////////////////////////
// Process creation and DLL injection

constexpr auto& ImportDirectory(auto& headers) noexcept
{
    return headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
}

constexpr auto& BoundDirectory(auto& headers) noexcept
{
    return headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
}

constexpr auto& ClrDirectory(auto& headers) noexcept
{
    return headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];
}

constexpr auto& IatDirectory(auto& headers) noexcept
{
    return headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
}

static BOOL WINAPI DetourCopyPayloadToProcess(
    _In_ HANDLE process, _In_ REFGUID guid, _In_reads_bytes_(dataSize) LPCVOID data, _In_ DWORD dataSize);

//////////////////////////////////////////////////////////////////////////////
//
// Enumerate through modules in the target process.
//
static PVOID LoadNtHeaderFromProcess(_In_ HANDLE hProcess,
                                     _In_ HMODULE hModule,
                                     _Out_ PIMAGE_NT_HEADERS32 pNtHeader)
{
    ZeroMemory(pNtHeader, sizeof(*pNtHeader));
    PBYTE pbModule = (PBYTE)hModule;

    if (pbModule == NULL) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    if (VirtualQueryEx(hProcess, hModule, &mbi, sizeof(mbi)) == 0) {
        return NULL;
    }

    IMAGE_DOS_HEADER idh;
    if (!ReadProcessMemory(hProcess, pbModule, &idh, sizeof(idh), NULL)) {
        return NULL;
    }

    if (idh.e_magic != IMAGE_DOS_SIGNATURE ||
        (DWORD)idh.e_lfanew > mbi.RegionSize ||
        (DWORD)idh.e_lfanew < sizeof(idh)) {

        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    if (!ReadProcessMemory(hProcess, pbModule + idh.e_lfanew,
                           pNtHeader, sizeof(*pNtHeader), NULL)) {
        return NULL;
    }

    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        SetLastError(ERROR_BAD_EXE_FORMAT);
        return NULL;
    }

    return pbModule + idh.e_lfanew;
}

static HMODULE EnumerateModulesInProcess(_In_ HANDLE hProcess,
                                         _In_opt_ HMODULE hModuleLast,
                                         _Out_ PIMAGE_NT_HEADERS32 pNtHeader)
{
    ZeroMemory(pNtHeader, sizeof(*pNtHeader));

    PBYTE pbLast = (PBYTE)hModuleLast + MM_ALLOCATION_GRANULARITY;

    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    // Find the next memory region that contains a mapped PE image.
    //

    for (;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {
        if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) == 0) {
            break;
        }

        // Usermode address space has such an unaligned region size always at the
        // end and only at the end.
        //
        if ((mbi.RegionSize & 0xfff) == 0xfff) {
            break;
        }
        if (((PBYTE)mbi.BaseAddress + mbi.RegionSize) < pbLast) {
            break;
        }

        // Skip uncommitted regions and guard pages.
        //
        if ((mbi.State != MEM_COMMIT) ||
            ((mbi.Protect & 0xff) == PAGE_NOACCESS) ||
            (mbi.Protect & PAGE_GUARD)) {
            continue;
        }

        if (LoadNtHeaderFromProcess(hProcess, (HMODULE)pbLast, pNtHeader)) {
            return (HMODULE)pbLast;
        }
    }
    return NULL;
}

//////////////////////////////////////////////////////////////////////////////
//
// Find a region of memory in which we can create a replacement import table.
//
static PBYTE FindAndAllocateNearBase(HANDLE hProcess, PBYTE pbModule, PBYTE pbBase, DWORD cbAlloc)
{
    MEMORY_BASIC_INFORMATION mbi;
    ZeroMemory(&mbi, sizeof(mbi));

    PBYTE pbLast = pbBase;
    for (;; pbLast = (PBYTE)mbi.BaseAddress + mbi.RegionSize) {

        ZeroMemory(&mbi, sizeof(mbi));
        if (VirtualQueryEx(hProcess, (PVOID)pbLast, &mbi, sizeof(mbi)) == 0) {
            break;
        }
        // Usermode address space has such an unaligned region size always at the
        // end and only at the end.
        //
        if ((mbi.RegionSize & 0xfff) == 0xfff) {
            break;
        }

        // Skip anything other than a pure free region.
        //
        if (mbi.State != MEM_FREE) {
            continue;
        }

        // Use the max of mbi.BaseAddress and pbBase, in case mbi.BaseAddress < pbBase.
        PBYTE pbAddress = (PBYTE)mbi.BaseAddress > pbBase ? (PBYTE)mbi.BaseAddress : pbBase;

        // Round pbAddress up to the nearest MM allocation boundary.
        const DWORD_PTR mmGranularityMinusOne = (DWORD_PTR)(MM_ALLOCATION_GRANULARITY -1);
        pbAddress = (PBYTE)(((DWORD_PTR)pbAddress + mmGranularityMinusOne) & ~mmGranularityMinusOne);

#ifdef _WIN64
        // The offset from pbModule to any replacement import must fit into 32 bits.
        // For simplicity, we check that the offset to the last byte fits into 32 bits,
        // instead of the largest offset we'll actually use. The values are very similar.
        const size_t GB4 = ((((size_t)1) << 32) - 1);
        if ((size_t)(pbAddress + cbAlloc - 1 - pbModule) > GB4) {
            return NULL;
        }
#else
        UNREFERENCED_PARAMETER(pbModule);
#endif


        for (; pbAddress < (PBYTE)mbi.BaseAddress + mbi.RegionSize; pbAddress += MM_ALLOCATION_GRANULARITY) {
            PBYTE pbAlloc = (PBYTE)VirtualAllocEx(hProcess, pbAddress, cbAlloc,
                                                  MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
            if (pbAlloc == NULL) {
                continue;
            }
#ifdef _WIN64
            // The offset from pbModule to any replacement import must fit into 32 bits.
            if ((size_t)(pbAddress + cbAlloc - 1 - pbModule) > GB4) {
                return NULL;
            }
#endif
            return pbAlloc;
        }
    }
    return NULL;
}

static inline DWORD PadToDword(DWORD dw)
{
    return (dw + 3) & ~3u;
}

static inline DWORD PadToDwordPtr(DWORD dw)
{
    return (dw + 7) & ~7u;
}

static BOOL RecordExeRestore(HANDLE hProcess, HMODULE hModule, DETOUR_EXE_RESTORE& der)
{
    // Save the various headers for DetourRestoreAfterWith.
    ZeroMemory(&der, sizeof(der));
    der.cb = sizeof(der);

    IMAGE_DOS_HEADER dosHeader{};
    if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(dosHeader), NULL)) {
        return FALSE;
    }

    // We read the NT header in two passes to get the full size.
    // First we read just the Signature and FileHeader.
    der.pinh = reinterpret_cast<PBYTE>(hModule) + dosHeader.e_lfanew;
    der.cbinh = FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader);
    if (!ReadProcessMemory(hProcess, der.pinh, &der.inh, der.cbinh, NULL)) {
        return FALSE;
    }

    // Second we read the OptionalHeader and Section headers.
    der.cbinh = (FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
                 der.inh.FileHeader.SizeOfOptionalHeader +
                 der.inh.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));

    if (der.cbinh > sizeof(der.raw)) {
        return FALSE;
    }

    if (!ReadProcessMemory(hProcess, der.pinh, &der.inh, der.cbinh, NULL)) {
        return FALSE;
    }

    // Third, we read the CLR header

    if (der.inh.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (ClrDirectory(der.inh32).VirtualAddress != 0 &&
            ClrDirectory(der.inh32).Size != 0) {


            der.pclr = ((PBYTE)hModule) + ClrDirectory(der.inh32).VirtualAddress;
        }
    }
    else if (der.inh.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (ClrDirectory(der.inh64).VirtualAddress != 0 &&
            ClrDirectory(der.inh64).Size != 0) {


            der.pclr = ((PBYTE)hModule) + ClrDirectory(der.inh64).VirtualAddress;
        }
    }

    if (der.pclr != 0) {
        if (!ReadProcessMemory(hProcess, der.pclr, &der.clr, sizeof(der.clr), NULL)) {
            return FALSE;
        }
    }

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// Import-table editing

static BOOL UpdateImports(HANDLE hProcess, HMODULE hModule, LPCSTR lpDll)
{
    DWORD cbNew = 0;

    DWORD i;
    SIZE_T cbRead;

    PBYTE pbModule = (PBYTE)hModule;

    IMAGE_DOS_HEADER idh;
    ZeroMemory(&idh, sizeof(idh));
    if (!ReadProcessMemory(hProcess, pbModule, &idh, sizeof(idh), &cbRead)
        || cbRead < sizeof(idh)) {

        return FALSE;
    }

    IMAGE_NT_HEADERS inh;
    ZeroMemory(&inh, sizeof(inh));

    if (!ReadProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), &cbRead)
        || cbRead < sizeof(inh)) {
        return FALSE;
    }

    if (inh.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        SetLastError(ERROR_INVALID_BLOCK);
        return FALSE;
    }

    // Zero out the bound table so loader doesn't use it instead of our new table.
    BoundDirectory(inh).VirtualAddress = 0;
    BoundDirectory(inh).Size = 0;

    // Find the size of the mapped file.
    DWORD dwSec = idh.e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        inh.FileHeader.SizeOfOptionalHeader;

    for (i = 0; i < inh.FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER ish;
        ZeroMemory(&ish, sizeof(ish));

        if (!ReadProcessMemory(hProcess, pbModule + dwSec + sizeof(ish) * i, &ish,
                               sizeof(ish), &cbRead)
            || cbRead < sizeof(ish)) {

            return FALSE;
        }


        // If the linker didn't suggest an IAT in the data directories, the
        // loader will look for the section of the import directory to be used
        // for this instead. Since we put out new IMPORT_DIRECTORY outside any
        // section boundary, the loader will not find it. So we provide one
        // explicitly to avoid the search.
        //
        if (IatDirectory(inh).VirtualAddress == 0 &&
            ImportDirectory(inh).VirtualAddress >= ish.VirtualAddress &&
            ImportDirectory(inh).VirtualAddress < ish.VirtualAddress + ish.SizeOfRawData) {

            IatDirectory(inh).VirtualAddress = ish.VirtualAddress;
            IatDirectory(inh).Size = ish.SizeOfRawData;
        }
    }

    if (ImportDirectory(inh).VirtualAddress != 0 && ImportDirectory(inh).Size == 0) {

        // Don't worry about changing the PE file,
        // because the load information of the original PE header has been saved and will be restored.
        // The change here is just for the following code to work normally

        PIMAGE_IMPORT_DESCRIPTOR pImageImport =
            (PIMAGE_IMPORT_DESCRIPTOR)(pbModule + ImportDirectory(inh).VirtualAddress);

        do {
            IMAGE_IMPORT_DESCRIPTOR ImageImport;
            if (!ReadProcessMemory(hProcess, pImageImport, &ImageImport, sizeof(ImageImport), NULL)) {
                return FALSE;
            }
            ImportDirectory(inh).Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            if (!ImageImport.Name) {
                break;
            }
            ++pImageImport;
        } while (TRUE);

    }


    // Calculate new import directory size.  Note that since inh is from another
    // process, inh could have been corrupted. We need to protect against
    // integer overflow in allocation calculations.
    constexpr DWORD descriptorSize = sizeof(IMAGE_IMPORT_DESCRIPTOR);
    const DWORD nOldDlls = ImportDirectory(inh).Size / descriptorSize;
    if (nOldDlls >= MAXDWORD / descriptorSize) {
        return FALSE;
    }
    const DWORD obOld = descriptorSize * (nOldDlls + 1);
    DWORD obTab = PadToDwordPtr(obOld);
    // Check for integer overflow.
    if (obTab < obOld) {
        return FALSE;
    }
    constexpr DWORD stSize = sizeof(IMAGE_THUNK_DATA) * 4;
    if (obTab > MAXDWORD - stSize) {
        return FALSE;
    }
    DWORD obStr = obTab + stSize;

    const size_t dllLength = strnlen_s(lpDll, DETOUR_MAX_DLL_PATH);
    if (dllLength == DETOUR_MAX_DLL_PATH) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }
    const DWORD paddedDllSize = PadToDword(static_cast<DWORD>(dllLength + 1));
    if (obStr > MAXDWORD - paddedDllSize) {
        return FALSE;
    }
    cbNew = obStr + paddedDllSize;
    std::unique_ptr<BYTE[]> pbNew(new (std::nothrow) BYTE[cbNew]{});
    if (!pbNew) {
        return FALSE;
    }

    PBYTE pbBase = pbModule;
    PBYTE pbNext = pbBase
        + inh.OptionalHeader.BaseOfCode
        + inh.OptionalHeader.SizeOfCode
        + inh.OptionalHeader.SizeOfInitializedData
        + inh.OptionalHeader.SizeOfUninitializedData;
    if (pbBase < pbNext) {
        pbBase = pbNext;
    }

    PBYTE pbNewIid = FindAndAllocateNearBase(hProcess, pbModule, pbBase, cbNew);
    if (pbNewIid == NULL) {
        return FALSE;
    }

    PIMAGE_IMPORT_DESCRIPTOR piid = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(pbNew.get());
    IMAGE_THUNK_DATA *pt = NULL;

    DWORD obBase = (DWORD)(pbNewIid - pbModule);
    DWORD dwProtect = 0;

    if (ImportDirectory(inh).VirtualAddress != 0) {
        // Read the old import directory if it exists.

        if (!ReadProcessMemory(hProcess,
                               pbModule + ImportDirectory(inh).VirtualAddress,
                               &piid[1],
                               nOldDlls * sizeof(IMAGE_IMPORT_DESCRIPTOR), &cbRead)
            || cbRead < nOldDlls * sizeof(IMAGE_IMPORT_DESCRIPTOR)) {

            return FALSE;
        }
    }

    CopyMemory(pbNew.get() + obStr, lpDll, dllLength + 1);

    piid[0].OriginalFirstThunk = obBase + obTab;

    // One ordinal import plus a terminator for both the import table and IAT.
    pt = reinterpret_cast<IMAGE_THUNK_DATA*>(pbNew.get() + obTab);
    pt[0].u1.Ordinal = IMAGE_ORDINAL_FLAG + 1;
    pt[1].u1.Ordinal = 0;

    constexpr DWORD iatOffset = sizeof(IMAGE_THUNK_DATA) * 2;
    piid[0].FirstThunk = obBase + obTab + iatOffset;
    pt = reinterpret_cast<IMAGE_THUNK_DATA*>(pbNew.get() + obTab + iatOffset);
    pt[0].u1.Ordinal = IMAGE_ORDINAL_FLAG + 1;
    pt[1].u1.Ordinal = 0;
    piid[0].Name = obBase + obStr;

    obStr += paddedDllSize;

    if (!WriteProcessMemory(hProcess, pbNewIid, pbNew.get(), obStr, NULL)) {
        return FALSE;
    }


    // In this case the file didn't have an import directory in first place,
    // so we couldn't fix the missing IAT above. We still need to explicitly
    // provide an IAT to prevent to loader from looking for one.
    //
    if (IatDirectory(inh).VirtualAddress == 0) {
        IatDirectory(inh).VirtualAddress = obBase;
        IatDirectory(inh).Size = cbNew;
    }

    ImportDirectory(inh).VirtualAddress = obBase;
    ImportDirectory(inh).Size = cbNew;

    /////////////////////// Update the NT header for the new import directory.
    //
    if (!MakeWritable(hProcess, pbModule, inh.OptionalHeader.SizeOfHeaders, &dwProtect)) {
        return FALSE;
    }

    inh.OptionalHeader.CheckSum = 0;

    if (!WriteProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), NULL)) {
        return FALSE;
    }

    if (!VirtualProtectEx(hProcess, pbModule, inh.OptionalHeader.SizeOfHeaders,
                          dwProtect, &dwProtect)) {
        return FALSE;
    }

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//
#if defined(_WIN64)

static_assert(sizeof(IMAGE_NT_HEADERS64) == sizeof(IMAGE_NT_HEADERS32) + 16);

static BOOL UpdateFrom32To64(HANDLE hProcess, HMODULE hModule, DETOUR_EXE_RESTORE& der)
{
    IMAGE_DOS_HEADER idh;
    IMAGE_NT_HEADERS32 inh32;
    IMAGE_NT_HEADERS64 inh64;
    IMAGE_SECTION_HEADER sects[32];
    PBYTE pbModule = (PBYTE)hModule;
    DWORD n;

    ZeroMemory(&inh32, sizeof(inh32));
    ZeroMemory(&inh64, sizeof(inh64));
    ZeroMemory(sects, sizeof(sects));

    //////////////////////////////////////////////////////// Read old headers.
    //
    if (!ReadProcessMemory(hProcess, pbModule, &idh, sizeof(idh), NULL)) {
        return FALSE;
    }

    PBYTE pnh = pbModule + idh.e_lfanew;
    if (!ReadProcessMemory(hProcess, pnh, &inh32, sizeof(inh32), NULL)) {
        return FALSE;
    }

    if (inh32.FileHeader.NumberOfSections > (sizeof(sects)/sizeof(sects[0]))) {
        return FALSE;
    }

    PBYTE psects = pnh +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        inh32.FileHeader.SizeOfOptionalHeader;
    ULONG cb = inh32.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (!ReadProcessMemory(hProcess, psects, &sects, cb, NULL)) {
        return FALSE;
    }

    ////////////////////////////////////////////////////////// Convert header.
    //
    inh64.Signature = inh32.Signature;
    inh64.FileHeader = inh32.FileHeader;
    inh64.FileHeader.Machine = DETOUR_CURRENT_PROCESS_MACHINE;
    inh64.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);

    inh64.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    inh64.OptionalHeader.MajorLinkerVersion = inh32.OptionalHeader.MajorLinkerVersion;
    inh64.OptionalHeader.MinorLinkerVersion = inh32.OptionalHeader.MinorLinkerVersion;
    inh64.OptionalHeader.SizeOfCode = inh32.OptionalHeader.SizeOfCode;
    inh64.OptionalHeader.SizeOfInitializedData = inh32.OptionalHeader.SizeOfInitializedData;
    inh64.OptionalHeader.SizeOfUninitializedData = inh32.OptionalHeader.SizeOfUninitializedData;
    inh64.OptionalHeader.AddressOfEntryPoint = inh32.OptionalHeader.AddressOfEntryPoint;
    inh64.OptionalHeader.BaseOfCode = inh32.OptionalHeader.BaseOfCode;
    inh64.OptionalHeader.ImageBase = inh32.OptionalHeader.ImageBase;
    inh64.OptionalHeader.SectionAlignment = inh32.OptionalHeader.SectionAlignment;
    inh64.OptionalHeader.FileAlignment = inh32.OptionalHeader.FileAlignment;
    inh64.OptionalHeader.MajorOperatingSystemVersion
        = inh32.OptionalHeader.MajorOperatingSystemVersion;
    inh64.OptionalHeader.MinorOperatingSystemVersion
        = inh32.OptionalHeader.MinorOperatingSystemVersion;
    inh64.OptionalHeader.MajorImageVersion = inh32.OptionalHeader.MajorImageVersion;
    inh64.OptionalHeader.MinorImageVersion = inh32.OptionalHeader.MinorImageVersion;
    inh64.OptionalHeader.MajorSubsystemVersion = inh32.OptionalHeader.MajorSubsystemVersion;
    inh64.OptionalHeader.MinorSubsystemVersion = inh32.OptionalHeader.MinorSubsystemVersion;
    inh64.OptionalHeader.Win32VersionValue = inh32.OptionalHeader.Win32VersionValue;
    inh64.OptionalHeader.SizeOfImage = inh32.OptionalHeader.SizeOfImage;
    inh64.OptionalHeader.SizeOfHeaders = inh32.OptionalHeader.SizeOfHeaders;
    inh64.OptionalHeader.CheckSum = inh32.OptionalHeader.CheckSum;
    inh64.OptionalHeader.Subsystem = inh32.OptionalHeader.Subsystem;
    inh64.OptionalHeader.DllCharacteristics = inh32.OptionalHeader.DllCharacteristics;
    inh64.OptionalHeader.SizeOfStackReserve = inh32.OptionalHeader.SizeOfStackReserve;
    inh64.OptionalHeader.SizeOfStackCommit = inh32.OptionalHeader.SizeOfStackCommit;
    inh64.OptionalHeader.SizeOfHeapReserve = inh32.OptionalHeader.SizeOfHeapReserve;
    inh64.OptionalHeader.SizeOfHeapCommit = inh32.OptionalHeader.SizeOfHeapCommit;
    inh64.OptionalHeader.LoaderFlags = inh32.OptionalHeader.LoaderFlags;
    inh64.OptionalHeader.NumberOfRvaAndSizes = inh32.OptionalHeader.NumberOfRvaAndSizes;
    for (n = 0; n < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; n++) {
        inh64.OptionalHeader.DataDirectory[n] = inh32.OptionalHeader.DataDirectory[n];
    }

    /////////////////////////////////////////////////////// Write new headers.
    //
    DWORD dwProtect = 0;
    if (!MakeWritable(hProcess, pbModule, inh64.OptionalHeader.SizeOfHeaders, &dwProtect)) {
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pnh, &inh64, sizeof(inh64), NULL)) {
        return FALSE;
    }

    psects = pnh +
        FIELD_OFFSET(IMAGE_NT_HEADERS, OptionalHeader) +
        inh64.FileHeader.SizeOfOptionalHeader;
    cb = inh64.FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    if (!WriteProcessMemory(hProcess, psects, &sects, cb, NULL)) {
        return FALSE;
    }

    // Record the updated headers.
    if (!RecordExeRestore(hProcess, hModule, der)) {
        return FALSE;
    }

    // Remove the import table.
    if (der.pclr != NULL && (der.clr.Flags & COMIMAGE_FLAGS_ILONLY)) {
        ImportDirectory(inh64).VirtualAddress = 0;
        ImportDirectory(inh64).Size = 0;

        if (!WriteProcessMemory(hProcess, pnh, &inh64, sizeof(inh64), NULL)) {
            return FALSE;
        }
    }

    DWORD dwOld = 0;
    if (!VirtualProtectEx(hProcess, pbModule, inh64.OptionalHeader.SizeOfHeaders,
                          dwProtect, &dwOld)) {
        return FALSE;
    }

    return TRUE;
}
#endif // _WIN64

//////////////////////////////////////////////////////////////////////////////
//
static BOOL GetProcessMachines(
    HANDLE process, WORD& processMachine, WORD& nativeMachine)
{
    processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    if (!IsWow64Process2(process, &processMachine, &nativeMachine)) {
        return FALSE;
    }

    if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
        return TRUE;
    }
    if (nativeMachine != IMAGE_FILE_MACHINE_ARM64) {
        processMachine = nativeMachine;
        return processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
    }

    // IsWow64Process2 reports UNKNOWN/ARM64 for both native ARM64 and
    // emulated x64 processes. Windows 11's ProcessMachineTypeInfo removes
    // that ambiguity; Windows 10 on ARM did not support x64 emulation.
    PROCESS_MACHINE_INFORMATION information{};
    if (GetProcessInformation(process, ProcessMachineTypeInfo, &information, sizeof(information))) {
        processMachine = information.ProcessMachine;
        if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
            return TRUE;
        }
    }
    else if (GetLastError() != ERROR_INVALID_PARAMETER && GetLastError() != ERROR_NOT_SUPPORTED) {
        return FALSE;
    }

    processMachine = IMAGE_FILE_MACHINE_ARM64;
    return TRUE;
}

static BOOL UpdateProcessWithDll(
    HANDLE hProcess, LPCSTR lpDll, WORD& processMachine, WORD& nativeMachine)
{
    if (!GetProcessMachines(hProcess, processMachine, nativeMachine)) {
        return FALSE;
    }
    if (processMachine != DETOUR_CURRENT_PROCESS_MACHINE) {
        SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
        return FALSE;
    }

    // Find the last mapped PE image that is not a DLL.
    HMODULE hModule = NULL;
    IMAGE_NT_HEADERS32 inh;
    for (HMODULE hLast = NULL; (hLast = EnumerateModulesInProcess(hProcess, hLast, &inh)) != NULL;) {
        if ((inh.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
            hModule = hLast;
        }
    }
    if (hModule == NULL || !LoadNtHeaderFromProcess(hProcess, hModule, &inh)) {
        SetLastError(ERROR_INVALID_OPERATION);
        return FALSE;
    }

    // Save the various headers for DetourRestoreAfterWith.
    DETOUR_EXE_RESTORE der;
    if (!RecordExeRestore(hProcess, hModule, der)) {
        return FALSE;
    }

#if defined(_WIN64)
    // Convert a neutral 32-bit managed binary to a 64-bit managed binary.
    if (inh.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && inh.FileHeader.Machine != 0) {
        if (!der.pclr                       // Native binary
            || (der.clr.Flags & COMIMAGE_FLAGS_ILONLY) == 0     // Or mixed-mode MSIL
            || (der.clr.Flags & COMIMAGE_FLAGS_32BITREQUIRED) != 0) {  // Or 32BIT Required MSIL

            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        if (!UpdateFrom32To64(hProcess, hModule, der)) {
            return FALSE;
        }
    }
#endif // _WIN64

    // The process architecture matches this DLL, so the executable now uses its native header layout.
    if (!UpdateImports(hProcess, hModule, lpDll)) {
        return FALSE;
    }

    /////////////////////////////////////////////////// Update the CLR header.
    //
    if (der.pclr != NULL) {
        DETOUR_CLR_HEADER clr;
        CopyMemory(&clr, &der.clr, sizeof(clr));
        clr.Flags &= ~COMIMAGE_FLAGS_ILONLY;    // Clear the IL_ONLY flag.

        DWORD dwProtect;
        if (!MakeWritable(hProcess, der.pclr, sizeof(clr), &dwProtect)) {
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, der.pclr, &clr, sizeof(clr), NULL)) {
            return FALSE;
        }

        if (!VirtualProtectEx(hProcess, der.pclr, sizeof(clr), dwProtect, &dwProtect)) {
            return FALSE;
        }
    }

    //////////////////////////////// Save the undo data to the target process.
    //
    if (!DetourCopyPayloadToProcess(hProcess, DETOUR_EXE_RESTORE_GUID, &der, sizeof(der))) {
        return FALSE;
    }
    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
//

static BOOL WINAPI DetourCopyPayloadToProcess(_In_ HANDLE hProcess,
                                       _In_ REFGUID rguid,
                                       _In_reads_bytes_(cbData) LPCVOID pvData,
                                       _In_ DWORD cbData)
{
    if (hProcess == NULL || pvData == NULL ||
        cbData > MAXDWORD - sizeof(DETOUR_PAYLOAD_HEADER)) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    const SIZE_T totalSize = sizeof(DETOUR_PAYLOAD_HEADER) + cbData;
    const auto base = static_cast<PBYTE>(VirtualAllocEx(
        hProcess, NULL, totalSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
    if (base == NULL) {
        return FALSE;
    }

    const DETOUR_PAYLOAD_HEADER header{ DETOUR_PAYLOAD_SIGNATURE, rguid, cbData, 0 };
    SIZE_T written = 0;
    const bool copied =
        WriteProcessMemory(hProcess, base, &header, sizeof(header), &written) &&
        written == sizeof(header) &&
        WriteProcessMemory(hProcess, base + sizeof(header), pvData, cbData, &written) &&
        written == cbData;

    if (!copied) {
        VirtualFreeEx(hProcess, base, 0, MEM_RELEASE);
        return FALSE;
    }

    SetLastError(NO_ERROR);
    return TRUE;
}

static PDETOUR_EXE_HELPER s_pHelper = NULL;

extern "C" VOID CALLBACK DetourFinishHelperProcess(_In_ HWND,
                                        _In_ HINSTANCE,
                                        _In_ LPSTR,
                                        _In_ INT)
{
    DWORD result = ERROR_INVALID_DATA;
    if (s_pHelper != NULL) {
        constexpr DWORD access = PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
            PROCESS_VM_READ | PROCESS_VM_WRITE;
        HANDLE process = OpenProcess(access, FALSE, s_pHelper->pid);
        if (process != NULL) {
            WORD processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            WORD nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
            if (UpdateProcessWithDll(
                    process, s_pHelper->dll, processMachine, nativeMachine)) {
                result = NO_ERROR;
            }
            else {
                result = GetLastError();
                if (result == NO_ERROR) {
                    result = ERROR_DLL_INIT_FAILED;
                }
            }
            CloseHandle(process);
        }
        else {
            result = GetLastError();
        }
    }

    if (s_pHelper != NULL) {
        DetourFreePayload(s_pHelper);
        s_pHelper = NULL;
    }

    ExitProcess(result);
}

extern "C" BOOL WINAPI DetourIsHelperProcess(VOID)
{
    DWORD cbData = 0;
    const auto helper = static_cast<PDETOUR_EXE_HELPER>(DetourFindPayload(DETOUR_EXE_HELPER_GUID, cbData));
    if (helper == NULL || cbData != sizeof(*helper) || memchr(helper->dll, '\0', sizeof(helper->dll)) == NULL) {
        return FALSE;
    }

    s_pHelper = helper;
    return TRUE;
}

static BOOL ValidateHelperImage(LPCSTR path, WORD expectedMachine)
{
    HANDLE file = CreateFileA(
        path, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    DWORD error = NO_ERROR;
    IMAGE_DOS_HEADER dosHeader{};
    DWORD bytesRead = 0;
    if (!ReadFile(file, &dosHeader, sizeof(dosHeader), &bytesRead, NULL) ||
        bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE ||
        dosHeader.e_lfanew <= 0) {
        error = ERROR_BAD_EXE_FORMAT;
    }

    LARGE_INTEGER fileSize{};
    const LONGLONG ntHeaderSize =
        sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (error == NO_ERROR &&
        (!GetFileSizeEx(file, &fileSize) ||
         dosHeader.e_lfanew > fileSize.QuadPart - ntHeaderSize)) {
        error = ERROR_BAD_EXE_FORMAT;
    }

    LARGE_INTEGER ntOffset{};
    ntOffset.QuadPart = dosHeader.e_lfanew;
    DWORD signature = 0;
    IMAGE_FILE_HEADER fileHeader{};
    if (error == NO_ERROR &&
        (!SetFilePointerEx(file, ntOffset, NULL, FILE_BEGIN) ||
         !ReadFile(file, &signature, sizeof(signature), &bytesRead, NULL) ||
         bytesRead != sizeof(signature) || signature != IMAGE_NT_SIGNATURE ||
         !ReadFile(file, &fileHeader, sizeof(fileHeader), &bytesRead, NULL) ||
         bytesRead != sizeof(fileHeader))) {
        error = ERROR_BAD_EXE_FORMAT;
    }

    if (error == NO_ERROR &&
        fileHeader.Machine != expectedMachine) {
        error = ERROR_EXE_MACHINE_TYPE_MISMATCH;
    }

    CloseHandle(file);
    SetLastError(error);
    return error == NO_ERROR;
}

static BOOL AppendPathSuffix(WCHAR* path, DWORD capacity, LPCWSTR suffix)
{
    const size_t length = wcsnlen_s(path, capacity);
    const size_t suffixLength = wcslen(suffix);
    if (length == capacity || length + suffixLength + 1 > capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    CopyMemory(path + length, suffix, (suffixLength + 1) * sizeof(WCHAR));
    return TRUE;
}

static BOOL GetHelperExecutableW(WORD targetMachine, WCHAR (&path)[MAX_PATH])
{
    DWORD length = 0;
    if (targetMachine == IMAGE_FILE_MACHINE_I386) {
        length = GetSystemWow64DirectoryW(path, ARRAYSIZE(path));
    }
#if defined(_M_IX86)
    else {
        length = GetWindowsDirectoryW(path, ARRAYSIZE(path));
        if (length != 0 && length < ARRAYSIZE(path) &&
            !AppendPathSuffix(path, ARRAYSIZE(path), L"\\sysnative")) {
            return FALSE;
        }
    }
#else
    else {
        length = GetSystemDirectoryW(path, ARRAYSIZE(path));
    }
#endif
    if (length == 0 || length >= ARRAYSIZE(path)) {
        if (length >= ARRAYSIZE(path)) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }
    return AppendPathSuffix(path, ARRAYSIZE(path), L"\\rundll32.exe");
}

static bool HelperNeedsMachineAttribute(WORD targetMachine, WORD nativeMachine)
{
    if (nativeMachine != IMAGE_FILE_MACHINE_ARM64 || targetMachine == IMAGE_FILE_MACHINE_I386) return false;
    if constexpr (DETOUR_CURRENT_PROCESS_MACHINE == IMAGE_FILE_MACHINE_AMD64) return true;
    return targetMachine == IMAGE_FILE_MACHINE_AMD64;
}

static LPPROC_THREAD_ATTRIBUTE_LIST CreateMachineAttributeList(WORD* targetMachine)
{
    SIZE_T size = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &size);
    if (size == 0) {
        return NULL;
    }

    auto storage = new (std::nothrow) BYTE[size];
    if (storage == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    const auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(storage);
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size)) {
        const DWORD error = GetLastError();
        delete[] storage;
        SetLastError(error);
        return NULL;
    }
    if (!UpdateProcThreadAttribute(attributes, 0,
                                   DETOUR_PROC_THREAD_ATTRIBUTE_MACHINE_TYPE,
                                   targetMachine, sizeof(*targetMachine), NULL, NULL)) {
        const DWORD error = GetLastError();
        DeleteProcThreadAttributeList(attributes);
        delete[] storage;
        SetLastError(error);
        return NULL;
    }
    return attributes;
}

static void DeleteMachineAttributeList(LPPROC_THREAD_ATTRIBUTE_LIST attributes)
{
    if (attributes != NULL) {
        DeleteProcThreadAttributeList(attributes);
        delete[] reinterpret_cast<PBYTE>(attributes);
    }
}

static BOOL FinishHelperProcess(PROCESS_INFORMATION& processInformation)
{
    DWORD error = NO_ERROR;
    if (ResumeThread(processInformation.hThread) == MAXDWORD) {
        error = GetLastError();
    }
    else {
        switch (WaitForSingleObject(
            processInformation.hProcess, DETOUR_HELPER_PROCESS_TIMEOUT_MS)) {
        case WAIT_OBJECT_0: {
            DWORD exitCode = ERROR_DLL_INIT_FAILED;
            if (!GetExitCodeProcess(processInformation.hProcess, &exitCode)) {
                error = GetLastError();
            }
            else if (exitCode != NO_ERROR) {
                error = exitCode;
            }
            break;
        }
        case WAIT_TIMEOUT:
            error = ERROR_TIMEOUT;
            break;
        default:
            error = GetLastError();
            break;
        }
    }

    if (error != NO_ERROR) {
        TerminateProcess(processInformation.hProcess, error);
        WaitForSingleObject(processInformation.hProcess,
                            DETOUR_HELPER_TERMINATION_TIMEOUT_MS);
    }
    CloseHandle(processInformation.hProcess);
    CloseHandle(processInformation.hThread);
    SetLastError(error);
    return error == NO_ERROR;
}

static BOOL WINAPI DetourProcessViaHelperW(
    DWORD targetPid, LPCSTR dllName, WORD targetMachine, WORD nativeMachine,
    decltype(&CreateProcessW) createProcess)
{
    DETOUR_EXE_HELPER helper{ targetPid };
    if (strcpy_s(helper.dll, dllName) != 0) {
        SetLastError(ERROR_BAD_PATHNAME);
        return FALSE;
    }

    BOOL result = FALSE;
    DWORD error = NO_ERROR;
    WCHAR executable[MAX_PATH]{};
    WCHAR wideDllName[DETOUR_MAX_DLL_PATH]{};
    WCHAR command[DETOUR_MAX_DLL_PATH + ARRAYSIZE(L"rundll32.exe \"\",#1")]{};
    PROCESS_INFORMATION processInformation{};
    STARTUPINFOEXW startupInfo{};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;

    // An ANSI path never needs more UTF-16 units than bytes, so both buffers hold any bounded path.
    if (MultiByteToWideChar(CP_ACP, 0, helper.dll, -1, wideDllName, ARRAYSIZE(wideDllName)) <= 0 ||
        !ValidateHelperImage(helper.dll, targetMachine) ||
        !GetHelperExecutableW(targetMachine, executable)) {
        error = GetLastError();
    }
    else if (swprintf_s(command, L"rundll32.exe \"%ls\",#1", wideDllName) < 0) {
        error = ERROR_INSUFFICIENT_BUFFER;
    }

    if (error == NO_ERROR) {
        DWORD flags = CREATE_SUSPENDED;
        startupInfo.StartupInfo.cb = sizeof(STARTUPINFOW);
        if (HelperNeedsMachineAttribute(targetMachine, nativeMachine)) {
            attributes = CreateMachineAttributeList(&targetMachine);
            if (attributes == NULL) {
                error = GetLastError();
            }
            else {
                startupInfo.lpAttributeList = attributes;
                startupInfo.StartupInfo.cb = sizeof(startupInfo);
                flags |= EXTENDED_STARTUPINFO_PRESENT;
            }
        }

        if (error == NO_ERROR) {
            // Preserve the native callback's output guarantees for static analysis.
            _Success_(return != 0) typedef BOOL WINAPI CreateProcessFunction(
                _In_opt_ LPCWSTR app, _Inout_opt_ LPWSTR commandLine,
                _In_opt_ LPSECURITY_ATTRIBUTES processAttributes, _In_opt_ LPSECURITY_ATTRIBUTES threadAttributes,
                BOOL inherit, DWORD creationFlags, _In_opt_ LPVOID environment, _In_opt_ LPCWSTR directory,
                _In_ LPSTARTUPINFOW startup, _Out_ _At_(information->hProcess, _Post_notnull_)
                _At_(information->hThread, _Post_notnull_) LPPROCESS_INFORMATION information);
            CreateProcessFunction* createHelperProcess = createProcess;
            if (!createHelperProcess(executable, command, NULL, NULL, FALSE, flags,
                                    NULL, NULL, &startupInfo.StartupInfo, &processInformation)) {
                error = GetLastError();
            }
            else if (!DetourCopyPayloadToProcess(processInformation.hProcess, DETOUR_EXE_HELPER_GUID,
                                                &helper, sizeof(helper))) {
                error = GetLastError();
                TerminateProcess(processInformation.hProcess, error);
                CloseHandle(processInformation.hProcess);
                CloseHandle(processInformation.hThread);
            }
            else {
                result = FinishHelperProcess(processInformation);
                error = GetLastError();
            }
        }
    }

    DeleteMachineAttributeList(attributes);
    SetLastError(result ? NO_ERROR : error);
    return result;
}

bool winpriv::loader::InjectLibrary(HANDLE process, LPCVOID payload, DWORD size,
    decltype(&CreateProcessW) createProcess)
{
    if (payload == nullptr || size < sizeof(LibraryBundle) || size > MAXDWORD - sizeof(DETOUR_PAYLOAD_HEADER))
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return false;
    }

    // Let the target's native Windows loader initialize the DLL before its entry point runs.
    const auto& paths = static_cast<const LibraryBundle*>(payload)->paths;
    WORD machine = IMAGE_FILE_MACHINE_UNKNOWN;
    WORD nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL injected = UpdateProcessWithDll(process, paths[currentLibrary], machine, nativeMachine);
    if (!injected && GetLastError() == ERROR_EXE_MACHINE_TYPE_MISMATCH)
    {
        // A helper of the target architecture injects that architecture's DLL from the same bundle.
        constexpr WORD machines[]{ IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64 };
        const auto target = static_cast<size_t>(std::ranges::find(machines, machine) - std::begin(machines));
        injected = target < std::size(machines) &&
            DetourProcessViaHelperW(GetProcessId(process), paths[target], machine, nativeMachine, createProcess);
    }
    return injected && DetourCopyPayloadToProcess(process, payloadGuid, payload, size);
}
