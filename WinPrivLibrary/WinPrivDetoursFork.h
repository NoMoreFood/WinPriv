/*
# Microsoft Detours source subset

WinPriv includes a consolidated Microsoft Detours 4.0.1 source subset derived
from upstream commit `d644ce94e8c7f7f5a31591577c78134ea3ac1fae`, including
Microsoft's ARM64 correctness fixes. The upstream license and fork provenance
are reproduced in this file.

The fork is specialized for WinPriv's x86, x64, and ARM64 builds and
its single injected DLL. Generic Detours APIs, multi-DLL payloads, optional
disassembler outputs, diagnostics, and compatibility code outside WinPriv's
supported Windows versions have been removed. Internal handoff data uses a
compact private payload record instead of a fabricated PE image. Architecture
selection uses MSVC's predefined `_M_IX86`, `_M_X64`, `_M_ARM64`, and `_WIN64`
macros directly.

The implementation lives in `WinPrivDetoursFork.cpp`. Its C-compatible public
surface and C++20 transaction wrapper live in `WinPrivDetoursFork.h`; PE
records, instruction relocation, payload storage, and process injection
remain private to the implementation translation unit.

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

//////////////////////////////////////////////////////////////////////////////
//
//  WinPriv's private Microsoft Detours 4.0.1 fork API.
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

#pragma once

#include <Windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef BOOL(WINAPI* PDETOUR_CREATE_PROCESS_ROUTINEA)(
    LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);

typedef BOOL(WINAPI* PDETOUR_CREATE_PROCESS_ROUTINEW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD,
    LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

LONG WINAPI DetourTransactionBegin(void);
LONG WINAPI DetourTransactionAbort(void);
LONG WINAPI DetourTransactionCommit(void);
LONG WINAPI DetourAttach(PVOID* target, PVOID replacement);
LONG WINAPI DetourDetach(PVOID* target, PVOID replacement);

BOOL WINAPI DetourCreateProcessWithDllExA(
    LPCSTR applicationName, LPSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles, DWORD creationFlags, LPVOID environment,
    LPCSTR currentDirectory, LPSTARTUPINFOA startupInfo,
    LPPROCESS_INFORMATION processInformation, LPCSTR dllName,
    const GUID* payloadGuid, LPCVOID payloadData, DWORD payloadSize,
    PDETOUR_CREATE_PROCESS_ROUTINEA createProcess);

BOOL WINAPI DetourCreateProcessWithDllExW(
    LPCWSTR applicationName, LPWSTR commandLine,
    LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes,
    BOOL inheritHandles, DWORD creationFlags, LPVOID environment,
    LPCWSTR currentDirectory, LPSTARTUPINFOW startupInfo,
    LPPROCESS_INFORMATION processInformation, LPCSTR dllName,
    const GUID* payloadGuid, LPCVOID payloadData, DWORD payloadSize,
    PDETOUR_CREATE_PROCESS_ROUTINEW createProcess);

PVOID WINAPI DetourFindPayload(const GUID* guid, DWORD* dataSize);
BOOL WINAPI DetourFreePayload(PVOID data);
BOOL WINAPI DetourRestoreAfterWith(void);
BOOL WINAPI DetourIsHelperProcess(void);

#ifdef __cplusplus
}

#include <type_traits>
#include <utility>

namespace winpriv::detours
{
    enum class action : bool
    {
        detach,
        attach,
    };

    template <typename Type>
    concept function_pointer =
        std::is_pointer_v<Type> && std::is_function_v<std::remove_pointer_t<Type>>;

    template <function_pointer Function>
    [[nodiscard]] inline LONG apply(
        action requestedAction, Function& target, Function replacement) noexcept
    {
        auto targetAddress = reinterpret_cast<PVOID*>(&target);
        auto replacementAddress = reinterpret_cast<PVOID>(replacement);
        return requestedAction == action::attach
            ? DetourAttach(targetAddress, replacementAddress)
            : DetourDetach(targetAddress, replacementAddress);
    }

    class transaction final
    {
    public:
        transaction() noexcept
            : result_(DetourTransactionBegin()), active_(result_ == NO_ERROR)
        {
        }

        transaction(const transaction&) = delete;
        transaction& operator=(const transaction&) = delete;
        transaction(transaction&&) = delete;
        transaction& operator=(transaction&&) = delete;

        ~transaction()
        {
            if (active_)
            {
                (void)DetourTransactionAbort();
            }
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return active_;
        }

        template <function_pointer Function>
        [[nodiscard]] LONG apply(
            action requestedAction, Function& target, Function replacement) noexcept
        {
            return active_
                ? detours::apply(requestedAction, target, replacement)
                : result_;
        }

        [[nodiscard]] LONG commit() noexcept
        {
            if (!std::exchange(active_, false))
            {
                return result_;
            }

            result_ = DetourTransactionCommit();
            return result_;
        }

    private:
        LONG result_;
        bool active_;
    };
}
#endif
