/*
# Microsoft Detours source subset

WinPriv includes a consolidated Microsoft Detours 4.0.1 source subset derived
from upstream commit `d644ce94e8c7f7f5a31591577c78134ea3ac1fae`, including
Microsoft's ARM64 correctness fixes. The upstream license and fork provenance
are reproduced in this file.

The fork provides instruction relocation and permanent hook attachment for
WinPriv's x86, x64, and ARM64 builds. Transactions suspend peer threads while
publishing hooks and retain published trampolines for the process lifetime.
Architecture selection uses MSVC's predefined target macros directly.

The implementation lives in `WinPrivDetoursFork.cpp`. Its C-compatible public
surface and C++20 transaction wrapper live in `WinPrivDetoursFork.h`.

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

extern "C" {

LONG WINAPI DetourTransactionBegin(void);
LONG WINAPI DetourTransactionAbort(void);
LONG WINAPI DetourTransactionCommit(void);
LONG WINAPI DetourAttach(PVOID* target, PVOID replacement);
LONG WINAPI DetourAttachTransaction(PVOID* target, PVOID replacement);

}

#include <type_traits>
#include <utility>
#include "WinPrivDynamicCode.h"

namespace winpriv::detours
{
    template <typename Type>
    concept function_pointer =
        std::is_pointer_v<Type> && std::is_function_v<std::remove_pointer_t<Type>>;

    template <function_pointer Function>
    [[nodiscard]] inline LONG attach(Function& target, Function replacement) noexcept
    {
        auto targetAddress = reinterpret_cast<PVOID*>(&target);
        auto replacementAddress = reinterpret_cast<PVOID>(replacement);
        return DetourAttach(targetAddress, replacementAddress);
    }

    class transaction final
    {
    public:
        transaction() noexcept
        {
            result_ = dynamicCode_.Result();
            if (result_ != NO_ERROR) return;

            result_ = DetourTransactionBegin();
            active_ = result_ == NO_ERROR;
            if (!active_)
            {
                dynamicCode_.Restore();
            }
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
            dynamicCode_.Restore();
        }

        [[nodiscard]] explicit operator bool() const noexcept
        {
            return active_;
        }

        template <function_pointer Function>
        [[nodiscard]] LONG attach(Function& target, Function replacement) noexcept
        {
            return active_
                ? detours::attach(target, replacement)
                : result_;
        }

        [[nodiscard]] LONG commit() noexcept
        {
            if (!std::exchange(active_, false))
            {
                return result_;
            }

            result_ = DetourTransactionCommit();
            dynamicCode_.Restore();
            return result_;
        }

    private:
        DynamicCodeScope dynamicCode_;
        LONG result_ = NO_ERROR;
        bool active_ = false;
    };
}
