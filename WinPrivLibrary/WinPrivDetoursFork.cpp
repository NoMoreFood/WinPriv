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
records, instruction relocation, payload handling, and process injection
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
//  WinPriv's private Microsoft Detours 4.0.1 fork implementation.
//  Copyright (c) Microsoft Corporation. All rights reserved.
//

#include "WinPrivDetoursFork.h"

#include <TlHelp32.h>

#include <climits>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <new>
#include <vector>

struct _DETOUR_TRAMPOLINE;
using DETOUR_TRAMPOLINE = _DETOUR_TRAMPOLINE;
using PDETOUR_TRAMPOLINE = DETOUR_TRAMPOLINE*;

struct DETOUR_ALIGN
{
    BYTE targetEnd;
    BYTE trampolineEnd;
};

static_assert(sizeof(DETOUR_ALIGN) == 2);

constexpr DWORD DETOUR_MAX_SUPPORTED_IMAGE_SECTION_HEADERS = 32;
constexpr SIZE_T MM_ALLOCATION_GRANULARITY = 0x10000;
constexpr DWORD DETOUR_HELPER_PROCESS_TIMEOUT_MS = 30000;
constexpr DWORD DETOUR_HELPER_TERMINATION_TIMEOUT_MS = 5000;
constexpr DWORD DETOUR_THREAD_ENUMERATION_RETRY_LIMIT = 64;
constexpr size_t DETOUR_MAX_DLL_PATH = 4096;
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
    DWORD cbclr;
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
    DWORD cb;
    DWORD pid;
    CHAR dll[1];
};
using PDETOUR_EXE_HELPER = DETOUR_EXE_HELPER*;
#pragma pack(pop)

static_assert(sizeof(IMAGE_NT_HEADERS64) == 0x108);

//////////////////////////////////////////////////////////////////////////////
// Instruction relocation

// Copy one instruction from pSrc to pDst, preserving relative targets.
// The return value points to the following source instruction; plExtra receives
// the number of bytes by which relocation must enlarge the instruction.

//////////////////////////////////////////////////// X86 and X64 Disassembler.
//
//  Includes full support for all x86 chips prior to the Pentium III, and some newer stuff.
//
#if defined(_M_X64) || defined(_M_IX86)

class CDetourDis
{
  public:
    explicit CDetourDis(LONG& extra);

    PBYTE   CopyInstruction(PBYTE pbDst, PBYTE pbSrc);

  public:
    struct COPYENTRY;
    typedef const COPYENTRY * REFCOPYENTRY;

    typedef PBYTE (CDetourDis::* COPYFUNC)(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    // nFlagBits flags.
    enum {
        ADDRESS     = 0x1u,
        NOENLARGE   = 0x2u,
        RAX         = 0x4u,
    };

    // ModR/M Flags
    enum {
        SIB         = 0x10u,
        RIP         = 0x20u,
        NOTSIB      = 0x0fu,
    };

    struct COPYENTRY
    {
        // Many of these fields are often ignored. See ENTRY_DataIgnored.
        ULONG       nFixedSize      : 4;    // Fixed size of opcode
        ULONG       nFixedSize16    : 4;    // Fixed size when 16 bit operand
        ULONG       nModOffset      : 4;    // Offset to mod/rm byte (0=none)
        ULONG       nRelOffset      : 4;    // Offset to relative target.
        ULONG       nFlagBits       : 4;
        COPYFUNC    pfCopy;                 // Function pointer.
    };

  protected:
// These macros define common uses of nFixedSize, nFixedSize16, nModOffset, nRelOffset, nFlagBits, pfCopy.
#define ENTRY_DataIgnored           0, 0, 0, 0, 0,
#define ENTRY_CopyBytes1            { 1, 1, 0, 0, 0, &CDetourDis::CopyBytes }
#ifdef _M_X64
#define ENTRY_CopyBytes1Address     { 9, 5, 0, 0, ADDRESS, &CDetourDis::CopyBytes }
#else
#define ENTRY_CopyBytes1Address     { 5, 3, 0, 0, ADDRESS, &CDetourDis::CopyBytes }
#endif
#define ENTRY_CopyBytes2            { 2, 2, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Jump        { ENTRY_DataIgnored &CDetourDis::CopyBytesJump }
#define ENTRY_CopyBytes2CantJump    { 2, 2, 0, 1, NOENLARGE, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3            { 3, 3, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5         { 5, 3, 0, 0, 0, &CDetourDis::CopyBytes }
#ifdef _M_X64
#define ENTRY_CopyBytes3Or5Rax      { 5, 3, 0, 0, RAX, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5Target   { 5, 5, 0, 1, 0, &CDetourDis::CopyBytes }
#else
#define ENTRY_CopyBytes3Or5Rax      { 5, 3, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Or5Target   { 5, 3, 0, 1, 0, &CDetourDis::CopyBytes }
#endif
#define ENTRY_CopyBytes4            { 4, 4, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes5Or7         { 7, 5, 0, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Mod         { 2, 2, 1, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2Mod1        { 3, 3, 1, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes2ModOperand  { 6, 4, 1, 0, 0, &CDetourDis::CopyBytes }
#define ENTRY_CopyBytes3Mod         { 3, 3, 2, 0, 0, &CDetourDis::CopyBytes } // SSE3 0F 38 opcode modrm
#define ENTRY_CopyBytes3Mod1        { 4, 4, 2, 0, 0, &CDetourDis::CopyBytes } // SSE3 0F 3A opcode modrm .. imm8
#define ENTRY_CopyBytesPrefix       { ENTRY_DataIgnored &CDetourDis::CopyBytesPrefix }
#define ENTRY_CopyBytesSegment      ENTRY_CopyBytesPrefix
#define ENTRY_CopyBytesRax          { ENTRY_DataIgnored &CDetourDis::CopyBytesRax }
#define ENTRY_CopyF2                { ENTRY_DataIgnored &CDetourDis::CopyF2 }
#define ENTRY_CopyF3                ENTRY_CopyBytesPrefix
#define ENTRY_Copy0F                { ENTRY_DataIgnored &CDetourDis::Copy0F }
#define ENTRY_Copy0F78              { ENTRY_DataIgnored &CDetourDis::Copy0F78 }
#define ENTRY_Copy66                { ENTRY_DataIgnored &CDetourDis::Copy66 }
#define ENTRY_Copy67                { ENTRY_DataIgnored &CDetourDis::Copy67 }
#define ENTRY_CopyF6                { ENTRY_DataIgnored &CDetourDis::CopyF6 }
#define ENTRY_CopyF7                { ENTRY_DataIgnored &CDetourDis::CopyF7 }
#define ENTRY_CopyFF                ENTRY_CopyBytes2Mod
#define ENTRY_CopyC7                { ENTRY_DataIgnored &CDetourDis::CopyC7 }
#define ENTRY_CopyVex2              { ENTRY_DataIgnored &CDetourDis::CopyVex2 }
#define ENTRY_CopyVex3              { ENTRY_DataIgnored &CDetourDis::CopyVex3 }
#define ENTRY_CopyEvex              { ENTRY_DataIgnored &CDetourDis::CopyEvex } // 62, 3 byte payload, then normal with implied prefixes like vex
#define ENTRY_CopyXop               { ENTRY_DataIgnored &CDetourDis::CopyXop }   // 0x8F ... POP /0 or AMD XOP
#define ENTRY_CopyRex2              { ENTRY_DataIgnored &CDetourDis::CopyRex2 }  // 0xD5 Intel APX REX2 (x64 only)
#define ENTRY_CopyBytesXop          { 5, 5, 4, 0, 0, &CDetourDis::CopyBytes } // 0x8F xop1 xop2 opcode modrm
#define ENTRY_CopyBytesXop1         { 6, 6, 4, 0, 0, &CDetourDis::CopyBytes } // 0x8F xop1 xop2 opcode modrm ... imm8
#define ENTRY_CopyBytesXop4         { 9, 9, 4, 0, 0, &CDetourDis::CopyBytes } // 0x8F xop1 xop2 opcode modrm ... imm32
#define ENTRY_Invalid               { ENTRY_DataIgnored &CDetourDis::Invalid }

    PBYTE CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
#ifdef _M_X64
    PBYTE CopyBytesRax(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
#endif
    PBYTE CopyBytesJump(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    PBYTE Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);

    void AdjustTarget(PBYTE pbDst, PBYTE pbSrc,
                      UINT cbTargetOffset, UINT cbTargetSize);

  protected:
    PBYTE Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy0F78(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); // vmread, 66/extrq/ib/ib, F2/insertq/ib/ib
    PBYTE Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyC7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVex2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVex3(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVexEvexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc, BYTE p, BYTE fp16 = 0);
    PBYTE CopyEvex(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyXop(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc);
#ifdef _M_X64
    PBYTE CopyRex2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc); // AMD64 only, Intel APX REX2
#endif

  protected:
    static const COPYENTRY  s_rceCopyTable[];
    static const COPYENTRY  s_rceCopyTable0F[];
    static const BYTE       s_rbModRm[256];

  protected:
    bool                m_bOperandOverride : 1 = false;
    bool                m_bAddressOverride : 1 = false;
#ifdef _M_X64
    bool                m_bRaxOverride : 1 = false;
#endif
    bool                m_bVex : 1 = false;
    bool                m_bEvex : 1 = false;
    bool                m_bF2 : 1 = false;
    LONG&               m_lExtra;
};

static PVOID WINAPI DetourCopyInstruction(PVOID pDst, PVOID pSrc, LONG* plExtra)
{
    CDetourDis oDetourDisasm(*plExtra);
    return oDetourDisasm.CopyInstruction((PBYTE)pDst, (PBYTE)pSrc);
}

/////////////////////////////////////////////////////////// Disassembler Code.
//
CDetourDis::CDetourDis(LONG& extra) :
    m_lExtra(extra)
{
    m_lExtra = 0;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pbDst, PBYTE pbSrc)
{
    // Figure out how big the instruction is, do the appropriate copy,
    // and relocate any relative target.
    //
    REFCOPYENTRY pEntry = &s_rceCopyTable[pbSrc[0]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytes(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    UINT nBytesFixed;

    UINT const nModOffset = pEntry->nModOffset;
    UINT const nFlagBits = pEntry->nFlagBits;
    UINT const nFixedSize = pEntry->nFixedSize;
    UINT const nFixedSize16 = pEntry->nFixedSize16;

    if (nFlagBits & ADDRESS) {
        nBytesFixed = m_bAddressOverride ? nFixedSize16 : nFixedSize;
    }
#ifdef _M_X64
    // REX.W trumps 66
    else if (m_bRaxOverride) {
        nBytesFixed = nFixedSize + ((nFlagBits & RAX) ? 4 : 0);
    }
#endif
    else if (m_bVex || m_bEvex) {
        // VEX/EVEX pp field does not shrink immediates to 16-bit.
        // This matters for EVEX MAP4 (APX) where entries like opcode 81
        // (Group 1 imm32) have nFixedSize=6 but nFixedSize16=4.
        nBytesFixed = nFixedSize;
    }
    else {
        nBytesFixed = m_bOperandOverride ? nFixedSize16 : nFixedSize;
    }

    UINT nBytes = nBytesFixed;
    UINT nRelOffset = pEntry->nRelOffset;
    UINT cbTarget = nBytes - nRelOffset;
    if (nModOffset > 0) {
        BYTE const bModRm = pbSrc[nModOffset];
        BYTE const bFlags = s_rbModRm[bModRm];

        nBytes += bFlags & NOTSIB;

        if (bFlags & SIB) {
            BYTE const bSib = pbSrc[nModOffset + 1];

            if ((bSib & 0x07) == 0x05) {
                if ((bModRm & 0xc0) == 0x00) {
                    nBytes += 4;
                }
                else if ((bModRm & 0xc0) == 0x40) {
                    nBytes += 1;
                }
                else if ((bModRm & 0xc0) == 0x80) {
                    nBytes += 4;
                }
            }
            cbTarget = nBytes - nRelOffset;
        }
#ifdef _M_X64
        else if (bFlags & RIP) {
            nRelOffset = nModOffset + 1;
            cbTarget = 4;
        }
#endif
    }
    CopyMemory(pbDst, pbSrc, nBytes);

    if (nRelOffset) {
        AdjustTarget(pbDst, pbSrc, nRelOffset, cbTarget);
    }
    if (nFlagBits & NOENLARGE) {
        m_lExtra = -m_lExtra;
    }
    return pbSrc + nBytes;
}

PBYTE CDetourDis::CopyBytesPrefix(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    pbDst[0] = pbSrc[0];
    pEntry = &s_rceCopyTable[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

#ifdef _M_X64
PBYTE CDetourDis::CopyBytesRax(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{ // AMD64 only
    if (pbSrc[0] & 0x8) {
        m_bRaxOverride = true;
    }
    return CopyBytesPrefix(0, pbDst, pbSrc);
}
#endif

PBYTE CDetourDis::CopyBytesJump(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    PVOID pvSrcAddr = &pbSrc[1];
    PVOID pvDstAddr = NULL;
    LONG_PTR nOldOffset = (LONG_PTR)*(signed char*&)pvSrcAddr;
    LONG_PTR nNewOffset = 0;

    if (pbSrc[0] == 0xeb) {
        pbDst[0] = 0xe9;
        pvDstAddr = &pbDst[1];
        nNewOffset = nOldOffset - ((pbDst - pbSrc) + 3);
        *(UNALIGNED LONG*&)pvDstAddr = (LONG)nNewOffset;

        m_lExtra = 3;
        return pbSrc + 2;
    }


    pbDst[0] = 0x0f;
    pbDst[1] = 0x80 | (pbSrc[0] & 0xf);
    pvDstAddr = &pbDst[2];
    nNewOffset = nOldOffset - ((pbDst - pbSrc) + 4);
    *(UNALIGNED LONG*&)pvDstAddr = (LONG)nNewOffset;

    m_lExtra = 4;
    return pbSrc + 2;
}

void CDetourDis::AdjustTarget(PBYTE pbDst, PBYTE pbSrc,
                              UINT cbTargetOffset, UINT cbTargetSize)
{
#if defined(_M_X64)
    typedef LONGLONG T;
#else
    typedef LONG T;
#endif
    T nOldOffset;
    T nNewOffset;
    PVOID pvTargetAddr = &pbDst[cbTargetOffset];

    switch (cbTargetSize) {
      case 1:
        nOldOffset = *(signed char*&)pvTargetAddr;
        break;
      case 2:
        nOldOffset = *(UNALIGNED SHORT*&)pvTargetAddr;
        break;
      case 4:
        nOldOffset = *(UNALIGNED LONG*&)pvTargetAddr;
        break;
#if defined(_M_X64)
      case 8:
        nOldOffset = *(UNALIGNED LONGLONG*&)pvTargetAddr;
        break;
#endif
      default:
        nOldOffset = 0;
        break;
    }

    nNewOffset = nOldOffset - (T)(pbDst - pbSrc);

    switch (cbTargetSize) {
      case 1:
        *(CHAR*&)pvTargetAddr = (CHAR)nNewOffset;
        if (nNewOffset < SCHAR_MIN || nNewOffset > SCHAR_MAX) {
            m_lExtra = sizeof(ULONG) - 1;
        }
        break;
      case 2:
        *(UNALIGNED SHORT*&)pvTargetAddr = (SHORT)nNewOffset;
        if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX) {
            m_lExtra = sizeof(ULONG) - 2;
        }
        break;
      case 4:
        *(UNALIGNED LONG*&)pvTargetAddr = (LONG)nNewOffset;
        if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX) {
            m_lExtra = sizeof(ULONG) - 4;
        }
        break;
#if defined(_M_X64)
      case 8:
        *(UNALIGNED LONGLONG*&)pvTargetAddr = nNewOffset;
        break;
#endif
    }
}

PBYTE CDetourDis::Invalid(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pbDst;
    (void)pEntry;
    return pbSrc + 1;
}

////////////////////////////////////////////////////// Individual Bytes Codes.
//
PBYTE CDetourDis::Copy0F(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    pbDst[0] = pbSrc[0];
    pEntry = &s_rceCopyTable0F[pbSrc[1]];
    return (this->*pEntry->pfCopy)(pEntry, pbDst + 1, pbSrc + 1);
}

PBYTE CDetourDis::Copy0F78(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
{
    // vmread, 66/extrq, F2/insertq

    static const COPYENTRY vmread = /* 78 */ ENTRY_CopyBytes2Mod;
    static const COPYENTRY extrq_insertq = /* 78 */ ENTRY_CopyBytes4;


    // For insertq and presumably despite documentation extrq, mode must be 11, not checked.
    // insertq/extrq/78 are followed by two immediate bytes, and given mode == 11, mod/rm byte is always one byte,
    // and the 0x78 makes 4 bytes (not counting the 66/F2/F which are accounted for elsewhere)

    REFCOPYENTRY const pEntry = ((m_bF2 || m_bOperandOverride) ? &extrq_insertq : &vmread);

    return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy66(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   // Operand-size override prefix
    m_bOperandOverride = true;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy67(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{   // Address size override prefix
    m_bAddressOverride = true;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    m_bF2 = true;
    return CopyBytesPrefix(pEntry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF6(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    // TEST BYTE /0 and /1 (both encodings are TEST per Intel SDM Vol 2A Group 3
    // and AMD APM Vol 3; /1 is an undocumented alias of /0 historically but is
    // now documented in both manuals).
    if (0x00 == (0x30 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 000 or 001
        static const COPYENTRY ce = /* f6 */ ENTRY_CopyBytes2Mod1;
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }
    // DIV /6
    // IDIV /7
    // IMUL /5
    // MUL /4
    // NEG /3
    // NOT /2

    static const COPYENTRY ce = /* f6 */ ENTRY_CopyBytes2Mod;
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    // TEST WORD /0 and /1 (see CopyF6 for /1 rationale).
    if (0x00 == (0x30 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 000 or 001
        static const COPYENTRY ce = /* f7 */ ENTRY_CopyBytes2ModOperand;
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }

    // DIV /6
    // IDIV /7
    // IMUL /5
    // MUL /4
    // NEG /3
    // NOT /2
    static const COPYENTRY ce = /* f7 */ ENTRY_CopyBytes2Mod;
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyC7(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
{
    (void)pEntry;

    // C7 /7 is XBEGIN rel32 (or rel16 with 66 prefix).
    // It has a relative displacement that must be relocated like CALL/JMP.
    if (0x38 == (0x38 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 111
        static const COPYENTRY ce = /* c7 /7 */ { 6, 4, 0, 2, 0, &CDetourDis::CopyBytes };
        return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
    }
    // MOV /0 r/m, imm16/32
    static const COPYENTRY ce = /* c7 /0 */ ENTRY_CopyBytes2ModOperand;
    return (this->*ce.pfCopy)(&ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyVexEvexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc, BYTE p, BYTE fp16)
// m is first instead of last in the hopes of pbDst/pbSrc being
// passed along efficiently in the registers they were already in.
{
    static const COPYENTRY ceF38 = /* 38 */ ENTRY_CopyBytes2Mod;
    static const COPYENTRY ceF3A = /* 3A */ ENTRY_CopyBytes2Mod1;
    static const COPYENTRY ceInvalid = /* C4 */ ENTRY_Invalid;

    switch (p & 3) {
    case 0:
    case 2: break;
    case 1: m_bOperandOverride = true; break;
    case 3: m_bF2 = true; break;
    }

    REFCOPYENTRY pEntry;

    // see https://software.intel.com/content/www/us/en/develop/download/intel-avx512-fp16-architecture-specification.html
    // EVEX maps (with FP16 and APX mmm-bit extension):
    //   mmm=001 (MAP1) and mmm=101 (MAP5) share the legacy 0F opcode structure,
    //     so per-opcode sizing must come from s_rceCopyTable0F (e.g. MAP5 C2 /r ib = VCMPPH/VCMPSH).
    //   mmm=010 (MAP2) and mmm=110 (MAP6) share the legacy 0F 38 structure (ModR/M, no imm).
    //   mmm=011 (MAP3) has the 0F 3A structure (ModR/M + imm8).
    //   mmm=100 (MAP4, APX) mirrors legacy MAP0 opcode structure (per-opcode sizing).
    switch (m | fp16) {
    default: return Invalid(&ceInvalid, pbDst, pbSrc);
    case 5:  // MAP5 (FP16) - opcode structure mirrors 0F (MAP1).
    case 1:  pEntry = &s_rceCopyTable0F[pbSrc[0]];
             return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
    case 6:  // MAP6 (FP16) - opcode structure mirrors 0F 38 (MAP2).
    case 2:  return CopyBytes(&ceF38, pbDst, pbSrc);
    case 3:  return CopyBytes(&ceF3A, pbDst, pbSrc);
    case 4:  // MAP4 (APX) - promoted legacy MAP0 instructions.
             pEntry = &s_rceCopyTable[pbSrc[0]];
             return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
    }
}

PBYTE CDetourDis::CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc)
// m is first instead of last in the hopes of pbDst/pbSrc being
// passed along efficiently in the registers they were already in.
{
    m_bVex = true;
    BYTE const p = (BYTE)(pbSrc[-1] & 3); // p in last byte
    return CopyVexEvexCommon(m, pbDst, pbSrc, p);
}

PBYTE CDetourDis::CopyVex3(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
// 3 byte VEX prefix 0xC4
{
#ifdef _M_IX86
    const static COPYENTRY ceLES = /* C4 */ ENTRY_CopyBytes2Mod;
    if ((pbSrc[1] & 0xC0) != 0xC0) {
        REFCOPYENTRY pEntry = &ceLES;
        return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
    }
#endif
    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];
    pbDst[2] = pbSrc[2];
#ifdef _M_X64
    m_bRaxOverride = m_bRaxOverride || (pbSrc[2] & 0x80); // w in last byte, see CopyBytesRax
#else
    //
    // TODO
    //
    // Usually the VEX.W bit changes the size of a general purpose register and is ignored for 32bit.
    // Sometimes it is an opcode extension.
    // Look in the Intel manual, in the instruction-by-instruction reference, for ".W1",
    // without nearby wording saying it is ignored for 32bit.
    // For example: "VFMADD132PD/VFMADD213PD/VFMADD231PD Fused Multiply-Add of Packed Double-Precision Floating-Point Values".
    //
    // Then, go through each such case and determine if W0 vs. W1 affect the size of the instruction. Probably not.
    // Look for the same encoding but with "W1" changed to "W0".
    // Here is one such pairing:
    // VFMADD132PD/VFMADD213PD/VFMADD231PD Fused Multiply-Add of Packed Double-Precision Floating-Point Values
    //
    // VEX.DDS.128.66.0F38.W1 98 /r A V/V FMA Multiply packed double-precision floating-point values
    // from xmm0 and xmm2/mem, add to xmm1 and
    // put result in xmm0.
    // VFMADD132PD xmm0, xmm1, xmm2/m128
    //
    // VFMADD132PS/VFMADD213PS/VFMADD231PS Fused Multiply-Add of Packed Single-Precision Floating-Point Values
    // VEX.DDS.128.66.0F38.W0 98 /r A V/V FMA Multiply packed single-precision floating-point values
    // from xmm0 and xmm2/mem, add to xmm1 and put
    // result in xmm0.
    // VFMADD132PS xmm0, xmm1, xmm2/m128
    //
#endif
    return CopyVexCommon(pbSrc[1] & 0x1F, pbDst + 3, pbSrc + 3);
}

PBYTE CDetourDis::CopyVex2(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
// 2 byte VEX prefix 0xC5
{
#ifdef _M_IX86
    const static COPYENTRY ceLDS = /* C5 */ ENTRY_CopyBytes2Mod;
    if ((pbSrc[1] & 0xC0) != 0xC0) {
        REFCOPYENTRY pEntry = &ceLDS;
        return (this->*pEntry->pfCopy)(pEntry, pbDst, pbSrc);
    }
#endif
    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];
    return CopyVexCommon(1, pbDst + 2, pbSrc + 2);
}

PBYTE CDetourDis::CopyEvex(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
// 62, 3 byte payload, x86 with implied prefixes like Vex
// for 32bit, mode 0xC0 else fallback to bound /r
{
    // NOTE: Intel and Wikipedia number these differently.
    // Intel says 0-2, Wikipedia says 1-3.

    BYTE const p0 = pbSrc[1];

#ifdef _M_IX86
    const static COPYENTRY ceBound = /* 62 */ ENTRY_CopyBytes2Mod;
    if ((p0 & 0xC0) != 0xC0) {
        return CopyBytes(&ceBound, pbDst, pbSrc);
    }
#endif

    static const COPYENTRY ceInvalid = /* 62 */ ENTRY_Invalid;

    BYTE const p1 = pbSrc[2];

    if ((p1 & 0x04) != 0x04)
        return Invalid(&ceInvalid, pbDst, pbSrc);

    // Copy 4 byte prefix.
    *(UNALIGNED ULONG *)pbDst = *(UNALIGNED ULONG*)pbSrc;

    m_bEvex = true;

#ifdef _M_X64
    m_bRaxOverride = m_bRaxOverride || (p1 & 0x80); // w
#endif

    // P0 layout: R'(7) X(6) B3(5) R'4(4) B4(3) m(2) m(1) m(0)
    // Bits [2:0] = map (1-7). Bit 3 = B4 (APX register extension, not a map bit).
    // For FP16: bit 2 extends map (MAP5=101, MAP6=110).
    // For APX:  map=4 (100) uses bit 2 as part of mmm field.
    return CopyVexEvexCommon(p0 & 3u, pbDst + 4, pbSrc + 4, p1 & 3u, p0 & 4u);
}

PBYTE CDetourDis::CopyXop(REFCOPYENTRY, PBYTE pbDst, PBYTE pbSrc)
/* 3 byte AMD XOP prefix 0x8F
byte0: 0x8F
byte1: RXBmmmmm
byte2: WvvvvLpp
byte3: opcode
mmmmm >= 8, else pop
mmmmm only otherwise defined for 8, 9, A.
pp is like VEX but only instructions with 0 are defined
*/
{
    const static COPYENTRY cePop = /* 8F */ ENTRY_CopyBytes2Mod;
    const static COPYENTRY ceXop = /* 8F */ ENTRY_CopyBytesXop;
    const static COPYENTRY ceXop1 = /* 8F */ ENTRY_CopyBytesXop1;
    const static COPYENTRY ceXop4 = /* 8F */ ENTRY_CopyBytesXop4;

    BYTE const m = (BYTE)(pbSrc[1] & 0x1F);
    switch (m)
    {
    default:
        return CopyBytes(&cePop, pbDst, pbSrc);

    case 8: // modrm with 8bit immediate
        return CopyBytes(&ceXop1, pbDst, pbSrc);

    case 9: // modrm with no immediate
        return CopyBytes(&ceXop, pbDst, pbSrc);

    case 10: // modrm with 32bit immediate
        return CopyBytes(&ceXop4, pbDst, pbSrc);
    }
}

#ifdef _M_X64
PBYTE CDetourDis::CopyRex2(REFCOPYENTRY pEntry, PBYTE pbDst, PBYTE pbSrc)
// Intel APX REX2 prefix 0xD5 (64-bit mode only)
// Byte 0: D5
// Byte 1: M(7) R4(6) X4(5) B4(4) W(3) R3(2) X3(1) B3(0)
//   M: 0 = opcode from MAP0, 1 = opcode from MAP1 (no 0F escape needed)
//   W: operand size override to 64-bit (same as REX.W)
{
    (void)pEntry;

    BYTE const payload = pbSrc[1];

    if (payload & 0x08) { // W bit (bit 3)
        m_bRaxOverride = true;
    }

    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];

    PBYTE pbOut;
    if (payload & 0x80) { // M bit (bit 7) - MAP1
        REFCOPYENTRY pEntry2 = &s_rceCopyTable0F[pbSrc[2]];
        pbOut = (this->*pEntry2->pfCopy)(pEntry2, pbDst + 2, pbSrc + 2);
    }
    else { // MAP0
        REFCOPYENTRY pEntry2 = &s_rceCopyTable[pbSrc[2]];
        pbOut = (this->*pEntry2->pfCopy)(pEntry2, pbDst + 2, pbSrc + 2);
    }

    return pbOut;
}
#endif

//////////////////////////////////////////////////////////////////////////////
//

///////////////////////////////////////////////////////// Disassembler Tables.
//
const BYTE CDetourDis::s_rbModRm[256] = {
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 0x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 1x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 2x
    0,0,0,0, SIB|1,RIP|4,0,0, 0,0,0,0, SIB|1,RIP|4,0,0, // 3x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 4x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 5x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 6x
    1,1,1,1, 2,1,1,1, 1,1,1,1, 2,1,1,1,                 // 7x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 8x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // 9x
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Ax
    4,4,4,4, 5,4,4,4, 4,4,4,4, 5,4,4,4,                 // Bx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Cx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Dx
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,                 // Ex
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0                  // Fx
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable[] =
{
    /* 00 */ ENTRY_CopyBytes2Mod,                      // ADD /r
    /* 01 */ ENTRY_CopyBytes2Mod,                      // ADD /r
    /* 02 */ ENTRY_CopyBytes2Mod,                      // ADD /r
    /* 03 */ ENTRY_CopyBytes2Mod,                      // ADD /r
    /* 04 */ ENTRY_CopyBytes2,                         // ADD ib
    /* 05 */ ENTRY_CopyBytes3Or5,                      // ADD iw
#ifdef _M_X64
    /* 06 */ ENTRY_Invalid,                            // Invalid
    /* 07 */ ENTRY_Invalid,                            // Invalid
#else
    /* 06 */ ENTRY_CopyBytes1,                         // PUSH
    /* 07 */ ENTRY_CopyBytes1,                         // POP
#endif
    /* 08 */ ENTRY_CopyBytes2Mod,                      // OR /r
    /* 09 */ ENTRY_CopyBytes2Mod,                      // OR /r
    /* 0A */ ENTRY_CopyBytes2Mod,                      // OR /r
    /* 0B */ ENTRY_CopyBytes2Mod,                      // OR /r
    /* 0C */ ENTRY_CopyBytes2,                         // OR ib
    /* 0D */ ENTRY_CopyBytes3Or5,                      // OR iw
#ifdef _M_X64
    /* 0E */ ENTRY_Invalid,                            // Invalid
#else
    /* 0E */ ENTRY_CopyBytes1,                         // PUSH
#endif
    /* 0F */ ENTRY_Copy0F,                             // Extension Ops
    /* 10 */ ENTRY_CopyBytes2Mod,                      // ADC /r
    /* 11 */ ENTRY_CopyBytes2Mod,                      // ADC /r
    /* 12 */ ENTRY_CopyBytes2Mod,                      // ADC /r
    /* 13 */ ENTRY_CopyBytes2Mod,                      // ADC /r
    /* 14 */ ENTRY_CopyBytes2,                         // ADC ib
    /* 15 */ ENTRY_CopyBytes3Or5,                      // ADC id
#ifdef _M_X64
    /* 16 */ ENTRY_Invalid,                            // Invalid
    /* 17 */ ENTRY_Invalid,                            // Invalid
#else
    /* 16 */ ENTRY_CopyBytes1,                         // PUSH
    /* 17 */ ENTRY_CopyBytes1,                         // POP
#endif
    /* 18 */ ENTRY_CopyBytes2Mod,                      // SBB /r
    /* 19 */ ENTRY_CopyBytes2Mod,                      // SBB /r
    /* 1A */ ENTRY_CopyBytes2Mod,                      // SBB /r
    /* 1B */ ENTRY_CopyBytes2Mod,                      // SBB /r
    /* 1C */ ENTRY_CopyBytes2,                         // SBB ib
    /* 1D */ ENTRY_CopyBytes3Or5,                      // SBB id
#ifdef _M_X64
    /* 1E */ ENTRY_Invalid,                            // Invalid
    /* 1F */ ENTRY_Invalid,                            // Invalid
#else
    /* 1E */ ENTRY_CopyBytes1,                         // PUSH
    /* 1F */ ENTRY_CopyBytes1,                         // POP
#endif
    /* 20 */ ENTRY_CopyBytes2Mod,                      // AND /r
    /* 21 */ ENTRY_CopyBytes2Mod,                      // AND /r
    /* 22 */ ENTRY_CopyBytes2Mod,                      // AND /r
    /* 23 */ ENTRY_CopyBytes2Mod,                      // AND /r
    /* 24 */ ENTRY_CopyBytes2,                         // AND ib
    /* 25 */ ENTRY_CopyBytes3Or5,                      // AND id
    /* 26 */ ENTRY_CopyBytesSegment,                   // ES prefix
#ifdef _M_X64
    /* 27 */ ENTRY_Invalid,                            // Invalid
#else
    /* 27 */ ENTRY_CopyBytes1,                         // DAA
#endif
    /* 28 */ ENTRY_CopyBytes2Mod,                      // SUB /r
    /* 29 */ ENTRY_CopyBytes2Mod,                      // SUB /r
    /* 2A */ ENTRY_CopyBytes2Mod,                      // SUB /r
    /* 2B */ ENTRY_CopyBytes2Mod,                      // SUB /r
    /* 2C */ ENTRY_CopyBytes2,                         // SUB ib
    /* 2D */ ENTRY_CopyBytes3Or5,                      // SUB id
    /* 2E */ ENTRY_CopyBytesSegment,                   // CS prefix
#ifdef _M_X64
    /* 2F */ ENTRY_Invalid,                            // Invalid
#else
    /* 2F */ ENTRY_CopyBytes1,                         // DAS
#endif
    /* 30 */ ENTRY_CopyBytes2Mod,                      // XOR /r
    /* 31 */ ENTRY_CopyBytes2Mod,                      // XOR /r
    /* 32 */ ENTRY_CopyBytes2Mod,                      // XOR /r
    /* 33 */ ENTRY_CopyBytes2Mod,                      // XOR /r
    /* 34 */ ENTRY_CopyBytes2,                         // XOR ib
    /* 35 */ ENTRY_CopyBytes3Or5,                      // XOR id
    /* 36 */ ENTRY_CopyBytesSegment,                   // SS prefix
#ifdef _M_X64
    /* 37 */ ENTRY_Invalid,                            // Invalid
#else
    /* 37 */ ENTRY_CopyBytes1,                         // AAA
#endif
    /* 38 */ ENTRY_CopyBytes2Mod,                      // CMP /r
    /* 39 */ ENTRY_CopyBytes2Mod,                      // CMP /r
    /* 3A */ ENTRY_CopyBytes2Mod,                      // CMP /r
    /* 3B */ ENTRY_CopyBytes2Mod,                      // CMP /r
    /* 3C */ ENTRY_CopyBytes2,                         // CMP ib
    /* 3D */ ENTRY_CopyBytes3Or5,                      // CMP id
    /* 3E */ ENTRY_CopyBytesSegment,                   // DS prefix
#ifdef _M_X64
    /* 3F */ ENTRY_Invalid,                            // Invalid
#else
    /* 3F */ ENTRY_CopyBytes1,                         // AAS
#endif
#ifdef _M_X64 // For Rax Prefix
    /* 40 */ ENTRY_CopyBytesRax,                       // Rax
    /* 41 */ ENTRY_CopyBytesRax,                       // Rax
    /* 42 */ ENTRY_CopyBytesRax,                       // Rax
    /* 43 */ ENTRY_CopyBytesRax,                       // Rax
    /* 44 */ ENTRY_CopyBytesRax,                       // Rax
    /* 45 */ ENTRY_CopyBytesRax,                       // Rax
    /* 46 */ ENTRY_CopyBytesRax,                       // Rax
    /* 47 */ ENTRY_CopyBytesRax,                       // Rax
    /* 48 */ ENTRY_CopyBytesRax,                       // Rax
    /* 49 */ ENTRY_CopyBytesRax,                       // Rax
    /* 4A */ ENTRY_CopyBytesRax,                       // Rax
    /* 4B */ ENTRY_CopyBytesRax,                       // Rax
    /* 4C */ ENTRY_CopyBytesRax,                       // Rax
    /* 4D */ ENTRY_CopyBytesRax,                       // Rax
    /* 4E */ ENTRY_CopyBytesRax,                       // Rax
    /* 4F */ ENTRY_CopyBytesRax,                       // Rax
#else
    /* 40 */ ENTRY_CopyBytes1,                         // INC
    /* 41 */ ENTRY_CopyBytes1,                         // INC
    /* 42 */ ENTRY_CopyBytes1,                         // INC
    /* 43 */ ENTRY_CopyBytes1,                         // INC
    /* 44 */ ENTRY_CopyBytes1,                         // INC
    /* 45 */ ENTRY_CopyBytes1,                         // INC
    /* 46 */ ENTRY_CopyBytes1,                         // INC
    /* 47 */ ENTRY_CopyBytes1,                         // INC
    /* 48 */ ENTRY_CopyBytes1,                         // DEC
    /* 49 */ ENTRY_CopyBytes1,                         // DEC
    /* 4A */ ENTRY_CopyBytes1,                         // DEC
    /* 4B */ ENTRY_CopyBytes1,                         // DEC
    /* 4C */ ENTRY_CopyBytes1,                         // DEC
    /* 4D */ ENTRY_CopyBytes1,                         // DEC
    /* 4E */ ENTRY_CopyBytes1,                         // DEC
    /* 4F */ ENTRY_CopyBytes1,                         // DEC
#endif
    /* 50 */ ENTRY_CopyBytes1,                         // PUSH
    /* 51 */ ENTRY_CopyBytes1,                         // PUSH
    /* 52 */ ENTRY_CopyBytes1,                         // PUSH
    /* 53 */ ENTRY_CopyBytes1,                         // PUSH
    /* 54 */ ENTRY_CopyBytes1,                         // PUSH
    /* 55 */ ENTRY_CopyBytes1,                         // PUSH
    /* 56 */ ENTRY_CopyBytes1,                         // PUSH
    /* 57 */ ENTRY_CopyBytes1,                         // PUSH
    /* 58 */ ENTRY_CopyBytes1,                         // POP
    /* 59 */ ENTRY_CopyBytes1,                         // POP
    /* 5A */ ENTRY_CopyBytes1,                         // POP
    /* 5B */ ENTRY_CopyBytes1,                         // POP
    /* 5C */ ENTRY_CopyBytes1,                         // POP
    /* 5D */ ENTRY_CopyBytes1,                         // POP
    /* 5E */ ENTRY_CopyBytes1,                         // POP
    /* 5F */ ENTRY_CopyBytes1,                         // POP
#ifdef _M_X64
    /* 60 */ ENTRY_Invalid,                            // Invalid
    /* 61 */ ENTRY_Invalid,                            // Invalid
    /* 62 */ ENTRY_CopyEvex,                           // EVEX / AVX512
#else
    /* 60 */ ENTRY_CopyBytes1,                         // PUSHAD
    /* 61 */ ENTRY_CopyBytes1,                         // POPAD
    /* 62 */ ENTRY_CopyEvex,                           // BOUND /r and EVEX / AVX512
#endif
    /* 63 */ ENTRY_CopyBytes2Mod,                      // 32bit ARPL /r, 64bit MOVSXD
    /* 64 */ ENTRY_CopyBytesSegment,                   // FS prefix
    /* 65 */ ENTRY_CopyBytesSegment,                   // GS prefix
    /* 66 */ ENTRY_Copy66,                             // Operand Prefix
    /* 67 */ ENTRY_Copy67,                             // Address Prefix
    /* 68 */ ENTRY_CopyBytes3Or5,                      // PUSH
    /* 69 */ ENTRY_CopyBytes2ModOperand,               // IMUL /r iz
    /* 6A */ ENTRY_CopyBytes2,                         // PUSH
    /* 6B */ ENTRY_CopyBytes2Mod1,                     // IMUL /r ib
    /* 6C */ ENTRY_CopyBytes1,                         // INS
    /* 6D */ ENTRY_CopyBytes1,                         // INS
    /* 6E */ ENTRY_CopyBytes1,                         // OUTS/OUTSB
    /* 6F */ ENTRY_CopyBytes1,                         // OUTS/OUTSW
    /* 70 */ ENTRY_CopyBytes2Jump,                     // JO           // 0f80
    /* 71 */ ENTRY_CopyBytes2Jump,                     // JNO          // 0f81
    /* 72 */ ENTRY_CopyBytes2Jump,                     // JB/JC/JNAE   // 0f82
    /* 73 */ ENTRY_CopyBytes2Jump,                     // JAE/JNB/JNC  // 0f83
    /* 74 */ ENTRY_CopyBytes2Jump,                     // JE/JZ        // 0f84
    /* 75 */ ENTRY_CopyBytes2Jump,                     // JNE/JNZ      // 0f85
    /* 76 */ ENTRY_CopyBytes2Jump,                     // JBE/JNA      // 0f86
    /* 77 */ ENTRY_CopyBytes2Jump,                     // JA/JNBE      // 0f87
    /* 78 */ ENTRY_CopyBytes2Jump,                     // JS           // 0f88
    /* 79 */ ENTRY_CopyBytes2Jump,                     // JNS          // 0f89
    /* 7A */ ENTRY_CopyBytes2Jump,                     // JP/JPE       // 0f8a
    /* 7B */ ENTRY_CopyBytes2Jump,                     // JNP/JPO      // 0f8b
    /* 7C */ ENTRY_CopyBytes2Jump,                     // JL/JNGE      // 0f8c
    /* 7D */ ENTRY_CopyBytes2Jump,                     // JGE/JNL      // 0f8d
    /* 7E */ ENTRY_CopyBytes2Jump,                     // JLE/JNG      // 0f8e
    /* 7F */ ENTRY_CopyBytes2Jump,                     // JG/JNLE      // 0f8f
    /* 80 */ ENTRY_CopyBytes2Mod1,                     // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate byte
    /* 81 */ ENTRY_CopyBytes2ModOperand,               // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 byte reg, immediate word or dword
#ifdef _M_X64
    /* 82 */ ENTRY_Invalid,                            // Invalid
#else
    /* 82 */ ENTRY_CopyBytes2Mod1,                     // MOV al,x
#endif
    /* 83 */ ENTRY_CopyBytes2Mod1,                     // ADD/0 OR/1 ADC/2 SBB/3 AND/4 SUB/5 XOR/6 CMP/7 reg, immediate byte
    /* 84 */ ENTRY_CopyBytes2Mod,                      // TEST /r
    /* 85 */ ENTRY_CopyBytes2Mod,                      // TEST /r
    /* 86 */ ENTRY_CopyBytes2Mod,                      // XCHG /r @todo
    /* 87 */ ENTRY_CopyBytes2Mod,                      // XCHG /r @todo
    /* 88 */ ENTRY_CopyBytes2Mod,                      // MOV /r
    /* 89 */ ENTRY_CopyBytes2Mod,                      // MOV /r
    /* 8A */ ENTRY_CopyBytes2Mod,                      // MOV /r
    /* 8B */ ENTRY_CopyBytes2Mod,                      // MOV /r
    /* 8C */ ENTRY_CopyBytes2Mod,                      // MOV /r
    /* 8D */ ENTRY_CopyBytes2Mod,                      // LEA /r
    /* 8E */ ENTRY_CopyBytes2Mod,                      // MOV /r
    /* 8F */ ENTRY_CopyXop,                            // POP /0 or AMD XOP
    /* 90 */ ENTRY_CopyBytes1,                         // NOP
    /* 91 */ ENTRY_CopyBytes1,                         // XCHG
    /* 92 */ ENTRY_CopyBytes1,                         // XCHG
    /* 93 */ ENTRY_CopyBytes1,                         // XCHG
    /* 94 */ ENTRY_CopyBytes1,                         // XCHG
    /* 95 */ ENTRY_CopyBytes1,                         // XCHG
    /* 96 */ ENTRY_CopyBytes1,                         // XCHG
    /* 97 */ ENTRY_CopyBytes1,                         // XCHG
    /* 98 */ ENTRY_CopyBytes1,                         // CWDE
    /* 99 */ ENTRY_CopyBytes1,                         // CDQ
#ifdef _M_X64
    /* 9A */ ENTRY_Invalid,                            // Invalid
#else
    /* 9A */ ENTRY_CopyBytes5Or7,                      // CALL cp
#endif
    /* 9B */ ENTRY_CopyBytes1,                         // WAIT/FWAIT
    /* 9C */ ENTRY_CopyBytes1,                         // PUSHFD
    /* 9D */ ENTRY_CopyBytes1,                         // POPFD
    /* 9E */ ENTRY_CopyBytes1,                         // SAHF
    /* 9F */ ENTRY_CopyBytes1,                         // LAHF
    /* A0 */ ENTRY_CopyBytes1Address,                  // MOV
    /* A1 */ ENTRY_CopyBytes1Address,                  // MOV
    /* A2 */ ENTRY_CopyBytes1Address,                  // MOV
    /* A3 */ ENTRY_CopyBytes1Address,                  // MOV
    /* A4 */ ENTRY_CopyBytes1,                         // MOVS
    /* A5 */ ENTRY_CopyBytes1,                         // MOVS/MOVSD
    /* A6 */ ENTRY_CopyBytes1,                         // CMPS/CMPSB
    /* A7 */ ENTRY_CopyBytes1,                         // CMPS/CMPSW
    /* A8 */ ENTRY_CopyBytes2,                         // TEST
    /* A9 */ ENTRY_CopyBytes3Or5,                      // TEST
    /* AA */ ENTRY_CopyBytes1,                         // STOS/STOSB
    /* AB */ ENTRY_CopyBytes1,                         // STOS/STOSW
    /* AC */ ENTRY_CopyBytes1,                         // LODS/LODSB
    /* AD */ ENTRY_CopyBytes1,                         // LODS/LODSW
    /* AE */ ENTRY_CopyBytes1,                         // SCAS/SCASB
    /* AF */ ENTRY_CopyBytes1,                         // SCAS/SCASD
    /* B0 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B1 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B2 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B3 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B4 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B5 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B6 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B7 */ ENTRY_CopyBytes2,                         // MOV B0+rb
    /* B8 */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* B9 */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* BA */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* BB */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* BC */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* BD */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* BE */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* BF */ ENTRY_CopyBytes3Or5Rax,                   // MOV B8+rb
    /* C0 */ ENTRY_CopyBytes2Mod1,                     // RCL/2 ib, etc.
    /* C1 */ ENTRY_CopyBytes2Mod1,                     // RCL/2 ib, etc.
    /* C2 */ ENTRY_CopyBytes3,                         // RET
    /* C3 */ ENTRY_CopyBytes1,                         // RET
    /* C4 */ ENTRY_CopyVex3,                           // LES, VEX 3-byte opcodes.
    /* C5 */ ENTRY_CopyVex2,                           // LDS, VEX 2-byte opcodes.
    /* C6 */ ENTRY_CopyBytes2Mod1,                     // MOV
    /* C7 */ ENTRY_CopyC7,                             // MOV/0 XBEGIN/7
    /* C8 */ ENTRY_CopyBytes4,                         // ENTER
    /* C9 */ ENTRY_CopyBytes1,                         // LEAVE
    /* CA */ ENTRY_CopyBytes3,                         // RET
    /* CB */ ENTRY_CopyBytes1,                         // RET
    /* CC */ ENTRY_CopyBytes1,                         // INT 3
    /* CD */ ENTRY_CopyBytes2,                         // INT ib
#ifdef _M_X64
    /* CE */ ENTRY_Invalid,                            // Invalid
#else
    /* CE */ ENTRY_CopyBytes1,                         // INTO
#endif
    /* CF */ ENTRY_CopyBytes1,                         // IRET
    /* D0 */ ENTRY_CopyBytes2Mod,                      // RCL/2, etc.
    /* D1 */ ENTRY_CopyBytes2Mod,                      // RCL/2, etc.
    /* D2 */ ENTRY_CopyBytes2Mod,                      // RCL/2, etc.
    /* D3 */ ENTRY_CopyBytes2Mod,                      // RCL/2, etc.
#ifdef _M_X64
    /* D4 */ ENTRY_Invalid,                            // Invalid
    /* D5 */ ENTRY_CopyRex2,                           // REX2 (Intel APX)
#else
    /* D4 */ ENTRY_CopyBytes2,                         // AAM
    /* D5 */ ENTRY_CopyBytes2,                         // AAD
#endif
    /* D6 */ ENTRY_Invalid,                            // Invalid
    /* D7 */ ENTRY_CopyBytes1,                         // XLAT/XLATB
    /* D8 */ ENTRY_CopyBytes2Mod,                      // FADD, etc.
    /* D9 */ ENTRY_CopyBytes2Mod,                      // F2XM1, etc.
    /* DA */ ENTRY_CopyBytes2Mod,                      // FLADD, etc.
    /* DB */ ENTRY_CopyBytes2Mod,                      // FCLEX, etc.
    /* DC */ ENTRY_CopyBytes2Mod,                      // FADD/0, etc.
    /* DD */ ENTRY_CopyBytes2Mod,                      // FFREE, etc.
    /* DE */ ENTRY_CopyBytes2Mod,                      // FADDP, etc.
    /* DF */ ENTRY_CopyBytes2Mod,                      // FBLD/4, etc.
    /* E0 */ ENTRY_CopyBytes2CantJump,                 // LOOPNE cb
    /* E1 */ ENTRY_CopyBytes2CantJump,                 // LOOPE cb
    /* E2 */ ENTRY_CopyBytes2CantJump,                 // LOOP cb
    /* E3 */ ENTRY_CopyBytes2CantJump,                 // JCXZ/JECXZ
    /* E4 */ ENTRY_CopyBytes2,                         // IN ib
    /* E5 */ ENTRY_CopyBytes2,                         // IN id
    /* E6 */ ENTRY_CopyBytes2,                         // OUT ib
    /* E7 */ ENTRY_CopyBytes2,                         // OUT ib
    /* E8 */ ENTRY_CopyBytes3Or5Target,                // CALL cd
    /* E9 */ ENTRY_CopyBytes3Or5Target,                // JMP cd
#ifdef _M_X64
    /* EA */ ENTRY_Invalid,                            // Invalid
#else
    /* EA */ ENTRY_CopyBytes5Or7,                      // JMP cp
#endif
    /* EB */ ENTRY_CopyBytes2Jump,                     // JMP cb
    /* EC */ ENTRY_CopyBytes1,                         // IN ib
    /* ED */ ENTRY_CopyBytes1,                         // IN id
    /* EE */ ENTRY_CopyBytes1,                         // OUT
    /* EF */ ENTRY_CopyBytes1,                         // OUT
    /* F0 */ ENTRY_CopyBytesPrefix,                    // LOCK prefix
    /* F1 */ ENTRY_CopyBytes1,                         // INT1 / ICEBP somewhat documented by AMD, not by Intel
    /* F2 */ ENTRY_CopyF2,                             // REPNE prefix
//#ifdef _M_IX86
    /* F3 */ ENTRY_CopyF3,                             // REPE prefix
//#else
// This does presently suffice for AMD64 but it requires tracing
// through a bunch of code to verify and seems not worth maintaining.
//  /* F3 */ ENTRY_CopyBytesPrefix,                    // REPE prefix
//#endif
    /* F4 */ ENTRY_CopyBytes1,                         // HLT
    /* F5 */ ENTRY_CopyBytes1,                         // CMC
    /* F6 */ ENTRY_CopyF6,                             // TEST/0, DIV/6
    /* F7 */ ENTRY_CopyF7,                             // TEST/0, DIV/6
    /* F8 */ ENTRY_CopyBytes1,                         // CLC
    /* F9 */ ENTRY_CopyBytes1,                         // STC
    /* FA */ ENTRY_CopyBytes1,                         // CLI
    /* FB */ ENTRY_CopyBytes1,                         // STI
    /* FC */ ENTRY_CopyBytes1,                         // CLD
    /* FD */ ENTRY_CopyBytes1,                         // STD
    /* FE */ ENTRY_CopyBytes2Mod,                      // DEC/1,INC/0
    /* FF */ ENTRY_CopyFF,                             // CALL/2
};

const CDetourDis::COPYENTRY CDetourDis::s_rceCopyTable0F[] =
{
    /* 00 */ ENTRY_CopyBytes2Mod,                      // sldt/0 str/1 lldt/2 ltr/3 verr/4 verw/5 invalid/6 invalid/7
    /* 01 */ ENTRY_CopyBytes2Mod,                      // INVLPG/7, etc.
    /* 02 */ ENTRY_CopyBytes2Mod,                      // LAR/r
    /* 03 */ ENTRY_CopyBytes2Mod,                      // LSL/r
    /* 04 */ ENTRY_Invalid,                            // _04
    /* 05 */ ENTRY_CopyBytes1,                         // SYSCALL
    /* 06 */ ENTRY_CopyBytes1,                         // CLTS
    /* 07 */ ENTRY_CopyBytes1,                         // SYSRET
    /* 08 */ ENTRY_CopyBytes1,                         // INVD
    /* 09 */ ENTRY_CopyBytes1,                         // WBINVD
    /* 0A */ ENTRY_Invalid,                            // _0A
    /* 0B */ ENTRY_CopyBytes1,                         // UD2
    /* 0C */ ENTRY_Invalid,                            // _0C
    /* 0D */ ENTRY_CopyBytes2Mod,                      // PREFETCH
    /* 0E */ ENTRY_CopyBytes1,                         // FEMMS (3DNow -- not in Intel documentation)
    /* 0F */ ENTRY_CopyBytes2Mod1,                     // 3DNow Opcodes
    /* 10 */ ENTRY_CopyBytes2Mod,                      // MOVSS MOVUPD MOVSD
    /* 11 */ ENTRY_CopyBytes2Mod,                      // MOVSS MOVUPD MOVSD
    /* 12 */ ENTRY_CopyBytes2Mod,                      // MOVLPD
    /* 13 */ ENTRY_CopyBytes2Mod,                      // MOVLPD
    /* 14 */ ENTRY_CopyBytes2Mod,                      // UNPCKLPD
    /* 15 */ ENTRY_CopyBytes2Mod,                      // UNPCKHPD
    /* 16 */ ENTRY_CopyBytes2Mod,                      // MOVHPD
    /* 17 */ ENTRY_CopyBytes2Mod,                      // MOVHPD
    /* 18 */ ENTRY_CopyBytes2Mod,                      // PREFETCHINTA...
    /* 19 */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1A */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1B */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1C */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1D */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1E */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop, not documented by Intel, documented by AMD
    /* 1F */ ENTRY_CopyBytes2Mod,                      // NOP/r multi byte nop
    /* 20 */ ENTRY_CopyBytes2Mod,                      // MOV/r
    /* 21 */ ENTRY_CopyBytes2Mod,                      // MOV/r
    /* 22 */ ENTRY_CopyBytes2Mod,                      // MOV/r
    /* 23 */ ENTRY_CopyBytes2Mod,                      // MOV/r
#ifdef _M_X64
    /* 24 */ ENTRY_Invalid,                            // _24
#else
    /* 24 */ ENTRY_CopyBytes2Mod,                      // MOV/r,TR TR is test register on 80386 and 80486, removed in Pentium
#endif
    /* 25 */ ENTRY_Invalid,                            // _25
#ifdef _M_X64
    /* 26 */ ENTRY_Invalid,                            // _26
#else
    /* 26 */ ENTRY_CopyBytes2Mod,                      // MOV TR/r TR is test register on 80386 and 80486, removed in Pentium
#endif
    /* 27 */ ENTRY_Invalid,                            // _27
    /* 28 */ ENTRY_CopyBytes2Mod,                      // MOVAPS MOVAPD
    /* 29 */ ENTRY_CopyBytes2Mod,                      // MOVAPS MOVAPD
    /* 2A */ ENTRY_CopyBytes2Mod,                      // CVPI2PS &
    /* 2B */ ENTRY_CopyBytes2Mod,                      // MOVNTPS MOVNTPD
    /* 2C */ ENTRY_CopyBytes2Mod,                      // CVTTPS2PI &
    /* 2D */ ENTRY_CopyBytes2Mod,                      // CVTPS2PI &
    /* 2E */ ENTRY_CopyBytes2Mod,                      // UCOMISS UCOMISD
    /* 2F */ ENTRY_CopyBytes2Mod,                      // COMISS COMISD
    /* 30 */ ENTRY_CopyBytes1,                         // WRMSR
    /* 31 */ ENTRY_CopyBytes1,                         // RDTSC
    /* 32 */ ENTRY_CopyBytes1,                         // RDMSR
    /* 33 */ ENTRY_CopyBytes1,                         // RDPMC
    /* 34 */ ENTRY_CopyBytes1,                         // SYSENTER
    /* 35 */ ENTRY_CopyBytes1,                         // SYSEXIT
    /* 36 */ ENTRY_Invalid,                            // _36
    /* 37 */ ENTRY_CopyBytes1,                         // GETSEC
    /* 38 */ ENTRY_CopyBytes3Mod,                      // SSE3 Opcodes
    /* 39 */ ENTRY_Invalid,                            // _39
    /* 3A */ ENTRY_CopyBytes3Mod1,                      // SSE3 Opcodes
    /* 3B */ ENTRY_Invalid,                            // _3B
    /* 3C */ ENTRY_Invalid,                            // _3C
    /* 3D */ ENTRY_Invalid,                            // _3D
    /* 3E */ ENTRY_Invalid,                            // _3E
    /* 3F */ ENTRY_Invalid,                            // _3F
    /* 40 */ ENTRY_CopyBytes2Mod,                      // CMOVO (0F 40)
    /* 41 */ ENTRY_CopyBytes2Mod,                      // CMOVNO (0F 41)
    /* 42 */ ENTRY_CopyBytes2Mod,                      // CMOVB & CMOVNE (0F 42)
    /* 43 */ ENTRY_CopyBytes2Mod,                      // CMOVAE & CMOVNB (0F 43)
    /* 44 */ ENTRY_CopyBytes2Mod,                      // CMOVE & CMOVZ (0F 44)
    /* 45 */ ENTRY_CopyBytes2Mod,                      // CMOVNE & CMOVNZ (0F 45)
    /* 46 */ ENTRY_CopyBytes2Mod,                      // CMOVBE & CMOVNA (0F 46)
    /* 47 */ ENTRY_CopyBytes2Mod,                      // CMOVA & CMOVNBE (0F 47)
    /* 48 */ ENTRY_CopyBytes2Mod,                      // CMOVS (0F 48)
    /* 49 */ ENTRY_CopyBytes2Mod,                      // CMOVNS (0F 49)
    /* 4A */ ENTRY_CopyBytes2Mod,                      // CMOVP & CMOVPE (0F 4A)
    /* 4B */ ENTRY_CopyBytes2Mod,                      // CMOVNP & CMOVPO (0F 4B)
    /* 4C */ ENTRY_CopyBytes2Mod,                      // CMOVL & CMOVNGE (0F 4C)
    /* 4D */ ENTRY_CopyBytes2Mod,                      // CMOVGE & CMOVNL (0F 4D)
    /* 4E */ ENTRY_CopyBytes2Mod,                      // CMOVLE & CMOVNG (0F 4E)
    /* 4F */ ENTRY_CopyBytes2Mod,                      // CMOVG & CMOVNLE (0F 4F)
    /* 50 */ ENTRY_CopyBytes2Mod,                      // MOVMSKPD MOVMSKPD
    /* 51 */ ENTRY_CopyBytes2Mod,                      // SQRTPS &
    /* 52 */ ENTRY_CopyBytes2Mod,                      // RSQRTTS RSQRTPS
    /* 53 */ ENTRY_CopyBytes2Mod,                      // RCPPS RCPSS
    /* 54 */ ENTRY_CopyBytes2Mod,                      // ANDPS ANDPD
    /* 55 */ ENTRY_CopyBytes2Mod,                      // ANDNPS ANDNPD
    /* 56 */ ENTRY_CopyBytes2Mod,                      // ORPS ORPD
    /* 57 */ ENTRY_CopyBytes2Mod,                      // XORPS XORPD
    /* 58 */ ENTRY_CopyBytes2Mod,                      // ADDPS &
    /* 59 */ ENTRY_CopyBytes2Mod,                      // MULPS &
    /* 5A */ ENTRY_CopyBytes2Mod,                      // CVTPS2PD &
    /* 5B */ ENTRY_CopyBytes2Mod,                      // CVTDQ2PS &
    /* 5C */ ENTRY_CopyBytes2Mod,                      // SUBPS &
    /* 5D */ ENTRY_CopyBytes2Mod,                      // MINPS &
    /* 5E */ ENTRY_CopyBytes2Mod,                      // DIVPS &
    /* 5F */ ENTRY_CopyBytes2Mod,                      // MASPS &
    /* 60 */ ENTRY_CopyBytes2Mod,                      // PUNPCKLBW/r
    /* 61 */ ENTRY_CopyBytes2Mod,                      // PUNPCKLWD/r
    /* 62 */ ENTRY_CopyBytes2Mod,                      // PUNPCKLWD/r
    /* 63 */ ENTRY_CopyBytes2Mod,                      // PACKSSWB/r
    /* 64 */ ENTRY_CopyBytes2Mod,                      // PCMPGTB/r
    /* 65 */ ENTRY_CopyBytes2Mod,                      // PCMPGTW/r
    /* 66 */ ENTRY_CopyBytes2Mod,                      // PCMPGTD/r
    /* 67 */ ENTRY_CopyBytes2Mod,                      // PACKUSWB/r
    /* 68 */ ENTRY_CopyBytes2Mod,                      // PUNPCKHBW/r
    /* 69 */ ENTRY_CopyBytes2Mod,                      // PUNPCKHWD/r
    /* 6A */ ENTRY_CopyBytes2Mod,                      // PUNPCKHDQ/r
    /* 6B */ ENTRY_CopyBytes2Mod,                      // PACKSSDW/r
    /* 6C */ ENTRY_CopyBytes2Mod,                      // PUNPCKLQDQ
    /* 6D */ ENTRY_CopyBytes2Mod,                      // PUNPCKHQDQ
    /* 6E */ ENTRY_CopyBytes2Mod,                      // MOVD/r
    /* 6F */ ENTRY_CopyBytes2Mod,                      // MOV/r
    /* 70 */ ENTRY_CopyBytes2Mod1,                     // PSHUFW/r ib
    /* 71 */ ENTRY_CopyBytes2Mod1,                     // PSLLW/6 ib,PSRAW/4 ib,PSRLW/2 ib
    /* 72 */ ENTRY_CopyBytes2Mod1,                     // PSLLD/6 ib,PSRAD/4 ib,PSRLD/2 ib
    /* 73 */ ENTRY_CopyBytes2Mod1,                     // PSLLQ/6 ib,PSRLQ/2 ib
    /* 74 */ ENTRY_CopyBytes2Mod,                      // PCMPEQB/r
    /* 75 */ ENTRY_CopyBytes2Mod,                      // PCMPEQW/r
    /* 76 */ ENTRY_CopyBytes2Mod,                      // PCMPEQD/r
    /* 77 */ ENTRY_CopyBytes1,                         // EMMS
    // extrq/insertq require mode=3 and are followed by two immediate bytes
    /* 78 */ ENTRY_Copy0F78,                           // VMREAD/r, 66/EXTRQ/r/ib/ib, F2/INSERTQ/r/ib/ib
    // extrq/insertq require mod=3, therefore ENTRY_CopyBytes2, but it ends up the same
    /* 79 */ ENTRY_CopyBytes2Mod,                      // VMWRITE/r, 66/EXTRQ/r, F2/INSERTQ/r
    /* 7A */ ENTRY_Invalid,                            // _7A
    /* 7B */ ENTRY_Invalid,                            // _7B
    /* 7C */ ENTRY_CopyBytes2Mod,                      // HADDPS
    /* 7D */ ENTRY_CopyBytes2Mod,                      // HSUBPS
    /* 7E */ ENTRY_CopyBytes2Mod,                      // MOVD/r
    /* 7F */ ENTRY_CopyBytes2Mod,                      // MOV/r
    /* 80 */ ENTRY_CopyBytes3Or5Target,                // JO
    /* 81 */ ENTRY_CopyBytes3Or5Target,                // JNO
    /* 82 */ ENTRY_CopyBytes3Or5Target,                // JB,JC,JNAE
    /* 83 */ ENTRY_CopyBytes3Or5Target,                // JAE,JNB,JNC
    /* 84 */ ENTRY_CopyBytes3Or5Target,                // JE,JZ,JZ
    /* 85 */ ENTRY_CopyBytes3Or5Target,                // JNE,JNZ
    /* 86 */ ENTRY_CopyBytes3Or5Target,                // JBE,JNA
    /* 87 */ ENTRY_CopyBytes3Or5Target,                // JA,JNBE
    /* 88 */ ENTRY_CopyBytes3Or5Target,                // JS
    /* 89 */ ENTRY_CopyBytes3Or5Target,                // JNS
    /* 8A */ ENTRY_CopyBytes3Or5Target,                // JP,JPE
    /* 8B */ ENTRY_CopyBytes3Or5Target,                // JNP,JPO
    /* 8C */ ENTRY_CopyBytes3Or5Target,                // JL,NGE
    /* 8D */ ENTRY_CopyBytes3Or5Target,                // JGE,JNL
    /* 8E */ ENTRY_CopyBytes3Or5Target,                // JLE,JNG
    /* 8F */ ENTRY_CopyBytes3Or5Target,                // JG,JNLE
    /* 90 */ ENTRY_CopyBytes2Mod,                      // CMOVO (0F 40)
    /* 91 */ ENTRY_CopyBytes2Mod,                      // CMOVNO (0F 41)
    /* 92 */ ENTRY_CopyBytes2Mod,                      // CMOVB & CMOVC & CMOVNAE (0F 42)
    /* 93 */ ENTRY_CopyBytes2Mod,                      // CMOVAE & CMOVNB & CMOVNC (0F 43)
    /* 94 */ ENTRY_CopyBytes2Mod,                      // CMOVE & CMOVZ (0F 44)
    /* 95 */ ENTRY_CopyBytes2Mod,                      // CMOVNE & CMOVNZ (0F 45)
    /* 96 */ ENTRY_CopyBytes2Mod,                      // CMOVBE & CMOVNA (0F 46)
    /* 97 */ ENTRY_CopyBytes2Mod,                      // CMOVA & CMOVNBE (0F 47)
    /* 98 */ ENTRY_CopyBytes2Mod,                      // CMOVS (0F 48)
    /* 99 */ ENTRY_CopyBytes2Mod,                      // CMOVNS (0F 49)
    /* 9A */ ENTRY_CopyBytes2Mod,                      // CMOVP & CMOVPE (0F 4A)
    /* 9B */ ENTRY_CopyBytes2Mod,                      // CMOVNP & CMOVPO (0F 4B)
    /* 9C */ ENTRY_CopyBytes2Mod,                      // CMOVL & CMOVNGE (0F 4C)
    /* 9D */ ENTRY_CopyBytes2Mod,                      // CMOVGE & CMOVNL (0F 4D)
    /* 9E */ ENTRY_CopyBytes2Mod,                      // CMOVLE & CMOVNG (0F 4E)
    /* 9F */ ENTRY_CopyBytes2Mod,                      // CMOVG & CMOVNLE (0F 4F)
    /* A0 */ ENTRY_CopyBytes1,                         // PUSH
    /* A1 */ ENTRY_CopyBytes1,                         // POP
    /* A2 */ ENTRY_CopyBytes1,                         // CPUID
    /* A3 */ ENTRY_CopyBytes2Mod,                      // BT  (0F A3)
    /* A4 */ ENTRY_CopyBytes2Mod1,                     // SHLD
    /* A5 */ ENTRY_CopyBytes2Mod,                      // SHLD
    /* A6 */ ENTRY_CopyBytes2Mod,                      // XBTS
    /* A7 */ ENTRY_CopyBytes2Mod,                      // IBTS
    /* A8 */ ENTRY_CopyBytes1,                         // PUSH
    /* A9 */ ENTRY_CopyBytes1,                         // POP
    /* AA */ ENTRY_CopyBytes1,                         // RSM
    /* AB */ ENTRY_CopyBytes2Mod,                      // BTS (0F AB)
    /* AC */ ENTRY_CopyBytes2Mod1,                     // SHRD
    /* AD */ ENTRY_CopyBytes2Mod,                      // SHRD

    // 0F AE mod76=mem mod543=0 fxsave
    // 0F AE mod76=mem mod543=1 fxrstor
    // 0F AE mod76=mem mod543=2 ldmxcsr
    // 0F AE mod76=mem mod543=3 stmxcsr
    // 0F AE mod76=mem mod543=4 xsave
    // 0F AE mod76=mem mod543=5 xrstor
    // 0F AE mod76=mem mod543=6 saveopt
    // 0F AE mod76=mem mod543=7 clflush
    // 0F AE mod76=11b mod543=5 lfence
    // 0F AE mod76=11b mod543=6 mfence
    // 0F AE mod76=11b mod543=7 sfence
    // F3 0F AE mod76=11b mod543=0 rdfsbase
    // F3 0F AE mod76=11b mod543=1 rdgsbase
    // F3 0F AE mod76=11b mod543=2 wrfsbase
    // F3 0F AE mod76=11b mod543=3 wrgsbase
    /* AE */ ENTRY_CopyBytes2Mod,                      // fxsave fxrstor ldmxcsr stmxcsr xsave xrstor saveopt clflush lfence mfence sfence rdfsbase rdgsbase wrfsbase wrgsbase
    /* AF */ ENTRY_CopyBytes2Mod,                      // IMUL (0F AF)
    /* B0 */ ENTRY_CopyBytes2Mod,                      // CMPXCHG (0F B0)
    /* B1 */ ENTRY_CopyBytes2Mod,                      // CMPXCHG (0F B1)
    /* B2 */ ENTRY_CopyBytes2Mod,                      // LSS/r
    /* B3 */ ENTRY_CopyBytes2Mod,                      // BTR (0F B3)
    /* B4 */ ENTRY_CopyBytes2Mod,                      // LFS/r
    /* B5 */ ENTRY_CopyBytes2Mod,                      // LGS/r
    /* B6 */ ENTRY_CopyBytes2Mod,                      // MOVZX/r
    /* B7 */ ENTRY_CopyBytes2Mod,                      // MOVZX/r
    /* B8 */ ENTRY_CopyBytes2Mod,                      // f3/popcnt
    /* B9 */ ENTRY_Invalid,                            // _B9
    /* BA */ ENTRY_CopyBytes2Mod1,                     // BT & BTC & BTR & BTS (0F BA)
    /* BB */ ENTRY_CopyBytes2Mod,                      // BTC (0F BB)
    /* BC */ ENTRY_CopyBytes2Mod,                      // BSF (0F BC)
    /* BD */ ENTRY_CopyBytes2Mod,                      // BSR (0F BD)
    /* BE */ ENTRY_CopyBytes2Mod,                      // MOVSX/r
    /* BF */ ENTRY_CopyBytes2Mod,                      // MOVSX/r
    /* C0 */ ENTRY_CopyBytes2Mod,                      // XADD/r
    /* C1 */ ENTRY_CopyBytes2Mod,                      // XADD/r
    /* C2 */ ENTRY_CopyBytes2Mod1,                     // CMPPS &
    /* C3 */ ENTRY_CopyBytes2Mod,                      // MOVNTI
    /* C4 */ ENTRY_CopyBytes2Mod1,                     // PINSRW /r ib
    /* C5 */ ENTRY_CopyBytes2Mod1,                     // PEXTRW /r ib
    /* C6 */ ENTRY_CopyBytes2Mod1,                     // SHUFPS & SHUFPD
    /* C7 */ ENTRY_CopyBytes2Mod,                      // CMPXCHG8B (0F C7)
    /* C8 */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* C9 */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* CA */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* CB */ ENTRY_CopyBytes1,                         // CVTPD2PI BSWAP 0F C8 + rd
    /* CC */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* CD */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* CE */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* CF */ ENTRY_CopyBytes1,                         // BSWAP 0F C8 + rd
    /* D0 */ ENTRY_CopyBytes2Mod,                      // ADDSUBPS (untestd)
    /* D1 */ ENTRY_CopyBytes2Mod,                      // PSRLW/r
    /* D2 */ ENTRY_CopyBytes2Mod,                      // PSRLD/r
    /* D3 */ ENTRY_CopyBytes2Mod,                      // PSRLQ/r
    /* D4 */ ENTRY_CopyBytes2Mod,                      // PADDQ
    /* D5 */ ENTRY_CopyBytes2Mod,                      // PMULLW/r
    /* D6 */ ENTRY_CopyBytes2Mod,                      // MOVDQ2Q / MOVQ2DQ
    /* D7 */ ENTRY_CopyBytes2Mod,                      // PMOVMSKB/r
    /* D8 */ ENTRY_CopyBytes2Mod,                      // PSUBUSB/r
    /* D9 */ ENTRY_CopyBytes2Mod,                      // PSUBUSW/r
    /* DA */ ENTRY_CopyBytes2Mod,                      // PMINUB/r
    /* DB */ ENTRY_CopyBytes2Mod,                      // PAND/r
    /* DC */ ENTRY_CopyBytes2Mod,                      // PADDUSB/r
    /* DD */ ENTRY_CopyBytes2Mod,                      // PADDUSW/r
    /* DE */ ENTRY_CopyBytes2Mod,                      // PMAXUB/r
    /* DF */ ENTRY_CopyBytes2Mod,                      // PANDN/r
    /* E0 */ ENTRY_CopyBytes2Mod ,                     // PAVGB
    /* E1 */ ENTRY_CopyBytes2Mod,                      // PSRAW/r
    /* E2 */ ENTRY_CopyBytes2Mod,                      // PSRAD/r
    /* E3 */ ENTRY_CopyBytes2Mod,                      // PAVGW
    /* E4 */ ENTRY_CopyBytes2Mod,                      // PMULHUW/r
    /* E5 */ ENTRY_CopyBytes2Mod,                      // PMULHW/r
    /* E6 */ ENTRY_CopyBytes2Mod,                      // CTDQ2PD &
    /* E7 */ ENTRY_CopyBytes2Mod,                      // MOVNTQ
    /* E8 */ ENTRY_CopyBytes2Mod,                      // PSUBB/r
    /* E9 */ ENTRY_CopyBytes2Mod,                      // PSUBW/r
    /* EA */ ENTRY_CopyBytes2Mod,                      // PMINSW/r
    /* EB */ ENTRY_CopyBytes2Mod,                      // POR/r
    /* EC */ ENTRY_CopyBytes2Mod,                      // PADDSB/r
    /* ED */ ENTRY_CopyBytes2Mod,                      // PADDSW/r
    /* EE */ ENTRY_CopyBytes2Mod,                      // PMAXSW /r
    /* EF */ ENTRY_CopyBytes2Mod,                      // PXOR/r
    /* F0 */ ENTRY_CopyBytes2Mod,                      // LDDQU
    /* F1 */ ENTRY_CopyBytes2Mod,                      // PSLLW/r
    /* F2 */ ENTRY_CopyBytes2Mod,                      // PSLLD/r
    /* F3 */ ENTRY_CopyBytes2Mod,                      // PSLLQ/r
    /* F4 */ ENTRY_CopyBytes2Mod,                      // PMULUDQ/r
    /* F5 */ ENTRY_CopyBytes2Mod,                      // PMADDWD/r
    /* F6 */ ENTRY_CopyBytes2Mod,                      // PSADBW/r
    /* F7 */ ENTRY_CopyBytes2Mod,                      // MASKMOVQ
    /* F8 */ ENTRY_CopyBytes2Mod,                      // PSUBB/r
    /* F9 */ ENTRY_CopyBytes2Mod,                      // PSUBW/r
    /* FA */ ENTRY_CopyBytes2Mod,                      // PSUBD/r
    /* FB */ ENTRY_CopyBytes2Mod,                      // FSUBQ/r
    /* FC */ ENTRY_CopyBytes2Mod,                      // PADDB/r
    /* FD */ ENTRY_CopyBytes2Mod,                      // PADDW/r
    /* FE */ ENTRY_CopyBytes2Mod,                      // PADDD/r
    /* FF */ ENTRY_Invalid,                            // _FF
};

#endif // defined(_M_X64) || defined(_M_IX86)

#ifdef _M_ARM64

//
// Problematic instructions:
//
// ADR     0ll10000 hhhhhhhh hhhhhhhh hhhddddd  & 0x9f000000 == 0x10000000  (l = low, h = high, d = Rd)
// ADRP    1ll10000 hhhhhhhh hhhhhhhh hhhddddd  & 0x9f000000 == 0x90000000  (l = low, h = high, d = Rd)
//
// B.cond  01010100 iiiiiiii iiiiiiii iii0cccc  & 0xff000010 == 0x54000000  (i = delta = SignExtend(imm19:00, 64), c = cond)
//
// B       000101ii iiiiiiii iiiiiiii iiiiiiii  & 0xfc000000 == 0x14000000  (i = delta = SignExtend(imm26:00, 64))
// BL      100101ii iiiiiiii iiiiiiii iiiiiiii  & 0xfc000000 == 0x94000000  (i = delta = SignExtend(imm26:00, 64))
//
// CBNZ    z0110101 iiiiiiii iiiiiiii iiittttt  & 0x7f000000 == 0x35000000  (z = size, i = delta = SignExtend(imm19:00, 64), t = Rt)
// CBZ     z0110100 iiiiiiii iiiiiiii iiittttt  & 0x7f000000 == 0x34000000  (z = size, i = delta = SignExtend(imm19:00, 64), t = Rt)
//
// LDR Wt  00011000 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0x18000000  (i = SignExtend(imm19:00, 64), t = Rt)
// LDR Xt  01011000 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0x58000000  (i = SignExtend(imm19:00, 64), t = Rt)
// LDRSW   10011000 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0x98000000  (i = SignExtend(imm19:00, 64), t = Rt)
// PRFM    11011000 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0xd8000000  (i = SignExtend(imm19:00, 64), t = Rt)
// LDR St  00011100 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0x1c000000  (i = SignExtend(imm19:00, 64), t = Rt)
// LDR Dt  01011100 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0x5c000000  (i = SignExtend(imm19:00, 64), t = Rt)
// LDR Qt  10011100 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0x9c000000  (i = SignExtend(imm19:00, 64), t = Rt)
// LDR inv 11011100 iiiiiiii iiiiiiii iiittttt  & 0xff000000 == 0xdc000000  (i = SignExtend(imm19:00, 64), t = Rt)
//
// TBNZ    z0110111 bbbbbiii iiiiiiii iiittttt  & 0x7f000000 == 0x37000000  (z = size, b = bitnum, i = SignExtend(imm14:00, 64), t = Rt)
// TBZ     z0110110 bbbbbiii iiiiiiii iiittttt  & 0x7f000000 == 0x36000000  (z = size, b = bitnum, i = SignExtend(imm14:00, 64), t = Rt)
//

class CDetourDis
{
  public:
    static PBYTE CopyInstruction(PBYTE pDst, PBYTE pSrc, LONG* plExtra);

    union AddImm12
    {
        DWORD Assembled;
        struct
        {
            DWORD Rd : 5;           // Destination register
            DWORD Rn : 5;           // Source register
            DWORD Imm12 : 12;       // 12-bit immediate
            DWORD Shift : 2;        // shift (must be 0 or 1)
            DWORD Opcode1 : 7;      // Must be 0010001 == 0x11
            DWORD Size : 1;         // 0 = 32-bit, 1 = 64-bit
        } s;
        static DWORD Assemble(DWORD size, DWORD rd, DWORD rn, ULONG imm, DWORD shift)
        {
            AddImm12 temp;
            temp.s.Rd = rd;
            temp.s.Rn = rn;
            temp.s.Imm12 = imm & 0xfff;
            temp.s.Shift = shift;
            temp.s.Opcode1 = 0x11;
            temp.s.Size = size;
            return temp.Assembled;
        }
        static DWORD AssembleAdd32(DWORD rd, DWORD rn, ULONG imm, DWORD shift) { return Assemble(0, rd, rn, imm, shift); }
        static DWORD AssembleAdd64(DWORD rd, DWORD rn, ULONG imm, DWORD shift)
        {
            return Assemble(1, rd, rn, imm, shift);
        }
    };

    union Adr19
    {
        DWORD Assembled;
        struct
        {
            DWORD Rd : 5;           // Destination register
            DWORD Imm19 : 19;       // 19-bit upper immediate
            DWORD Opcode1 : 5;      // Must be 10000 == 0x10
            DWORD Imm2 : 2;         // 2-bit lower immediate
            DWORD Type : 1;         // 0 = ADR, 1 = ADRP
        } s;
        inline LONG Imm() const { DWORD Imm = (s.Imm19 << 2) | s.Imm2; return (LONG)(Imm << 11) >> 11; }
        static DWORD Assemble(DWORD type, DWORD rd, LONG delta)
        {
            Adr19 temp;
            temp.s.Rd = rd;
            temp.s.Imm19 = (delta >> 2) & 0x7ffff;
            temp.s.Opcode1 = 0x10;
            temp.s.Imm2 = delta & 3;
            temp.s.Type = type;
            return temp.Assembled;
        }
        static DWORD AssembleAdr(DWORD rd, LONG delta) { return Assemble(0, rd, delta); }
        static DWORD AssembleAdrp(DWORD rd, LONG delta) { return Assemble(1, rd, delta); }
    };

    union Bcc19
    {
        DWORD Assembled;
        struct
        {
            DWORD Condition : 4;    // Condition
            DWORD Opcode1 : 1;      // Must be 0
            DWORD Imm19 : 19;       // 19-bit immediate
            DWORD Opcode2 : 8;      // Must be 01010100 == 0x54
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm19 << 13) >> 11; }
        static DWORD AssembleBcc(DWORD condition, LONG delta)
        {
            Bcc19 temp;
            temp.s.Condition = condition;
            temp.s.Opcode1 = 0;
            temp.s.Imm19 = delta >> 2;
            temp.s.Opcode2 = 0x54;
            return temp.Assembled;
        }
    };

    union Branch26
    {
        DWORD Assembled;
        struct
        {
            DWORD Imm26 : 26;       // 26-bit immediate
            DWORD Opcode1 : 5;      // Must be 00101 == 0x5
            DWORD Link : 1;         // 0 = B, 1 = BL
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm26 << 6) >> 4; }
        static DWORD Assemble(DWORD link, LONG delta)
        {
            Branch26 temp;
            temp.s.Imm26 = delta >> 2;
            temp.s.Opcode1 = 0x5;
            temp.s.Link = link;
            return temp.Assembled;
        }
        static DWORD AssembleB(LONG delta) { return Assemble(0, delta); }
    };

    union Br
    {
        DWORD Assembled;
        struct
        {
            DWORD Opcode1 : 5;      // Must be 00000 == 0
            DWORD Rn : 5;           // Register number
            DWORD Opcode2 : 22;     // Must be 1101011000011111000000 == 0x3587c0 for Br
                                    //                                   0x358fc0 for Brl
        } s;
        static DWORD Assemble(DWORD rn, bool link)
        {
            Br temp;
            temp.s.Opcode1 = 0;
            temp.s.Rn = rn;
            temp.s.Opcode2 = 0x3587c0;
            if (link)
                temp.Assembled |= 0x00200000;
            return temp.Assembled;
        }
        static DWORD AssembleBr(DWORD rn)
        {
            return Assemble(rn, false);
        }
    };

    union Cbz19
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           // Register to test
            DWORD Imm19 : 19;       // 19-bit immediate
            DWORD Nz : 1;           // 0 = CBZ, 1 = CBNZ
            DWORD Opcode1 : 6;      // Must be 011010 == 0x1a
            DWORD Size : 1;         // 0 = 32-bit, 1 = 64-bit
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm19 << 13) >> 11; }
        static DWORD Assemble(DWORD size, DWORD nz, DWORD rt, LONG delta)
        {
            Cbz19 temp;
            temp.s.Rt = rt;
            temp.s.Imm19 = delta >> 2;
            temp.s.Nz = nz;
            temp.s.Opcode1 = 0x1a;
            temp.s.Size = size;
            return temp.Assembled;
        }
    };

    union LdrLit19
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           // Destination register
            DWORD Imm19 : 19;       // 19-bit immediate
            DWORD Opcode1 : 2;      // Must be 0
            DWORD FpNeon : 1;       // 0 = LDR Wt/LDR Xt/LDRSW/PRFM, 1 = LDR St/LDR Dt/LDR Qt
            DWORD Opcode2 : 3;      // Must be 011 = 3
            DWORD Size : 2;         // 00 = LDR Wt/LDR St, 01 = LDR Xt/LDR Dt, 10 = LDRSW/LDR Qt, 11 = PRFM/invalid
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm19 << 13) >> 11; }
        static DWORD Assemble(DWORD size, DWORD fpneon, DWORD rt, LONG delta)
        {
            LdrLit19 temp;
            temp.s.Rt = rt;
            temp.s.Imm19 = delta >> 2;
            temp.s.Opcode1 = 0;
            temp.s.FpNeon = fpneon;
            temp.s.Opcode2 = 3;
            temp.s.Size = size;
            return temp.Assembled;
        }
    };

    union LdrFpNeonImm9
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           // Destination register
            DWORD Rn : 5;           // Base register
            DWORD Imm12 : 12;       // 12-bit immediate
            DWORD Opcode1 : 1;      // Must be 1 == 1
            DWORD Opc : 1;          // Part of size
            DWORD Opcode2 : 6;      // Must be 111101 == 0x3d
            DWORD Size : 2;         // Size (0=8-bit, 1=16-bit, 2=32-bit, 3=64-bit, 4=128-bit)
        } s;
        static DWORD Assemble(DWORD size, DWORD rt, DWORD rn, ULONG imm)
        {
            LdrFpNeonImm9 temp;
            temp.s.Rt = rt;
            temp.s.Rn = rn;
            temp.s.Imm12 = imm;
            temp.s.Opcode1 = 1;
            temp.s.Opc = size >> 2;
            temp.s.Opcode2 = 0x3d;
            temp.s.Size = size & 3;
            return temp.Assembled;
        }
    };

    union Mov16
    {
        DWORD Assembled;
        struct
        {
            DWORD Rd : 5;           // Destination register
            DWORD Imm16 : 16;       // Immediate
            DWORD Shift : 2;        // Shift amount (0=0, 1=16, 2=32, 3=48)
            DWORD Opcode : 6;       // Must be 100101 == 0x25
            DWORD Type : 2;         // 0 = MOVN, 1 = reserved, 2 = MOVZ, 3 = MOVK
            DWORD Size : 1;         // 0 = 32-bit, 1 = 64-bit
        } s;
        static DWORD Assemble(DWORD size, DWORD type, DWORD rd, DWORD imm, DWORD shift)
        {
            Mov16 temp;
            temp.s.Rd = rd;
            temp.s.Imm16 = imm;
            temp.s.Shift = shift;
            temp.s.Opcode = 0x25;
            temp.s.Type = type;
            temp.s.Size = size;
            return temp.Assembled;
        }
        static DWORD AssembleMovn32(DWORD rd, DWORD imm, DWORD shift) { return Assemble(0, 0, rd, imm, shift); }
        static DWORD AssembleMovn64(DWORD rd, DWORD imm, DWORD shift) { return Assemble(1, 0, rd, imm, shift); }
        static DWORD AssembleMovz64(DWORD rd, DWORD imm, DWORD shift) { return Assemble(1, 2, rd, imm, shift); }
        static DWORD AssembleMovk64(DWORD rd, DWORD imm, DWORD shift) { return Assemble(1, 3, rd, imm, shift); }
    };

    union Tbz14
    {
        DWORD Assembled;
        struct
        {
            DWORD Rt : 5;           // Register to test
            DWORD Imm14 : 14;       // 14-bit immediate
            DWORD Bit : 5;          // 5-bit index
            DWORD Nz : 1;           // 0 = TBZ, 1 = TBNZ
            DWORD Opcode1 : 6;      // Must be 011011 == 0x1b
            DWORD Size : 1;         // 0 = 32-bit, 1 = 64-bit
        } s;
        inline LONG Imm() const { return (LONG)(s.Imm14 << 18) >> 16; }
        static DWORD Assemble(DWORD size, DWORD nz, DWORD rt, DWORD bit, LONG delta)
        {
            Tbz14 temp;
            temp.s.Rt = rt;
            temp.s.Imm14 = delta >> 2;
            temp.s.Bit = bit;
            temp.s.Nz = nz;
            temp.s.Opcode1 = 0x1b;
            temp.s.Size = size;
            return temp.Assembled;
        }
    };

protected:
    static BYTE PureCopy32(BYTE* pSource, BYTE* pDest);
    static BYTE EmitMovImmediate(PULONG& pDstInst, BYTE rd, UINT64 immediate);
    static BYTE CopyAdr(BYTE* pSource, BYTE* pDest, ULONG instruction);
    static BYTE CopyBcc(BYTE* pSource, BYTE* pDest, ULONG instruction);
    static BYTE CopyB_or_Bl(BYTE* pSource, BYTE* pDest, ULONG instruction, bool link);
    static BYTE CopyCbz(BYTE* pSource, BYTE* pDest, ULONG instruction);
    static BYTE CopyTbz(BYTE* pSource, BYTE* pDest, ULONG instruction);
    static BYTE CopyLdrLiteral(BYTE* pSource, BYTE* pDest, ULONG instruction);

  protected:
    static ULONG GetInstruction(BYTE* pSource)
    {
        return ((PULONG)pSource)[0];
    }

    static BYTE EmitInstruction(PULONG& pDstInst, ULONG instruction)
    {
        *pDstInst++ = instruction;
        return sizeof(ULONG);
    }
};

BYTE CDetourDis::PureCopy32(BYTE* pSource, BYTE* pDest)
{
    *(ULONG *)pDest = *(ULONG*)pSource;
    return sizeof(DWORD);
}

PBYTE CDetourDis::CopyInstruction(PBYTE pDst,
                                  PBYTE pSrc,
                                  LONG* plExtra)
{
    DWORD Instruction = GetInstruction(pSrc);

    ULONG CopiedSize;
    if ((Instruction & 0x1f000000) == 0x10000000) {
        CopiedSize = CopyAdr(pSrc, pDst, Instruction);
    } else if ((Instruction & 0xff000010) == 0x54000000) {
        CopiedSize = CopyBcc(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7c000000) == 0x14000000) {
        CopiedSize = CopyB_or_Bl(pSrc, pDst, Instruction, (Instruction & 0x80000000) != 0);
    } else if ((Instruction & 0x7e000000) == 0x34000000) {
        CopiedSize = CopyCbz(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7e000000) == 0x36000000) {
        CopiedSize = CopyTbz(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x3b000000) == 0x18000000) {
        CopiedSize = CopyLdrLiteral(pSrc, pDst, Instruction);
    } else {
        CopiedSize = PureCopy32(pSrc, pDst);
    }

    *plExtra = CopiedSize - sizeof(DWORD);

    return pSrc + 4;
}

BYTE CDetourDis::EmitMovImmediate(PULONG& pDstInst, BYTE rd, UINT64 immediate)
{
    DWORD piece[4];
    piece[3] = (DWORD)((immediate >> 48) & 0xffff);
    piece[2] = (DWORD)((immediate >> 32) & 0xffff);
    piece[1] = (DWORD)((immediate >> 16) & 0xffff);
    piece[0] = (DWORD)((immediate >> 0) & 0xffff);
    int count = 0;

    // special case: MOVN with 32-bit dest
    if (piece[3] == 0 && piece[2] == 0 && piece[1] == 0xffff)
    {
        EmitInstruction(pDstInst, Mov16::AssembleMovn32(rd, piece[0] ^ 0xffff, 0));
        count++;
    }

    // MOVN/MOVZ with 64-bit dest
    else
    {
        int zero_pieces = (piece[3] == 0x0000) + (piece[2] == 0x0000) + (piece[1] == 0x0000) + (piece[0] == 0x0000);
        int ffff_pieces = (piece[3] == 0xffff) + (piece[2] == 0xffff) + (piece[1] == 0xffff) + (piece[0] == 0xffff);
        DWORD defaultPiece = (ffff_pieces > zero_pieces) ? 0xffff : 0x0000;
        bool first = true;
        for (int pieceNum = 3; pieceNum >= 0; pieceNum--)
        {
            DWORD curPiece = piece[pieceNum];
            if (curPiece != defaultPiece || (pieceNum == 0 && first))
            {
                count++;
                if (first)
                {
                    if (defaultPiece == 0xffff)
                    {
                        EmitInstruction(pDstInst, Mov16::AssembleMovn64(rd, curPiece ^ 0xffff, pieceNum));
                    }
                    else
                    {
                        EmitInstruction(pDstInst, Mov16::AssembleMovz64(rd, curPiece, pieceNum));
                    }
                    first = false;
                }
                else
                {
                    EmitInstruction(pDstInst, Mov16::AssembleMovk64(rd, curPiece, pieceNum));
                }
            }
        }
    }
    return (BYTE)(count * sizeof(DWORD));
}

BYTE CDetourDis::CopyAdr(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Adr19& decoded = (Adr19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    // ADR case
    if (decoded.s.Type == 0)
    {
        BYTE* pTarget = pSource + decoded.Imm();
        LONG64 delta = pTarget - pDest;
        LONG64 deltaPage = ((ULONG_PTR)pTarget >> 12) - ((ULONG_PTR)pDest >> 12);

        // output as ADR
        if (delta >= -(1 << 20) && delta < (1 << 20))
        {
            EmitInstruction(pDstInst, Adr19::AssembleAdr(decoded.s.Rd, (LONG)delta));
        }

        // output as ADRP; ADD
        else if (deltaPage >= -(1 << 20) && (deltaPage < (1 << 20)))
        {
            EmitInstruction(pDstInst, Adr19::AssembleAdrp(decoded.s.Rd, (LONG)deltaPage));
            EmitInstruction(pDstInst, AddImm12::AssembleAdd64(
                decoded.s.Rd, decoded.s.Rd,
                ((ULONG)(ULONG_PTR)pTarget) & 0xfff, 0));
        }

        // output as immediate move
        else
        {
            EmitMovImmediate(pDstInst, decoded.s.Rd, (ULONG_PTR)pTarget);
        }
    }

    // ADRP case
    else
    {
        BYTE* pTarget = (BYTE*)((((ULONG_PTR)pSource >> 12) + decoded.Imm()) << 12);
        LONG64 deltaPage = ((ULONG_PTR)pTarget >> 12) - ((ULONG_PTR)pDest >> 12);

        // output as ADRP
        if (deltaPage >= -(1 << 20) && (deltaPage < (1 << 20)))
        {
            EmitInstruction(pDstInst, Adr19::AssembleAdrp(decoded.s.Rd, (LONG)deltaPage));
        }

        // output as immediate move
        else
        {
            EmitMovImmediate(pDstInst, decoded.s.Rd, (ULONG_PTR)pTarget);
        }
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyBcc(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Bcc19& decoded = (Bcc19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;
    LONG64 delta4 = pTarget - (pDest + 4);

    // output as BCC
    if (delta >= -(1 << 20) && delta < (1 << 20))
    {
        EmitInstruction(pDstInst, Bcc19::AssembleBcc(decoded.s.Condition, (LONG)delta));
    }

    // output as BCC <skip>; B
    else if (delta4 >= -(1 << 27) && (delta4 < (1 << 27)))
    {
        EmitInstruction(pDstInst, Bcc19::AssembleBcc(decoded.s.Condition ^ 1, 8));
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta4));
    }

    // output as MOV x17, Target; BCC <skip>; BR x17 (BIG assumption that x17 isn't being used for anything!!)
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Bcc19::AssembleBcc(decoded.s.Condition ^ 1, 8));
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyB_or_Bl(BYTE* pSource, BYTE* pDest, ULONG instruction, bool link)
{
    Branch26& decoded = (Branch26&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;

    // output as B or BRL
    if (delta >= -(1 << 27) && (delta < (1 << 27)))
    {
        EmitInstruction(pDstInst, Branch26::Assemble(link, (LONG)delta));
    }

    // output as MOV x17, Target; BR or BRL x17 (BIG assumption that x17 isn't being used for anything!!)
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Br::Assemble(17, link));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyCbz(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Cbz19& decoded = (Cbz19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;
    LONG64 delta4 = pTarget - (pDest + 4);

    // output as CBZ/NZ
    if (delta >= -(1 << 20) && delta < (1 << 20))
    {
        EmitInstruction(pDstInst, Cbz19::Assemble(decoded.s.Size, decoded.s.Nz, decoded.s.Rt, (LONG)delta));
    }

    // output as CBNZ/Z <skip>; B
    else if (delta4 >= -(1 << 27) && (delta4 < (1 << 27)))
    {
        EmitInstruction(pDstInst, Cbz19::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, 8));
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta4));
    }

    // output as MOV x17, Target; CBNZ/Z <skip>; BR x17 (BIG assumption that x17 isn't being used for anything!!)
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Cbz19::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, 8));
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyTbz(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Tbz14& decoded = (Tbz14&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;
    LONG64 delta4 = pTarget - (pDest + 4);

    // output as TBZ/NZ
    if (delta >= -(1 << 13) && delta < (1 << 13))
    {
        EmitInstruction(pDstInst, Tbz14::Assemble(decoded.s.Size, decoded.s.Nz, decoded.s.Rt, decoded.s.Bit, (LONG)delta));
    }

    // output as TBNZ/Z <skip>; B
    else if (delta4 >= -(1 << 27) && (delta4 < (1 << 27)))
    {
        EmitInstruction(pDstInst, Tbz14::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, decoded.s.Bit, 8));
        EmitInstruction(pDstInst, Branch26::AssembleB((LONG)delta4));
    }

    // output as MOV x17, Target; TBNZ/Z <skip>; BR x17 (BIG assumption that x17 isn't being used for anything!!)
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Tbz14::Assemble(decoded.s.Size, decoded.s.Nz ^ 1, decoded.s.Rt, decoded.s.Bit, 8));
        EmitInstruction(pDstInst, Br::AssembleBr(17));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

BYTE CDetourDis::CopyLdrLiteral(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    LdrLit19& decoded = (LdrLit19&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;

    // output as LDR
    if (delta >= -(1 << 20) && delta < (1 << 20))
    {
        EmitInstruction(pDstInst, LdrLit19::Assemble(decoded.s.Size, decoded.s.FpNeon, decoded.s.Rt, (LONG)delta));
    }

    // PRFM is a non-faulting hint, so preserve its visible semantics with a NOP.
    else if (decoded.s.FpNeon == 0 && decoded.s.Size == 3)
    {
        EmitInstruction(pDstInst, 0xd503201f);
    }

    // output as move immediate
    else if (decoded.s.FpNeon == 0)
    {
        UINT64 value = 0;
        switch (decoded.s.Size)
        {
            case 0: value = *(ULONG*)pTarget;       break;
            case 1: value = *(UINT64*)pTarget;   break;
            case 2: value = *(LONG*)pTarget;        break;
        }
        EmitMovImmediate(pDstInst, decoded.s.Rt, value);
    }

    // FP/NEON register: compute address in x17 and load from there (BIG assumption that x17 isn't being used for anything!!)
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, LdrFpNeonImm9::Assemble(2 + decoded.s.Size, decoded.s.Rt, 17, 0));
    }

    return (BYTE)((BYTE*)pDstInst - pDest);
}

static PVOID WINAPI DetourCopyInstruction(PVOID pDst, PVOID pSrc, LONG* plExtra)
{
    return (PVOID)CDetourDis::CopyInstruction((PBYTE)pDst, (PBYTE)pSrc, plExtra);
}

#endif // _M_ARM64

//
///////////////////////////////////////////////////////////////// End of File.

#undef ENTRY_Copy0F
#undef ENTRY_Copy0F78
#undef ENTRY_Copy66
#undef ENTRY_Copy67
#undef ENTRY_CopyBytes1
#undef ENTRY_CopyBytes1Address
#undef ENTRY_CopyBytes2
#undef ENTRY_CopyBytes2CantJump
#undef ENTRY_CopyBytes2Jump
#undef ENTRY_CopyBytes2Mod
#undef ENTRY_CopyBytes2Mod1
#undef ENTRY_CopyBytes2ModOperand
#undef ENTRY_CopyBytes3
#undef ENTRY_CopyBytes3Mod
#undef ENTRY_CopyBytes3Mod1
#undef ENTRY_CopyBytes3Or5
#undef ENTRY_CopyBytes3Or5Rax
#undef ENTRY_CopyBytes3Or5Target
#undef ENTRY_CopyBytes4
#undef ENTRY_CopyBytes5Or7
#undef ENTRY_CopyBytesPrefix
#undef ENTRY_CopyBytesRax
#undef ENTRY_CopyBytesSegment
#undef ENTRY_CopyBytesXop
#undef ENTRY_CopyBytesXop1
#undef ENTRY_CopyBytesXop4
#undef ENTRY_CopyC7
#undef ENTRY_CopyEvex
#undef ENTRY_CopyF2
#undef ENTRY_CopyF3
#undef ENTRY_CopyF6
#undef ENTRY_CopyF7
#undef ENTRY_CopyFF
#undef ENTRY_CopyRex2
#undef ENTRY_CopyVex2
#undef ENTRY_CopyVex3
#undef ENTRY_CopyXop
#undef ENTRY_DataIgnored
#undef ENTRY_Invalid

//////////////////////////////////////////////////////////////////////////////
// Trampolines and transactions

// Region reserved for system DLLs, which cannot be used for trampolines.
//
static PVOID const s_pSystemRegionLowerBound = (PVOID)(ULONG_PTR)0x70000000;
static PVOID const s_pSystemRegionUpperBound = (PVOID)(ULONG_PTR)0x80000000;

//////////////////////////////////////////////////////////////////////////////
//
static bool detour_is_imported(PBYTE pbCode, PBYTE pbAddress)
{
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((PVOID)pbCode, &mbi, sizeof(mbi));
    __try {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)mbi.AllocationBase;
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader +
                                                          pDosHeader->e_lfanew);
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        if (pbAddress >= ((PBYTE)pDosHeader +
                          pNtHeader->OptionalHeader
                          .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) &&
            pbAddress < ((PBYTE)pDosHeader +
                         pNtHeader->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress +
                         pNtHeader->OptionalHeader
                         .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size)) {
            return true;
        }
    }
    __except(GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ?
             EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return false;
    }
    return false;
}

inline ULONG_PTR detour_2gb_below(ULONG_PTR address)
{
    return (address > (ULONG_PTR)0x7ff80000) ? address - 0x7ff80000 : 0x80000;
}

inline ULONG_PTR detour_2gb_above(ULONG_PTR address)
{
#if defined(_WIN64)
    return (address < (ULONG_PTR)0xffffffff80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfffffffffff80000;
#else
    return (address < (ULONG_PTR)0x80000000) ? address + 0x7ff80000 : (ULONG_PTR)0xfff80000;
#endif
}

///////////////////////////////////////////////////////////////////////// X86.
//
#ifdef _M_IX86

struct _DETOUR_TRAMPOLINE
{
    BYTE            rbCode[30];     // target code + jmp to pbRemain
    BYTE            cbCode;         // size of relocated target code.
    BYTE            cbCodeWithJump; // size including the jump to pbRemain.
    BYTE            rbRestore[22];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            alignCount;     // populated instruction alignment entries.
    DETOUR_ALIGN    rAlign[8];      // target/trampoline instruction boundaries.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 80);

enum {
    SIZE_OF_JMP = 5,
    SIZE_OF_TRAMPOLINE_JMP = 5
};

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode)
{
    PBYTE pbCodeOriginal;

    if (pbCode == NULL) {
        return NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
        // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = *(UNALIGNED PBYTE *)&pbCode[2];
        if (detour_is_imported(pbCode, pbTarget)) {
            PBYTE pbNew = *(UNALIGNED PBYTE *)pbTarget;
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb) {   // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR *)&pbCode[1];
        pbCode = pbNew;
        pbCodeOriginal = pbCode;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [imm32]
            // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = *(UNALIGNED PBYTE *)&pbCode[2];
            if (detour_is_imported(pbCode, pbTarget)) {
                pbNew = *(UNALIGNED PBYTE *)pbTarget;
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9) {   // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
            pbCode = pbNew;

            // Patches applied by the OS will jump through an HPAT page to get
            // the target function in the patch image. The jump is always performed
            // to the target function found at the current instruction pointer +
            // PAGE_SIZE - 6 (size of jump).
            // If this is an OS patch, we want to detour at the point of the target function
            // padding in the base image. Ideally, we would detour at the target function, but
            // since it's patched it begins with a short jump (to padding) which isn't long
            // enough to hold the detour code bytes.
            if (pbCode[0] == 0xff &&
                pbCode[1] == 0x25 &&
                *(UNALIGNED INT32 *)&pbCode[2] == (UNALIGNED INT32)(pbCode + 0x1000)) {   // jmp [eip+PAGE_SIZE-6]

                pbCode = pbCodeOriginal;
            }

        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
                                   PDETOUR_TRAMPOLINE *ppLower,
                                   PDETOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);

    // And, within +/- 2GB of relative jmp targets.
    if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
    }

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc) {    // brk
        return TRUE;
    }
    else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3) {  // rep ret
        return TRUE;
    }
    else if (pbCode[0] == 0xff && pbCode[1] == 0x25) {  // jmp [+imm32]
        return TRUE;
    }
    else if ((pbCode[0] == 0x26 ||      // jmp es:
              pbCode[0] == 0x2e ||      // jmp cs:
              pbCode[0] == 0x36 ||      // jmp ss:
              pbCode[0] == 0x3e ||      // jmp ds:
              pbCode[0] == 0x64 ||      // jmp fs:
              pbCode[0] == 0x65) &&     // jmp gs:
             pbCode[1] == 0xff &&       // jmp [+imm32]
             pbCode[2] == 0x25) {
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90) {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90) {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00) {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
        pbCode[3] == 0x00) {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00) {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00) {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00) {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00) {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00) {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
        pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00) {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
        pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00 && pbCode[10] == 0x00) {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xcc) {
        return 1;
    }
    return 0;
}

#endif // _M_IX86

///////////////////////////////////////////////////////////////////////// X64.
//
#ifdef _M_X64

struct _DETOUR_TRAMPOLINE
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    BYTE            rbCode[30];     // target code + jmp to pbRemain.
    BYTE            cbCode;         // size of relocated target code.
    BYTE            cbCodeWithJump; // size including the jump to pbRemain.
    BYTE            rbRestore[30];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            alignCount;     // populated instruction alignment entries.
    DETOUR_ALIGN    rAlign[8];      // target/trampoline instruction boundaries.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
    BYTE            rbCodeIn[8];    // jmp [pbDetour]
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 104);

enum {
    SIZE_OF_JMP = 5,
    SIZE_OF_TRAMPOLINE_JMP = 6
};

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_jmp_indirect(PBYTE pbCode, PBYTE *ppbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 6;
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode)
{
    PBYTE pbCodeOriginal;

    if (pbCode == NULL) {
        return NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
        // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
        if (detour_is_imported(pbCode, pbTarget)) {
            PBYTE pbNew = *(UNALIGNED PBYTE *)pbTarget;
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb) {   // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR *)&pbCode[1];
        pbCode = pbNew;
        pbCodeOriginal = pbCode;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
            // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
            if (detour_is_imported(pbCode, pbTarget)) {
                pbNew = *(UNALIGNED PBYTE *)pbTarget;
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9) {   // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
            pbCode = pbNew;

            // Patches applied by the OS will jump through an HPAT page to get
            // the target function in the patch image. The jump is always performed
            // to the target function found at the current instruction pointer +
            // PAGE_SIZE - 6 (size of jump).
            // If this is an OS patch, we want to detour at the point of the target function
            // in the base image. Since we need 5 bytes to perform the jump, detour at the
            // point of the long jump instead of the short jump at the start of the target.
            if (pbCode[0] == 0xff &&
                pbCode[1] == 0x25 &&
                *(UNALIGNED INT32 *)&pbCode[2] == 0xFFA) {   // jmp [rip+PAGE_SIZE-6]

                pbCode = pbCodeOriginal;
            }
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
                                   PDETOUR_TRAMPOLINE *ppLower,
                                   PDETOUR_TRAMPOLINE *ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);

    // And, within +/- 2GB of relative jmp vectors.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
        PBYTE pbNew = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
    }
    // And, within +/- 2GB of relative jmp targets.
    else if (pbCode[0] == 0xe9) {   // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];

        if (pbNew < pbCode) {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        }
        else {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
    }

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc) {    // brk
        return TRUE;
    }
    else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3) {  // rep ret
        return TRUE;
    }
    else if (pbCode[0] == 0xff && pbCode[1] == 0x25) {  // jmp [+imm32]
        return TRUE;
    }
    else if ((pbCode[0] == 0x26 ||      // jmp es:
              pbCode[0] == 0x2e ||      // jmp cs:
              pbCode[0] == 0x36 ||      // jmp ss:
              pbCode[0] == 0x3e ||      // jmp ds:
              pbCode[0] == 0x64 ||      // jmp fs:
              pbCode[0] == 0x65) &&     // jmp gs:
             pbCode[1] == 0xff &&       // jmp [+imm32]
             pbCode[2] == 0x25) {
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90) {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90) {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00) {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 &&
        pbCode[3] == 0x00) {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00) {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x44 && pbCode[4] == 0x00 && pbCode[5] == 0x00) {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00) {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 &&
        pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00) {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F &&
        pbCode[3] == 0x84 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00) {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F &&
        pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00) {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 &&
        pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
        pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
        pbCode[9] == 0x00 && pbCode[10] == 0x00) {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xcc) {
        return 1;
    }
    return 0;
}

#endif // _M_X64

/////////////////////////////////////////////////////////////////////// ARM64.
//
#ifdef _M_ARM64

struct _DETOUR_TRAMPOLINE
{
    // An ARM64 instruction is 4 bytes long.
    //
    // The overwrite is always composed of 3 instructions (12 bytes) which perform an indirect jump
    // using _DETOUR_TRAMPOLINE::pbDetour as the address holding the target location.
    //
    // Copied instructions can expand.
    //
    // The scheme using MovImmediate can cause an instruction
    // to grow as much as 6 times.
    // That would be Bcc or Tbz with a large address space:
    //   4 instructions to form immediate
    //   inverted tbz/bcc
    //   br
    //
    // An expansion of 4 is not uncommon -- bl/blr and small address space:
    //   3 instructions to form immediate
    //   br or brl
    //
    // A theoretical maximum for rbCode is thefore 4*4*6 + 16 = 112 (another 16 for jmp to pbRemain).
    //
    // With literals, the maximum expansion is 5, including the literals: 4*4*5 + 16 = 96.
    //
    // The number is rounded up to 128. m_rbScratchDst should match this.
    //
    BYTE            rbCode[128];    // target code + jmp to pbRemain
    BYTE            cbCode;         // size of relocated target code.
    BYTE            cbCodeWithJump; // size including the jump to pbRemain.
    BYTE            rbRestore[24];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            alignCount;     // populated instruction alignment entries.
    DETOUR_ALIGN    rAlign[8];      // target/trampoline instruction boundaries.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 192);

enum {
    SIZE_OF_JMP = 12,
    SIZE_OF_TRAMPOLINE_JMP = 16
};

inline ULONG fetch_opcode(PBYTE pbCode)
{
    return *(ULONG *)pbCode;
}

inline void write_opcode(PBYTE &pbCode, ULONG Opcode)
{
    *(ULONG *)pbCode = Opcode;
    pbCode += 4;
}

struct ARM64_INDIRECT_JMP {
    struct {
        ULONG Rd : 5;
        ULONG immhi : 19;
        ULONG iop : 5;
        ULONG immlo : 2;
        ULONG op : 1;
    } ardp;

    struct {
        ULONG Rt : 5;
        ULONG Rn : 5;
        ULONG imm : 12;
        ULONG opc : 2;
        ULONG iop1 : 2;
        ULONG V : 1;
        ULONG iop2 : 3;
        ULONG size : 2;
    } ldr;

    ULONG br;
};

#pragma warning(push)
#pragma warning(disable:4201)

union ARM64_INDIRECT_IMM {
    struct {
        ULONG64 pad : 12;
        ULONG64 adrp_immlo : 2;
        ULONG64 adrp_immhi : 19;
    };

    LONG64 value;
};

#pragma warning(pop)

PBYTE detour_gen_jmp_indirect(BYTE *pbCode, ULONG64 *pbJmpVal)
{
    // adrp x17, [jmpval]
    // ldr x17, [x17, jmpval]
    // br x17

    struct ARM64_INDIRECT_JMP *pIndJmp;
    union ARM64_INDIRECT_IMM jmpIndAddr;

    jmpIndAddr.value = (((LONG64)pbJmpVal) & 0xFFFFFFFFFFFFF000) - 
                       (((LONG64)pbCode) & 0xFFFFFFFFFFFFF000);

    pIndJmp = (struct ARM64_INDIRECT_JMP *)pbCode;
    pbCode = (BYTE *)(pIndJmp + 1);

    pIndJmp->ardp.Rd = 17;
    pIndJmp->ardp.immhi = jmpIndAddr.adrp_immhi;
    pIndJmp->ardp.iop = 0x10;
    pIndJmp->ardp.immlo = jmpIndAddr.adrp_immlo;
    pIndJmp->ardp.op = 1;

    pIndJmp->ldr.Rt = 17;
    pIndJmp->ldr.Rn = 17;
    pIndJmp->ldr.imm = (((ULONG64)pbJmpVal) & 0xFFF) / 8;
    pIndJmp->ldr.opc = 1;
    pIndJmp->ldr.iop1 = 1;
    pIndJmp->ldr.V = 0;
    pIndJmp->ldr.iop2 = 7;
    pIndJmp->ldr.size = 3;

    pIndJmp->br = 0xD61F0220;

    return pbCode;
}

PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE *ppPool, PBYTE pbJmpVal)
{
    *ppPool -= 8;
    PBYTE pbLiteral = *ppPool;

    *((PBYTE*&)pbLiteral) = pbJmpVal;
    LONG delta = (LONG)(pbLiteral - pbCode);

    write_opcode(pbCode, 0x58000011 | ((delta / 4) << 5));  // LDR X17,[PC+n]
    write_opcode(pbCode, 0xd61f0000 | (17 << 5));           // BR X17
    return pbCode;
}

constexpr INT64 detour_sign_extend(UINT64 value, UINT bits)
{
    const UINT64 sign = UINT64{ 1 } << (bits - 1);
    return static_cast<INT64>((value ^ sign) - sign);
}
static_assert(detour_sign_extend(0x100000, 21) == -0x100000);

inline PBYTE detour_skip_jmp(PBYTE pbCode)
{
    if (pbCode == NULL) {
        return NULL;
    }

    // Skip over the import jump if there is one.
    ULONG Opcode = fetch_opcode(pbCode);

    if ((Opcode & 0x9f00001f) == 0x90000010) {           // adrp  x16, IAT
        ULONG Opcode2 = fetch_opcode(pbCode + 4);

        if ((Opcode2 & 0xffe003ff) == 0xf9400210) {      // ldr   x16, [x16, IAT]
            ULONG Opcode3 = fetch_opcode(pbCode + 8);

            if (Opcode3 == 0xd61f0200) {                 // br    x16

/* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf
    The ADRP instruction shifts a signed, 21-bit immediate left by 12 bits, adds it to the value of the program counter with
    the bottom 12 bits cleared to zero, and then writes the result to a general-purpose register. This permits the
    calculation of the address at a 4KB aligned memory region. In conjunction with an ADD (immediate) instruction, or
    a Load/Store instruction with a 12-bit immediate offset, this allows for the calculation of, or access to, any address
    within +/- 4GB of the current PC.

PC-rel. addressing
    This section describes the encoding of the PC-rel. addressing instruction class. The encodings in this section are
    decoded from Data Processing -- Immediate on page C4-226.
    Add/subtract (immediate)
    This section describes the encoding of the Add/subtract (immediate) instruction class. The encodings in this section
    are decoded from Data Processing -- Immediate on page C4-226.
    Decode fields
    Instruction page
    op
    0 ADR
    1 ADRP

C6.2.10 ADRP
    Form PC-relative address to 4KB page adds an immediate value that is shifted left by 12 bits, to the PC value to
    form a PC-relative address, with the bottom 12 bits masked out, and writes the result to the destination register.
    ADRP <Xd>, <label>
    imm = SignExtend(immhi:immlo:Zeros(12), 64);

    31  30 29 28 27 26 25 24 23 5    4 0
    1   immlo  1  0  0  0  0  immhi  Rd
         9             0

Rd is hardcoded as 0x10 above.
Immediate is 21 signed bits split into 2 bits and 19 bits, and is scaled by 4K.
*/
                UINT64 const pageLow2 = (Opcode >> 29) & 3;
                UINT64 const pageHigh19 = (Opcode >> 5) & ~(~0ui64 << 19);
                INT64 const page = detour_sign_extend((pageHigh19 << 2) | pageLow2, 21) * (INT64{ 1 } << 12);

/* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf

    C6.2.101 LDR (immediate)
    Load Register (immediate) loads a word or doubleword from memory and writes it to a register. The address that is
    used for the load is calculated from a base register and an immediate offset.
    The Unsigned offset variant scales the immediate offset value by the size of the value accessed before adding it
    to the base register value.

Unsigned offset
64-bit variant Applies when size == 11.
    31 30 29 28  27 26 25 24  23 22  21   10   9 5   4 0
     1  x  1  1   1  0  0  1   0  1  imm12      Rn    Rt
         F             9        4              200    10

That is, two low 5 bit fields are registers, hardcoded as 0x10 and 0x10 << 5 above,
then unsigned size-unscaled (8) 12-bit offset, then opcode bits 0xF94.
*/
                UINT64 const offset = ((Opcode2 >> 10) & ~(~0ui64 << 12)) << 3;

                PBYTE const pbTarget = (PBYTE)((ULONG64)pbCode & 0xfffffffffffff000ULL) + page + offset;

                if (detour_is_imported(pbCode, pbTarget)) {
                    PBYTE pbNew = *(PBYTE *)pbTarget;
                    return pbNew;
                }
            }
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode,
                                   PDETOUR_TRAMPOLINE *ppLower,
                                   PDETOUR_TRAMPOLINE *ppUpper)
{
    // The encoding used by detour_gen_jmp_indirect actually enables a
    // displacement of +/- 4GiB. In the future, this could be changed to
    // reflect that. For now, just reuse the x86 logic which is plenty.

    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_is_code_os_patched(PBYTE pbCode)
{
    // Identify whether the provided code pointer is a OS patch jump.
    // We can do this by checking if a branch (b <imm26>) is present, and if so,
    // it must be jumping to an HPAT page containing ldr <reg> [PC+PAGE_SIZE-4], br <reg>.
    ULONG Opcode = fetch_opcode(pbCode);

    if ((Opcode & 0xfc000000) != 0x14000000) {
        return FALSE;
    }
    // The branch must be jumping forward if it's going into the HPAT.
    // Check that the sign bit is cleared.
    if ((Opcode & 0x2000000) != 0) {
        return FALSE;
    }
    ULONG Delta = (ULONG)((Opcode & 0x1FFFFFF) * 4);
    PBYTE BranchTarget = pbCode + Delta;

    // Now inspect the opcodes of the code we jumped to in order to determine if it's HPAT.
    ULONG HpatOpcode1 = fetch_opcode(BranchTarget);
    ULONG HpatOpcode2 = fetch_opcode(BranchTarget + 4);

    if (HpatOpcode1 != 0x58008010) {    // ldr <reg> [PC+PAGE_SIZE]
        return FALSE;
    }
    if (HpatOpcode2 != 0xd61f0200) {    // br <reg>
        return FALSE;
    }
    return TRUE;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    ULONG Opcode = fetch_opcode(pbCode);
    // When the OS has patched a function entry point, it will incorrectly
    // appear as though the function is just a single branch instruction.
    if (detour_is_code_os_patched(pbCode)) {
        return FALSE;
    }
    if ((Opcode & 0xffbffc1f) == 0xd61f0000 ||      // ret/br <reg>
        (Opcode & 0xfc000000) == 0x14000000) {      // b <imm26>
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    if (*(ULONG *)pbCode == 0xd503201f) {   // nop.
        return 4;
    }
    if (*(ULONG *)pbCode == 0x00000000) {   // zero-filled padding.
        return 4;
    }
    return 0;
}

#endif // _M_ARM64

//////////////////////////////////////////////// Trampoline Memory Management.
//
struct DETOUR_REGION
{
    ULONG               dwSignature;
    DETOUR_REGION *     pNext;  // Next region in list of regions.
    DETOUR_TRAMPOLINE * pFree;  // List of free trampolines in this region.
};
typedef DETOUR_REGION * PDETOUR_REGION;

const ULONG DETOUR_REGION_SIGNATURE = 'Rrtd';
const ULONG DETOUR_REGION_SIZE = 0x10000;
const ULONG DETOUR_TRAMPOLINES_PER_REGION = (DETOUR_REGION_SIZE
                                             / sizeof(DETOUR_TRAMPOLINE)) - 1;
static PDETOUR_REGION s_pRegions = NULL;            // List of all regions.
static PDETOUR_REGION s_pRegion = NULL;             // Default region.

static DWORD detour_writable_trampoline_regions()
{
    // Mark all of the regions as writable.
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        DWORD dwOld;
        if (!VirtualProtect(pRegion, DETOUR_REGION_SIZE, PAGE_EXECUTE_READWRITE, &dwOld)) {
            return GetLastError();
        }
    }
    return NO_ERROR;
}

static void detour_runnable_trampoline_regions()
{
    HANDLE hProcess = GetCurrentProcess();

    // Mark all of the regions as executable.
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext) {
        DWORD dwOld;
        VirtualProtect(pRegion, DETOUR_REGION_SIZE, PAGE_EXECUTE_READ, &dwOld);
        FlushInstructionCache(hProcess, pRegion, DETOUR_REGION_SIZE);
    }
}

static PBYTE detour_alloc_round_down_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0) {
        pbTry -= extra;
    }
    return pbTry;
}

static PBYTE detour_alloc_round_up_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0) {
        ULONG_PTR adjust = DETOUR_REGION_SIZE - extra;
        pbTry += adjust;
    }
    return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

static PVOID detour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi)
{
    PBYTE pbTry = detour_alloc_round_up_to_region(pbLo);


    for (; pbTry < pbHi;) {
        MEMORY_BASIC_INFORMATION mbi;

        if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry += 0x08000000;
            continue;
        }

        ZeroMemory(&mbi, sizeof(mbi));
        if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
            break;
        }


        if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

            PVOID pv = VirtualAlloc(pbTry,
                                    DETOUR_REGION_SIZE,
                                    MEM_COMMIT|MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
            if (pv != NULL) {
                return pv;
            }
            else if (GetLastError() == ERROR_DYNAMIC_CODE_BLOCKED) {
                return NULL;
            }
            pbTry += DETOUR_REGION_SIZE;
        }
        else {
            pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

static PVOID detour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi)
{
    PBYTE pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);


    for (; pbTry > pbLo;) {
        MEMORY_BASIC_INFORMATION mbi;

        if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound) {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry -= 0x08000000;
            continue;
        }

        ZeroMemory(&mbi, sizeof(mbi));
        if (!VirtualQuery(pbTry, &mbi, sizeof(mbi))) {
            break;
        }


        if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE) {

            PVOID pv = VirtualAlloc(pbTry,
                                    DETOUR_REGION_SIZE,
                                    MEM_COMMIT|MEM_RESERVE,
                                    PAGE_EXECUTE_READWRITE);
            if (pv != NULL) {
                return pv;
            }
            else if (GetLastError() == ERROR_DYNAMIC_CODE_BLOCKED) {
                return NULL;
            }
            pbTry -= DETOUR_REGION_SIZE;
        }
        else {
            pbTry = detour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase
                                                      - DETOUR_REGION_SIZE);
        }
    }
    return NULL;
}

static PVOID detour_alloc_trampoline_allocate_new(PBYTE pbTarget,
                                                  PDETOUR_TRAMPOLINE pLo,
                                                  PDETOUR_TRAMPOLINE pHi)
{
    PVOID pbTry = NULL;

    // NB: We must always also start the search at an offset from pbTarget
    //     in order to maintain ASLR entropy.

#if defined(_WIN64)
    // Try looking 1GB below or lower.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000) {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget - 0x40000000);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, (PBYTE)pHi);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000) {
        pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
    }
#endif

    // Try anything below.
    if (pbTry == NULL) {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget);
    }
    // try anything above.
    if (pbTry == NULL) {
        pbTry = detour_alloc_region_from_lo(pbTarget, (PBYTE)pHi);
    }

    return pbTry;
}

static PDETOUR_TRAMPOLINE detour_alloc_trampoline(PBYTE pbTarget)
{
    // We have to place trampolines within +/- 2GB of target.

    PDETOUR_TRAMPOLINE pLo;
    PDETOUR_TRAMPOLINE pHi;

    detour_find_jmp_bounds(pbTarget, &pLo, &pHi);

    PDETOUR_TRAMPOLINE pTrampoline = NULL;

    // Insure that there is a default region.
    if (s_pRegion == NULL && s_pRegions != NULL) {
        s_pRegion = s_pRegions;
    }

    // First check the default region for an valid free block.
    if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
        s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi) {

      found_region:
        pTrampoline = s_pRegion->pFree;
        // do a last sanity check on region.
        if (pTrampoline < pLo || pTrampoline > pHi) {
            return NULL;
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pTrampoline->pbRemain;
        return pTrampoline;
    }

    // Then check the existing regions for a valid free block.
    for (s_pRegion = s_pRegions; s_pRegion != NULL; s_pRegion = s_pRegion->pNext) {
        if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
            s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi) {
            goto found_region;
        }
    }

    // We need to allocate a new region.

    // Round pbTarget down to 64KB block.
    // /RTCc RuntimeChecks breaks PtrToUlong.
    pbTarget = pbTarget - (ULONG)((ULONG_PTR)pbTarget & 0xffff);

    PVOID pbNewlyAllocated =
        detour_alloc_trampoline_allocate_new(pbTarget, pLo, pHi);
    if (pbNewlyAllocated != NULL) {
        s_pRegion = (DETOUR_REGION*)pbNewlyAllocated;
        s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
        s_pRegion->pFree = NULL;
        s_pRegion->pNext = s_pRegions;
        s_pRegions = s_pRegion;

        // Put everything but the first trampoline on the free list.
        PBYTE pFree = NULL;
        pTrampoline = ((PDETOUR_TRAMPOLINE)s_pRegion) + 1;
        for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--) {
            pTrampoline[i].pbRemain = pFree;
            pFree = (PBYTE)&pTrampoline[i];
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pFree;
        goto found_region;
    }

    return NULL;
}

static void detour_free_trampoline(PDETOUR_TRAMPOLINE pTrampoline)
{
    PDETOUR_REGION pRegion = (PDETOUR_REGION)
        ((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);

    pTrampoline->pbRemain = (PBYTE)pRegion->pFree;
    pRegion->pFree = pTrampoline;
}

///////////////////////////////////////////////////////// Transaction Structs.
//

struct DetourOperation
{
    PBYTE *             ppbPointer;
    PBYTE               pbTarget;
    PDETOUR_TRAMPOLINE  pTrampoline;
    ULONG               dwPerm;
    bool                fIsRemove;
};

static constexpr ULONG DETOUR_PENDING_OPERATION_CAPACITY = 64;
static LONG s_nPendingThreadId = 0;
static LONG s_nPendingError = NO_ERROR;
static ULONG s_nPendingOperationCount = 0;
static DetourOperation s_rPendingOperations[DETOUR_PENDING_OPERATION_CAPACITY];

//////////////////////////////////////////////////////////////////////////////
//
static PBYTE detour_code_from_pointer(PVOID pPointer)
{
    return detour_skip_jmp((PBYTE)pPointer);
}

#pragma warning(push)
#pragma warning(disable:4324)
struct DetourSuspendedThread
{
    DWORD threadId;
    HANDLE handle;
    CONTEXT originalContext;
    CONTEXT relocatedContext;
    bool suspended;
    bool contextChanged;
};
#pragma warning(pop)

template<typename T>
struct DetourVirtualAllocator
{
    using value_type = T;

    DetourVirtualAllocator() noexcept = default;

    template<typename U>
    DetourVirtualAllocator(const DetourVirtualAllocator<U>&) noexcept
    {
    }

    T* allocate(size_t count)
    {
        if (count > SIZE_MAX / sizeof(T)) {
            throw std::bad_alloc();
        }
        auto allocation = VirtualAlloc(
            NULL, count * sizeof(T), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocation == NULL) {
            throw std::bad_alloc();
        }
        return static_cast<T*>(allocation);
    }

    void deallocate(T* allocation, size_t) noexcept
    {
        if (allocation != NULL) {
            VirtualFree(allocation, 0, MEM_RELEASE);
        }
    }
};

template<typename T, typename U>
bool operator==(const DetourVirtualAllocator<T>&,
                const DetourVirtualAllocator<U>&) noexcept
{
    return true;
}

template<typename T, typename U>
bool operator!=(const DetourVirtualAllocator<T>&,
                const DetourVirtualAllocator<U>&) noexcept
{
    return false;
}

using DetourSuspendedThreads = std::vector<
    DetourSuspendedThread, DetourVirtualAllocator<DetourSuspendedThread>>;

static void detour_resume_and_close_threads(
    DetourSuspendedThreads& threads)
{
    for (auto& thread : threads) {
        if (thread.handle != NULL && thread.suspended) {
            ResumeThread(thread.handle);
            thread.suspended = false;
        }
    }

    for (auto& thread : threads) {
        if (thread.handle != NULL) {
            CloseHandle(thread.handle);
            thread.handle = NULL;
        }
    }
    threads.clear();
}

static LONG detour_suspend_other_threads(
    DetourSuspendedThreads& threads)
{
    const DWORD processId = GetCurrentProcessId();
    const DWORD currentThreadId = GetCurrentThreadId();
    DWORD transientRetries = 0;

    // Suspend newly discovered threads immediately, then enumerate again. Once
    // an enumeration finds no new thread, every peer that could create another
    // peer is suspended. The VirtualAlloc-backed vector avoids taking the
    // process heap lock after a thread that owns that lock has been suspended.
    for (;;) {
        bool discoveredThread = false;
        bool retryEnumeration = false;
        LONG retryError = ERROR_RETRY;
        const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            const LONG error = GetLastError();
            detour_resume_and_close_threads(threads);
            return error;
        }

        THREADENTRY32 entry{ .dwSize = sizeof(entry) };
        BOOL more = Thread32First(snapshot, &entry);
        while (more) {
            if (entry.th32OwnerProcessID == processId &&
                entry.th32ThreadID != currentThreadId) {

                bool alreadyOpened = false;
                for (const auto& opened : threads) {
                    if (opened.threadId == entry.th32ThreadID) {
                        alreadyOpened = true;
                        break;
                    }
                }

                if (!alreadyOpened) {
                    try { threads.reserve(threads.size() + 1); }
                    catch (...) {
                        CloseHandle(snapshot); detour_resume_and_close_threads(threads);
                        return ERROR_NOT_ENOUGH_MEMORY; }
                    constexpr DWORD access = SYNCHRONIZE |
                        THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME |
                        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
                    HANDLE thread = OpenThread(access, FALSE, entry.th32ThreadID);
                    if (thread != NULL) {
                        // A thread ID from the snapshot can be reused before
                        // OpenThread runs. Never suspend a recycled foreign ID.
                        const DWORD openedProcessId = GetProcessIdOfThread(thread);
                        if (openedProcessId == 0) {
                            const LONG error = GetLastError();
                            const DWORD wait = WaitForSingleObject(thread, 0);
                            if (wait == WAIT_OBJECT_0 ||
                                error == ERROR_INVALID_PARAMETER) {
                                CloseHandle(thread);
                                retryEnumeration = true;
                                retryError = error;
                            }
                            else {
                                CloseHandle(thread);
                                CloseHandle(snapshot);
                                detour_resume_and_close_threads(threads);
                                return error;
                            }
                        }
                        else if (openedProcessId != processId) {
                            CloseHandle(thread);
                            retryEnumeration = true;
                        }
                        else if (SuspendThread(thread) == MAXDWORD) {
                            const LONG error = GetLastError();
                            const DWORD wait = WaitForSingleObject(thread, 0);
                            if (wait == WAIT_OBJECT_0 ||
                                error == ERROR_INVALID_PARAMETER) {
                                CloseHandle(thread);
                                retryEnumeration = true;
                                retryError = error;
                            }
                            else {
                                CloseHandle(thread);
                                CloseHandle(snapshot);
                                detour_resume_and_close_threads(threads);
                                return error;
                            }
                        }
                        else {
                            DetourSuspendedThread candidate{
                                .threadId = entry.th32ThreadID,
                                .handle = thread,
                                .originalContext = {},
                                .relocatedContext = {},
                                .suspended = true,
                                .contextChanged = false,
                            };
#if defined(_M_IX86)
                            candidate.originalContext.ContextFlags = CONTEXT_CONTROL;
#elif defined(_M_X64) || defined(_M_ARM64)
                            candidate.originalContext.ContextFlags =
                                CONTEXT_CONTROL | CONTEXT_INTEGER;
#endif
                            if (GetThreadContext(
                                    thread, &candidate.originalContext)) {
                                candidate.relocatedContext =
                                    candidate.originalContext;
                                threads.push_back(candidate);
                                discoveredThread = true;
                            }
                            else {
                                const LONG error = GetLastError();
                                const DWORD wait = WaitForSingleObject(thread, 0);
                                if (wait != WAIT_OBJECT_0) {
                                    ResumeThread(thread);
                                }
                                CloseHandle(thread);
                                if (wait == WAIT_OBJECT_0 ||
                                    error == ERROR_INVALID_PARAMETER) {
                                    retryEnumeration = true;
                                    retryError = error;
                                }
                                else {
                                    CloseHandle(snapshot);
                                    detour_resume_and_close_threads(threads);
                                    return error;
                                }
                            }
                        }
                    }
                    else {
                        const LONG error = GetLastError();
                        if (error == ERROR_INVALID_PARAMETER) {
                            retryEnumeration = true;
                            retryError = error;
                        }
                        else {
                            CloseHandle(snapshot);
                            detour_resume_and_close_threads(threads);
                            return error;
                        }
                    }
                }
            }

            entry.dwSize = sizeof(entry);
            more = Thread32Next(snapshot, &entry);
        }

        const DWORD enumerationError = GetLastError();
        CloseHandle(snapshot);
        if (enumerationError != ERROR_NO_MORE_FILES) {
            detour_resume_and_close_threads(threads);
            return enumerationError;
        }
        if (retryEnumeration) {
            if (++transientRetries > DETOUR_THREAD_ENUMERATION_RETRY_LIMIT) {
                detour_resume_and_close_threads(threads);
                return retryError;
            }
            continue;
        }
        transientRetries = 0;
        if (!discoveredThread) {
            break;
        }
    }

    return NO_ERROR;
}

static ULONG_PTR detour_context_instruction_pointer(const CONTEXT& context)
{
#if defined(_M_IX86)
    return context.Eip;
#elif defined(_M_X64)
    return context.Rip;
#elif defined(_M_ARM64)
    return context.Pc;
#endif
}

static void detour_set_context_instruction_pointer(
    CONTEXT& context, ULONG_PTR instructionPointer)
{
#if defined(_M_IX86)
    context.Eip = static_cast<DWORD>(instructionPointer);
#elif defined(_M_X64)
    context.Rip = instructionPointer;
#elif defined(_M_ARM64)
    context.Pc = instructionPointer;
#endif
}

static PBYTE detour_align_target_to_trampoline(
    PDETOUR_TRAMPOLINE trampoline, BYTE targetOffset)
{
    BYTE targetStart = 0;
    BYTE trampolineStart = 0;
    for (BYTE i = 0; i < trampoline->alignCount; ++i) {
        const DETOUR_ALIGN& alignment = trampoline->rAlign[i];
        if (targetOffset < alignment.targetEnd) {
            return trampoline->rbCode + trampolineStart;
        }
        targetStart = alignment.targetEnd;
        trampolineStart = alignment.trampolineEnd;
    }

    return targetOffset == targetStart
        ? trampoline->rbCode + trampolineStart
        : trampoline->pbRemain;
}

static PBYTE detour_align_trampoline_to_target(
    const DetourOperation& operation, BYTE trampolineOffset)
{
    BYTE targetStart = 0;
    for (BYTE i = 0; i < operation.pTrampoline->alignCount; ++i) {
        const DETOUR_ALIGN& alignment = operation.pTrampoline->rAlign[i];
        if (trampolineOffset < alignment.trampolineEnd) {
            return operation.pbTarget + targetStart;
        }
        targetStart = alignment.targetEnd;
    }

    return trampolineOffset < operation.pTrampoline->cbCodeWithJump
        ? operation.pTrampoline->pbRemain
        : operation.pbTarget + targetStart;
}

static LONG detour_relocate_suspended_threads(
    DetourSuspendedThreads& threads)
{
    for (auto& thread : threads) {
        if (thread.handle == NULL) {
            continue;
        }

        const ULONG_PTR instructionPointer =
            detour_context_instruction_pointer(thread.originalContext);
        PBYTE relocated = NULL;

        for (ULONG i = s_nPendingOperationCount; i-- != 0;) {
            const DetourOperation& operation = s_rPendingOperations[i];
            const auto targetBegin = reinterpret_cast<ULONG_PTR>(operation.pbTarget);
            const auto targetEnd = targetBegin + operation.pTrampoline->cbRestore;
            const auto trampolineBegin = reinterpret_cast<ULONG_PTR>(
                operation.pTrampoline->rbCode);
            const auto trampolineCodeEnd = trampolineBegin +
                operation.pTrampoline->cbCodeWithJump;

            if (!operation.fIsRemove &&
                instructionPointer >= targetBegin &&
                instructionPointer < targetEnd) {

                relocated = detour_align_target_to_trampoline(
                    operation.pTrampoline,
                    static_cast<BYTE>(instructionPointer - targetBegin));
                break;
            }

            if (operation.fIsRemove) {
                if (instructionPointer >= trampolineBegin &&
                    instructionPointer < trampolineCodeEnd) {

                    relocated = detour_align_trampoline_to_target(
                        operation,
                        static_cast<BYTE>(instructionPointer - trampolineBegin));
                    break;
                }

                if (instructionPointer >= targetBegin &&
                    instructionPointer < targetBegin + SIZE_OF_JMP) {
                    relocated = operation.pbTarget;
                    break;
                }

#if defined(_M_X64)
                const auto codeInBegin = reinterpret_cast<ULONG_PTR>(
                    operation.pTrampoline->rbCodeIn);
                if (instructionPointer >= codeInBegin &&
                    instructionPointer < codeInBegin + 6) {
                    relocated = operation.pbTarget;
                    break;
                }
#endif
            }
        }

        if (relocated != NULL &&
            reinterpret_cast<ULONG_PTR>(relocated) != instructionPointer) {
            detour_set_context_instruction_pointer(
                thread.relocatedContext,
                reinterpret_cast<ULONG_PTR>(relocated));
            thread.contextChanged = true;
        }
    }

    // Verify context writes are permitted before changing any instruction pointer.
    for (auto& thread : threads) {
        if (thread.handle != NULL && thread.contextChanged &&
            !SetThreadContext(thread.handle, &thread.originalContext)) {
            return GetLastError();
        }
    }

    for (SIZE_T threadIndex = 0; threadIndex < threads.size(); ++threadIndex) {
        auto& thread = threads[threadIndex];
        if (thread.handle == NULL || !thread.contextChanged) {
            continue;
        }
        if (!SetThreadContext(thread.handle, &thread.relocatedContext)) {
            const LONG error = GetLastError();
            for (SIZE_T i = 0; i < threadIndex; ++i) {
                auto& prior = threads[i];
                if (prior.handle != NULL && prior.contextChanged) {
                    SetThreadContext(prior.handle, &prior.originalContext);
                }
            }
            return error;
        }
    }

    return NO_ERROR;
}

//////////////////////////////////////////////////////////// Transaction APIs.
//

extern "C" LONG WINAPI DetourTransactionBegin()
{
    if (InterlockedCompareExchange(&s_nPendingThreadId,
                                   (LONG)GetCurrentThreadId(), 0) != 0) {
        return ERROR_INVALID_OPERATION;
    }

    s_nPendingOperationCount = 0;
    s_nPendingError = detour_writable_trampoline_regions();
    if (s_nPendingError != NO_ERROR) {
        LONG error = s_nPendingError;
        detour_runnable_trampoline_regions();
        s_nPendingError = NO_ERROR;
        InterlockedExchange(&s_nPendingThreadId, 0);
        return error;
    }

    return NO_ERROR;
}

extern "C" LONG WINAPI DetourTransactionAbort()
{
    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    for (ULONG i = s_nPendingOperationCount; i-- != 0;) {
        DetourOperation& o = s_rPendingOperations[i];
        DWORD dwOld;
        VirtualProtect(o.pbTarget, o.pTrampoline->cbRestore, o.dwPerm, &dwOld);

        if (!o.fIsRemove) {
            detour_free_trampoline(o.pTrampoline);
        }
    }
    s_nPendingOperationCount = 0;

    detour_runnable_trampoline_regions();
    s_nPendingError = NO_ERROR;
    InterlockedExchange(&s_nPendingThreadId, 0);

    return NO_ERROR;
}

extern "C" LONG WINAPI DetourTransactionCommit()
{
    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    if (s_nPendingError != NO_ERROR) {
        LONG error = s_nPendingError;
        DetourTransactionAbort();
        return error;
    }

    DetourSuspendedThreads suspendedThreads;
    if (s_nPendingOperationCount != 0) {
        LONG error = detour_suspend_other_threads(suspendedThreads);
        if (error != NO_ERROR) {
            DetourTransactionAbort();
            return error;
        }

        error = detour_relocate_suspended_threads(suspendedThreads);
        if (error != NO_ERROR) {
            detour_resume_and_close_threads(suspendedThreads);
            DetourTransactionAbort();
            return error;
        }
    }

    for (ULONG i = s_nPendingOperationCount; i-- != 0;) {
        DetourOperation& o = s_rPendingOperations[i];
        if (o.fIsRemove) {
            CopyMemory(o.pbTarget, o.pTrampoline->rbRestore,
                       o.pTrampoline->cbRestore);
            *o.ppbPointer = o.pbTarget;
        }
        else {
#ifdef _M_X64
            detour_gen_jmp_indirect(o.pTrampoline->rbCodeIn,
                                    &o.pTrampoline->pbDetour);
            detour_gen_jmp_immediate(o.pbTarget, o.pTrampoline->rbCodeIn);
#endif // _M_X64

#ifdef _M_IX86
            detour_gen_jmp_immediate(o.pbTarget, o.pTrampoline->pbDetour);
#endif // _M_IX86

#ifdef _M_ARM64
            detour_gen_jmp_indirect(o.pbTarget,
                                    (ULONG64*)&o.pTrampoline->pbDetour);
#endif // _M_ARM64
            *o.ppbPointer = o.pTrampoline->rbCode;
        }
    }

    HANDLE hProcess = GetCurrentProcess();
    for (ULONG i = s_nPendingOperationCount; i-- != 0;) {
        DetourOperation& o = s_rPendingOperations[i];
        DWORD dwOld;
        VirtualProtect(o.pbTarget, o.pTrampoline->cbRestore, o.dwPerm, &dwOld);
        FlushInstructionCache(hProcess, o.pbTarget, o.pTrampoline->cbRestore);

    }
    s_nPendingOperationCount = 0;

    // A detached trampoline may still be cached in a suspended thread's data
    // registers even when its instruction pointer is elsewhere. Keep published
    // trampolines alive for the lifetime of this loaded module rather than
    // risking a stale-pointer use-after-free when that thread resumes.
    detour_runnable_trampoline_regions();
    detour_resume_and_close_threads(suspendedThreads);
    InterlockedExchange(&s_nPendingThreadId, 0);
    return NO_ERROR;
}

///////////////////////////////////////////////////////////// Transacted APIs.
//
extern "C" LONG WINAPI DetourAttach(_Inout_ PVOID *ppPointer,
                         _In_ PVOID pDetour)
{
    if (pDetour == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        return s_nPendingError;
    }

    if (ppPointer == NULL) {
        return ERROR_INVALID_HANDLE;
    }
    if (*ppPointer == NULL) {
        return s_nPendingError = ERROR_INVALID_HANDLE;
    }

    PBYTE pbTarget = detour_code_from_pointer(*ppPointer);
    pDetour = detour_code_from_pointer(pDetour);

    if (pDetour == (PVOID)pbTarget) {
        return NO_ERROR;
    }

    if (s_nPendingOperationCount == DETOUR_PENDING_OPERATION_CAPACITY) {
        return s_nPendingError = ERROR_NOT_ENOUGH_MEMORY;
    }

    PDETOUR_TRAMPOLINE pTrampoline = detour_alloc_trampoline(pbTarget);
    if (pTrampoline == NULL) {
        return s_nPendingError = ERROR_NOT_ENOUGH_MEMORY;
    }

    const auto fail = [&](LONG error) {
        detour_free_trampoline(pTrampoline);
        s_nPendingError = error;
        return error;
    };

    PBYTE pbSrc = pbTarget;
    PBYTE pbTrampoline = pTrampoline->rbCode;
    PBYTE pbPool = pbTrampoline + sizeof(pTrampoline->rbCode);
    ULONG cbTarget = 0;

    pTrampoline->cbCode = 0;
    pTrampoline->cbCodeWithJump = 0;
    pTrampoline->cbRestore = 0;
    pTrampoline->alignCount = 0;
    ZeroMemory(pTrampoline->rAlign, sizeof(pTrampoline->rAlign));

    while (cbTarget < SIZE_OF_JMP) {
        if (pTrampoline->alignCount == ARRAYSIZE(pTrampoline->rAlign)) {
            return fail(ERROR_INVALID_BLOCK);
        }

        PBYTE pbOp = pbSrc;
        LONG lExtra = 0;

        pbSrc = (PBYTE)DetourCopyInstruction(pbTrampoline, pbSrc, &lExtra);
        pbTrampoline += (pbSrc - pbOp) + lExtra;
        cbTarget = (LONG)(pbSrc - pbTarget);

        if (pbTrampoline > pbPool) {
            return fail(ERROR_INVALID_BLOCK);
        }

        const auto targetEnd = static_cast<SIZE_T>(pbSrc - pbTarget);
        const auto trampolineEnd = static_cast<SIZE_T>(
            pbTrampoline - pTrampoline->rbCode);
        if (targetEnd > MAXBYTE || trampolineEnd > MAXBYTE) {
            return fail(ERROR_INVALID_BLOCK);
        }

        pTrampoline->rAlign[pTrampoline->alignCount++] = {
            static_cast<BYTE>(targetEnd),
            static_cast<BYTE>(trampolineEnd),
        };

        if (detour_does_code_end_function(pbOp)) {
            break;
        }
    }

    // Consume, but don't duplicate padding if it is needed and available.
    while (cbTarget < SIZE_OF_JMP) {
        LONG cFiller = detour_is_code_filler(pbSrc);
        if (cFiller == 0) {
            break;
        }

        pbSrc += cFiller;
        cbTarget = (LONG)(pbSrc - pbTarget);
    }

    if (cbTarget < SIZE_OF_JMP ||
        cbTarget > sizeof(pTrampoline->rbRestore)) {
        return fail(ERROR_INVALID_BLOCK);
    }

    if (pbTrampoline > pbPool ||
        pbPool - pbTrampoline < SIZE_OF_TRAMPOLINE_JMP) {
        return fail(ERROR_INVALID_BLOCK);
    }

    pTrampoline->cbRestore = (BYTE)cbTarget;
    CopyMemory(pTrampoline->rbRestore, pbTarget, cbTarget);

    pTrampoline->pbRemain = pbTarget + cbTarget;
    pTrampoline->pbDetour = (PBYTE)pDetour;

    pTrampoline->cbCode = static_cast<BYTE>(
        pbTrampoline - pTrampoline->rbCode);

#ifdef _M_X64
    pbTrampoline = detour_gen_jmp_indirect(pbTrampoline, &pTrampoline->pbRemain);
#endif // _M_X64

#ifdef _M_IX86
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, pTrampoline->pbRemain);
#endif // _M_IX86

#ifdef _M_ARM64
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, &pbPool, pTrampoline->pbRemain);
#endif // _M_ARM64

    if (pbTrampoline > pbPool) {
        return fail(ERROR_INVALID_BLOCK);
    }

    pTrampoline->cbCodeWithJump = static_cast<BYTE>(
        pbTrampoline - pTrampoline->rbCode);

    DWORD dwOld = 0;
    if (!VirtualProtect(pbTarget, cbTarget, PAGE_EXECUTE_READWRITE, &dwOld)) {
        return fail(GetLastError());
    }

    s_rPendingOperations[s_nPendingOperationCount++] = {
        .ppbPointer = (PBYTE*)ppPointer,
        .pbTarget = pbTarget,
        .pTrampoline = pTrampoline,
        .dwPerm = dwOld,
        .fIsRemove = false,
    };

    return NO_ERROR;
}

extern "C" LONG WINAPI DetourDetach(_Inout_ PVOID *ppPointer,
                         _In_ PVOID pDetour)
{
    if (s_nPendingThreadId != (LONG)GetCurrentThreadId()) {
        return ERROR_INVALID_OPERATION;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != NO_ERROR) {
        return s_nPendingError;
    }

    if (pDetour == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (ppPointer == NULL) {
        return ERROR_INVALID_HANDLE;
    }
    if (*ppPointer == NULL) {
        return s_nPendingError = ERROR_INVALID_HANDLE;
    }

    if (s_nPendingOperationCount == DETOUR_PENDING_OPERATION_CAPACITY) {
        return s_nPendingError = ERROR_NOT_ENOUGH_MEMORY;
    }

    PDETOUR_TRAMPOLINE pTrampoline = (PDETOUR_TRAMPOLINE)
        detour_code_from_pointer(*ppPointer);
    pDetour = detour_code_from_pointer(pDetour);

    LONG cbTarget = pTrampoline->cbRestore;
    PBYTE pbTarget = pTrampoline->pbRemain - cbTarget;
    if (cbTarget == 0 || cbTarget > sizeof(pTrampoline->rbRestore)) {
        return s_nPendingError = ERROR_INVALID_BLOCK;
    }

    if (pTrampoline->pbDetour != pDetour) {
        return s_nPendingError = ERROR_INVALID_BLOCK;
    }

    DWORD dwOld = 0;
    if (!VirtualProtect(pbTarget, cbTarget,
                        PAGE_EXECUTE_READWRITE, &dwOld)) {
        return s_nPendingError = GetLastError();
    }

    s_rPendingOperations[s_nPendingOperationCount++] = {
        .ppbPointer = (PBYTE*)ppPointer,
        .pbTarget = pbTarget,
        .pTrampoline = pTrampoline,
        .dwPerm = dwOld,
        .fIsRemove = true,
    };

    return NO_ERROR;
}

//////////////////////////////////////////////////////////////////////////////
//
// Helpers for manipulating page protection.
//

// For reference:
//   PAGE_NOACCESS          0x01
//   PAGE_READONLY          0x02
//   PAGE_READWRITE         0x04
//   PAGE_WRITECOPY         0x08
//   PAGE_EXECUTE           0x10
//   PAGE_EXECUTE_READ      0x20
//   PAGE_EXECUTE_READWRITE 0x40
//   PAGE_EXECUTE_WRITECOPY 0x80
//   PAGE_GUARD             ...
//   PAGE_NOCACHE           ...
//   PAGE_WRITECOMBINE      ...

constexpr DWORD DETOUR_PAGE_EXECUTE_ALL = PAGE_EXECUTE |
    PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
constexpr DWORD DETOUR_PAGE_NO_EXECUTE_ALL = PAGE_NOACCESS |
    PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY;
constexpr DWORD DETOUR_PAGE_ATTRIBUTES =
    ~(DETOUR_PAGE_EXECUTE_ALL | DETOUR_PAGE_NO_EXECUTE_ALL);

static_assert((DETOUR_PAGE_NO_EXECUTE_ALL << 4) == DETOUR_PAGE_EXECUTE_ALL);

static DWORD DetourPageProtectAdjustExecute(_In_  DWORD dwOldProtect,
                                            _In_  DWORD dwNewProtect)
//  Copy EXECUTE from dwOldProtect to dwNewProtect.
{
    bool const fOldExecute = ((dwOldProtect & DETOUR_PAGE_EXECUTE_ALL) != 0);
    bool const fNewExecute = ((dwNewProtect & DETOUR_PAGE_EXECUTE_ALL) != 0);

    if (fOldExecute && !fNewExecute) {
        dwNewProtect = ((dwNewProtect & DETOUR_PAGE_NO_EXECUTE_ALL) << 4)
            | (dwNewProtect & DETOUR_PAGE_ATTRIBUTES);
    }
    else if (!fOldExecute && fNewExecute) {
        dwNewProtect = ((dwNewProtect & DETOUR_PAGE_EXECUTE_ALL) >> 4)
            | (dwNewProtect & DETOUR_PAGE_ATTRIBUTES);
    }
    return dwNewProtect;
}

_Success_(return != FALSE)
static BOOL WINAPI DetourVirtualProtectSameExecuteEx(_In_  HANDLE hProcess,
                                              _In_  PVOID pAddress,
                                              _In_  SIZE_T nSize,
                                              _In_  DWORD dwNewProtect,
                                              _Out_ PDWORD pdwOldProtect)
// Some systems do not allow executability of a page to change. This function applies
// dwNewProtect to [pAddress, nSize), but preserving the previous executability.
// This function is meant to be a drop-in replacement for some uses of VirtualProtectEx.
// When "restoring" page protection, there is no need to use this function.
{
    MEMORY_BASIC_INFORMATION mbi;

    // Query to get existing execute access.

    ZeroMemory(&mbi, sizeof(mbi));

    if (VirtualQueryEx(hProcess, pAddress, &mbi, sizeof(mbi)) == 0) {
        return FALSE;
    }
    return VirtualProtectEx(hProcess, pAddress, nSize,
                            DetourPageProtectAdjustExecute(mbi.Protect, dwNewProtect),
                            pdwOldProtect);
}

//////////////////////////////////////////////////////////////////////////////
// Payload discovery and image restoration

static PVOID WINAPI DetourFindPayloadEx(REFGUID guid, DWORD* dataSize)
{
    if (dataSize != NULL) {
        *dataSize = 0;
    }

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

                    if (dataSize != NULL) {
                        *dataSize = header->cbData;
                    }
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

extern "C" PVOID WINAPI DetourFindPayload(const GUID* guid, DWORD* dataSize)
{
    if (guid == NULL) {
        if (dataSize != NULL) {
            *dataSize = 0;
        }
        SetLastError(ERROR_INVALID_PARAMETER);
        return NULL;
    }
    return DetourFindPayloadEx(*guid, dataSize);
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

static BOOL Protect(PVOID address, SIZE_T size, DWORD protection, PDWORD oldProtection)
{
    return DetourVirtualProtectSameExecuteEx(
        GetCurrentProcess(), address, size, protection, oldProtection);
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

    if (Protect(restore->pinh, restore->cbinh, PAGE_EXECUTE_READWRITE, &ntProtection)) {
        CopyMemory(restore->pinh, &restore->inh, restore->cbinh);

        if (restore->pclr == NULL || promotedManagedImage) {
            succeeded = TRUE;
        }
        else if (Protect(restore->pclr, restore->cbclr,
                         PAGE_EXECUTE_READWRITE, &clrProtection)) {
            CopyMemory(restore->pclr, &restore->clr, restore->cbclr);
            VirtualProtect(restore->pclr, restore->cbclr, clrProtection, &ignored);
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
    PVOID data = DetourFindPayloadEx(DETOUR_EXE_RESTORE_GUID, &dataSize);
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
    HANDLE process, REFGUID guid, LPCVOID data, DWORD dataSize);

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
                                         _Out_ PIMAGE_NT_HEADERS32 pNtHeader,
                                         _Out_opt_ PVOID *pRemoteNtHeader)
{
    ZeroMemory(pNtHeader, sizeof(*pNtHeader));
    if (pRemoteNtHeader) {
        *pRemoteNtHeader = NULL;
    }

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

        PVOID remoteHeader
            = LoadNtHeaderFromProcess(hProcess, (HMODULE)pbLast, pNtHeader);
        if (remoteHeader) {
            if (pRemoteNtHeader) {
                *pRemoteNtHeader = remoteHeader;
            }

            return (HMODULE)pbLast;
        }
    }
    return NULL;
}

//////////////////////////////////////////////////////////////////////////////
//
// Find payloads in target process.
//

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
            if (GetLastError() == ERROR_INVALID_PARAMETER) {
                break;
            }
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
        der.cbclr = sizeof(der.clr);
        if (!ReadProcessMemory(hProcess, der.pclr, &der.clr, der.cbclr, NULL)) {
            return FALSE;
        }
    }

    return TRUE;
}

//////////////////////////////////////////////////////////////////////////////
// Import-table editing

static BOOL UpdateImports(HANDLE hProcess, HMODULE hModule, LPCSTR lpDll)
{
    BOOL fSucceeded = FALSE;
    DWORD cbNew = 0;

    BYTE * pbNew = NULL;
    DWORD i;
    SIZE_T cbRead;

    PBYTE pbModule = (PBYTE)hModule;

    IMAGE_DOS_HEADER idh;
    ZeroMemory(&idh, sizeof(idh));
    if (!ReadProcessMemory(hProcess, pbModule, &idh, sizeof(idh), &cbRead)
        || cbRead < sizeof(idh)) {


      finish:
        if (pbNew != NULL) {
            delete[] pbNew;
            pbNew = NULL;
        }
        return fSucceeded;
    }

    IMAGE_NT_HEADERS inh;
    ZeroMemory(&inh, sizeof(inh));

    if (!ReadProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), &cbRead)
        || cbRead < sizeof(inh)) {
        goto finish;
    }

    if (inh.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        SetLastError(ERROR_INVALID_BLOCK);
        goto finish;
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

            goto finish;
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
                goto finish;
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
        goto finish;
    }
    const DWORD obOld = descriptorSize * (nOldDlls + 1);
    DWORD obTab = PadToDwordPtr(obOld);
    // Check for integer overflow.
    if (obTab < obOld) {
        goto finish;
    }
    constexpr DWORD stSize = sizeof(IMAGE_THUNK_DATA) * 4;
    if (obTab > MAXDWORD - stSize) {
        goto finish;
    }
    DWORD obStr = obTab + stSize;

    const size_t dllLength = strnlen_s(lpDll, DETOUR_MAX_DLL_PATH);
    if (dllLength == DETOUR_MAX_DLL_PATH) {
        SetLastError(ERROR_BAD_PATHNAME);
        goto finish;
    }
    const DWORD paddedDllSize = PadToDword(static_cast<DWORD>(dllLength + 1));
    if (obStr > MAXDWORD - paddedDllSize) {
        goto finish;
    }
    cbNew = obStr + paddedDllSize;
    pbNew = new (std::nothrow) BYTE[cbNew];
    if (pbNew == NULL) {
        goto finish;
    }
    ZeroMemory(pbNew, cbNew);

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
        goto finish;
    }

    PIMAGE_IMPORT_DESCRIPTOR piid = (PIMAGE_IMPORT_DESCRIPTOR)pbNew;
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

            goto finish;
        }
    }

    CopyMemory(pbNew + obStr, lpDll, dllLength + 1);

    piid[0].OriginalFirstThunk = obBase + obTab;

    // One ordinal import plus a terminator for both the import table and IAT.
    pt = reinterpret_cast<IMAGE_THUNK_DATA*>(pbNew + obTab);
    pt[0].u1.Ordinal = IMAGE_ORDINAL_FLAG + 1;
    pt[1].u1.Ordinal = 0;

    constexpr DWORD iatOffset = sizeof(IMAGE_THUNK_DATA) * 2;
    piid[0].FirstThunk = obBase + obTab + iatOffset;
    pt = reinterpret_cast<IMAGE_THUNK_DATA*>(pbNew + obTab + iatOffset);
    pt[0].u1.Ordinal = IMAGE_ORDINAL_FLAG + 1;
    pt[1].u1.Ordinal = 0;
    piid[0].Name = obBase + obStr;

    obStr += paddedDllSize;

if (!WriteProcessMemory(hProcess, pbNewIid, pbNew, obStr, NULL)) {
        goto finish;
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
    if (!DetourVirtualProtectSameExecuteEx(hProcess, pbModule, inh.OptionalHeader.SizeOfHeaders,
                                           PAGE_EXECUTE_READWRITE, &dwProtect)) {
        goto finish;
    }

    inh.OptionalHeader.CheckSum = 0;

    if (!WriteProcessMemory(hProcess, pbModule + idh.e_lfanew, &inh, sizeof(inh), NULL)) {
        goto finish;
    }

    if (!VirtualProtectEx(hProcess, pbModule, inh.OptionalHeader.SizeOfHeaders,
                          dwProtect, &dwProtect)) {
        goto finish;
    }

    fSucceeded = TRUE;
    goto finish;
}

//////////////////////////////////////////////////////////////////////////////
//
#if defined(_WIN64)

static_assert(sizeof(IMAGE_NT_HEADERS64) == sizeof(IMAGE_NT_HEADERS32) + 16);

static BOOL UpdateFrom32To64(HANDLE hProcess, HMODULE hModule, WORD machine,
                             DETOUR_EXE_RESTORE& der)
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
    inh64.FileHeader.Machine = machine;
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
    if (!DetourVirtualProtectSameExecuteEx(hProcess, pbModule, inh64.OptionalHeader.SizeOfHeaders,
                                           PAGE_EXECUTE_READWRITE, &dwProtect)) {
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

static BOOL UpdateProcessWithDllEx(HANDLE hProcess,
                                   HMODULE hModule,
                                   WORD processMachine,
                                   LPCSTR lpDll);

//////////////////////////////////////////////////////////////////////////////
//
struct DETOUR_PROCESS_MACHINE_INFORMATION
{
    USHORT processMachine;
    USHORT reserved;
    ULONG attributes;
};

using PDETOUR_IS_WOW64_PROCESS2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
using PDETOUR_GET_PROCESS_INFORMATION = BOOL(WINAPI*)(HANDLE, INT, LPVOID, DWORD);

static WORD NormalizeProcessMachine(WORD machine)
{
#ifdef IMAGE_FILE_MACHINE_ARM64EC
    if (machine == IMAGE_FILE_MACHINE_ARM64EC) {
        return IMAGE_FILE_MACHINE_AMD64;
    }
#endif
    return machine;
}

static WORD NativeMachineFromSystemInfo()
{
    SYSTEM_INFO information{};
    GetNativeSystemInfo(&information);
    switch (information.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_INTEL:
        return IMAGE_FILE_MACHINE_I386;
    case PROCESSOR_ARCHITECTURE_AMD64:
        return IMAGE_FILE_MACHINE_AMD64;
    case PROCESSOR_ARCHITECTURE_ARM64:
        return IMAGE_FILE_MACHINE_ARM64;
    default:
        return IMAGE_FILE_MACHINE_UNKNOWN;
    }
}

static BOOL GetProcessMachines(
    HANDLE process, WORD& processMachine, WORD& nativeMachine)
{
    processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 == NULL) {
        return FALSE;
    }

    const auto isWow64Process2 = reinterpret_cast<PDETOUR_IS_WOW64_PROCESS2>(
        GetProcAddress(kernel32, "IsWow64Process2"));
    if (isWow64Process2 != NULL) {
        USHORT wowMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        USHORT hostMachine = IMAGE_FILE_MACHINE_UNKNOWN;
        if (!isWow64Process2(process, &wowMachine, &hostMachine)) {
            return FALSE;
        }

        wowMachine = NormalizeProcessMachine(wowMachine);
        hostMachine = NormalizeProcessMachine(hostMachine);
        nativeMachine = hostMachine;
        if (wowMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
            processMachine = wowMachine;
            return TRUE;
        }

        if (hostMachine != IMAGE_FILE_MACHINE_ARM64) {
            processMachine = hostMachine;
            return processMachine != IMAGE_FILE_MACHINE_UNKNOWN;
        }

        // IsWow64Process2 reports UNKNOWN/ARM64 for both native ARM64 and
        // emulated x64 processes. Windows 11's ProcessMachineTypeInfo removes
        // that ambiguity; Windows 10 on ARM did not support x64 emulation.
        const auto getProcessInformation =
            reinterpret_cast<PDETOUR_GET_PROCESS_INFORMATION>(
                GetProcAddress(kernel32, "GetProcessInformation"));
        if (getProcessInformation != NULL) {
            constexpr INT processMachineTypeInfo = 9;
            DETOUR_PROCESS_MACHINE_INFORMATION information{};
            if (getProcessInformation(process, processMachineTypeInfo,
                                      &information, sizeof(information))) {
                processMachine = NormalizeProcessMachine(
                    information.processMachine);
                if (processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
                    return TRUE;
                }
            }
            else {
                const DWORD error = GetLastError();
                if (error != ERROR_INVALID_PARAMETER &&
                    error != ERROR_NOT_SUPPORTED) {
                    return FALSE;
                }
            }
        }

        processMachine = IMAGE_FILE_MACHINE_ARM64;
        return TRUE;
    }

    nativeMachine = NativeMachineFromSystemInfo();
    if (nativeMachine == IMAGE_FILE_MACHINE_UNKNOWN ||
        nativeMachine == IMAGE_FILE_MACHINE_ARM64) {
        SetLastError(ERROR_NOT_SUPPORTED);
        return FALSE;
    }

    BOOL isWow64 = FALSE;
    if (!IsWow64Process(process, &isWow64)) {
        return FALSE;
    }
    processMachine = isWow64 ? IMAGE_FILE_MACHINE_I386 : nativeMachine;
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

    // Find the next memory region that contains a mapped PE image.
    //
    HMODULE hModule = NULL;
    HMODULE hLast = NULL;


    for (;;) {
        IMAGE_NT_HEADERS32 inh;

        if ((hLast = EnumerateModulesInProcess(hProcess, hLast, &inh, NULL)) == NULL) {
            break;
        }


        if ((inh.FileHeader.Characteristics & IMAGE_FILE_DLL) == 0) {
            hModule = hLast;
        }
    }

    if (hModule == NULL) {
        SetLastError(ERROR_INVALID_OPERATION);
        return FALSE;
    }

    return UpdateProcessWithDllEx(hProcess, hModule, processMachine, lpDll);
}

static BOOL UpdateProcessWithDllEx(HANDLE hProcess,
                                   HMODULE hModule,
                                   WORD processMachine,
                                   LPCSTR lpDll)
{
    // Find the next memory region that contains a mapped PE image.
    //
    const BOOL bIs32BitProcess = processMachine == IMAGE_FILE_MACHINE_I386;
    BOOL bIs32BitExe = FALSE;


    IMAGE_NT_HEADERS32 inh;

    if (hModule == NULL || !LoadNtHeaderFromProcess(hProcess, hModule, &inh)) {
        SetLastError(ERROR_INVALID_OPERATION);
        return FALSE;
    }

    if (inh.OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC
        && inh.FileHeader.Machine != 0) {

        bIs32BitExe = TRUE;
    }


    if (hModule == NULL) {
        SetLastError(ERROR_INVALID_OPERATION);
        return FALSE;
    }

    // Save the various headers for DetourRestoreAfterWith.
    //
    DETOUR_EXE_RESTORE der;

    if (!RecordExeRestore(hProcess, hModule, der)) {
        return FALSE;
    }

#if defined(_WIN64)
    // Try to convert a neutral 32-bit managed binary to a 64-bit managed binary.
    if (bIs32BitExe && !bIs32BitProcess) {
        if (!der.pclr                       // Native binary
            || (der.clr.Flags & COMIMAGE_FLAGS_ILONLY) == 0     // Or mixed-mode MSIL
            || (der.clr.Flags & COMIMAGE_FLAGS_32BITREQUIRED) != 0) {  // Or 32BIT Required MSIL

            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }

        if (!UpdateFrom32To64(hProcess, hModule,
#if defined(_M_X64)
                              IMAGE_FILE_MACHINE_AMD64,
#elif defined(_M_ARM64)
                              IMAGE_FILE_MACHINE_ARM64,
#endif
                              der)) {
            return FALSE;
        }
        bIs32BitExe = FALSE;
    }
#endif // _WIN64

    // Now decide if we can insert the detour.

#if defined(_M_IX86)
    if (bIs32BitProcess) {
        // 32-bit native or 32-bit managed process on any platform.
        if (!UpdateImports(hProcess, hModule, lpDll)) {
            return FALSE;
        }
    }
    else {
        // 64-bit native or 64-bit managed process.
        //
        // Can't detour a 64-bit process with 32-bit code.
        // Note: This happens for 32-bit PE binaries containing only
        // manage code that have been marked as 64-bit ready.
        //
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
#elif defined(_WIN64)
    if (bIs32BitProcess || bIs32BitExe) {
        // Can't detour a 32-bit process with 64-bit code.
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }
    else {
        // 64-bit native or 64-bit managed process on any platform.
        if (!UpdateImports(hProcess, hModule, lpDll)) {
            return FALSE;
        }
    }
#endif // _WIN64

    /////////////////////////////////////////////////// Update the CLR header.
    //
    if (der.pclr != NULL) {
        DETOUR_CLR_HEADER clr;
        CopyMemory(&clr, &der.clr, sizeof(clr));
        clr.Flags &= ~COMIMAGE_FLAGS_ILONLY;    // Clear the IL_ONLY flag.

        DWORD dwProtect;
        if (!DetourVirtualProtectSameExecuteEx(hProcess, der.pclr, sizeof(clr), PAGE_READWRITE, &dwProtect)) {
            return FALSE;
        }

        if (!WriteProcessMemory(hProcess, der.pclr, &clr, sizeof(clr), NULL)) {
            return FALSE;
        }

        if (!VirtualProtectEx(hProcess, der.pclr, sizeof(clr), dwProtect, &dwProtect)) {
            return FALSE;
        }

#if defined(_WIN64)
        if (der.clr.Flags & COMIMAGE_FLAGS_32BITREQUIRED) { // Is the 32BIT Required Flag set?
            SetLastError(ERROR_INVALID_HANDLE);
            return FALSE;
        }
#endif // _WIN64
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

static BOOL s_fSearchedForHelper = FALSE;
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
    PVOID pvData;
    DWORD cbData;

    if (s_fSearchedForHelper) {
        return (s_pHelper != NULL);
    }

    s_fSearchedForHelper = TRUE;
    pvData = DetourFindPayloadEx(DETOUR_EXE_HELPER_GUID, &cbData);

    constexpr DWORD minimumSize = offsetof(DETOUR_EXE_HELPER, dll) + 1;
    if (pvData == NULL || cbData < minimumSize) {
        return FALSE;
    }

    s_pHelper = (PDETOUR_EXE_HELPER)pvData;
    if (s_pHelper->cb < minimumSize || s_pHelper->cb > cbData ||
        s_pHelper->dll[s_pHelper->cb - offsetof(DETOUR_EXE_HELPER, dll) - 1] != '\0') {
        s_pHelper = NULL;
        return FALSE;
    }

    return TRUE;
}

static LPCSTR DllSuffixForMachine(WORD machine)
{
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
        return "-32.dll";
    case IMAGE_FILE_MACHINE_AMD64:
        return "-64.dll";
    case IMAGE_FILE_MACHINE_ARM64:
        return "-arm64.dll";
    default:
        return NULL;
    }
}

static PDETOUR_EXE_HELPER AllocExeHelper(
    DWORD targetPid, LPCSTR dll, WORD targetMachine)
{
    constexpr LPCSTR knownSuffixes[] = { "-32.dll", "-64.dll", "-arm64.dll" };
    const LPCSTR targetSuffix = DllSuffixForMachine(targetMachine);
    if (dll == NULL || targetSuffix == NULL) {
        SetLastError(ERROR_EXE_MACHINE_TYPE_MISMATCH);
        return NULL;
    }

    const size_t length = strnlen_s(dll, DETOUR_MAX_DLL_PATH);
    if (length == 0 || length == DETOUR_MAX_DLL_PATH) {
        SetLastError(ERROR_BAD_PATHNAME);
        return NULL;
    }

    size_t oldSuffixLength = 0;
    for (LPCSTR suffix : knownSuffixes) {
        const size_t suffixLength = strlen(suffix);
        if (length >= suffixLength &&
            _stricmp(dll + length - suffixLength, suffix) == 0) {
            oldSuffixLength = suffixLength;
            break;
        }
    }
    if (oldSuffixLength == 0) {
        SetLastError(ERROR_BAD_PATHNAME);
        return NULL;
    }

    const size_t targetSuffixLength = strlen(targetSuffix);
    const size_t targetLength = length - oldSuffixLength + targetSuffixLength;
    const size_t allocationSize = offsetof(DETOUR_EXE_HELPER, dll) + targetLength + 1;
    auto helper = reinterpret_cast<PDETOUR_EXE_HELPER>(
        new (std::nothrow) BYTE[allocationSize]);
    if (helper == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }

    helper->cb = static_cast<DWORD>(allocationSize);
    helper->pid = targetPid;
    const size_t prefixLength = length - oldSuffixLength;
    CopyMemory(helper->dll, dll, prefixLength);
    CopyMemory(helper->dll + prefixLength, targetSuffix, targetSuffixLength + 1);
    return helper;
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
        NormalizeProcessMachine(fileHeader.Machine) != expectedMachine) {
        error = ERROR_EXE_MACHINE_TYPE_MISMATCH;
    }

    CloseHandle(file);
    SetLastError(error);
    return error == NO_ERROR;
}

static BOOL AppendPathSuffix(CHAR* path, DWORD capacity, LPCSTR suffix)
{
    const size_t length = strnlen_s(path, capacity);
    const size_t suffixLength = strlen(suffix);
    if (length == capacity || length + suffixLength + 1 > capacity) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }
    CopyMemory(path + length, suffix, suffixLength + 1);
    return TRUE;
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

static BOOL GetHelperExecutableA(WORD targetMachine, CHAR (&path)[MAX_PATH])
{
    DWORD length = 0;
    if (targetMachine == IMAGE_FILE_MACHINE_I386) {
        length = GetSystemWow64DirectoryA(path, ARRAYSIZE(path));
    }
#if defined(_M_IX86)
    else {
        length = GetWindowsDirectoryA(path, ARRAYSIZE(path));
        if (length != 0 && length < ARRAYSIZE(path) &&
            !AppendPathSuffix(path, ARRAYSIZE(path), "\\sysnative")) {
            return FALSE;
        }
    }
#else
    else {
        length = GetSystemDirectoryA(path, ARRAYSIZE(path));
    }
#endif
    if (length == 0 || length >= ARRAYSIZE(path)) {
        if (length >= ARRAYSIZE(path)) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
        }
        return FALSE;
    }
    return AppendPathSuffix(path, ARRAYSIZE(path), "\\rundll32.exe");
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
    return nativeMachine == IMAGE_FILE_MACHINE_ARM64 &&
        targetMachine != IMAGE_FILE_MACHINE_I386 &&
        (targetMachine == IMAGE_FILE_MACHINE_AMD64 ||
         DETOUR_CURRENT_PROCESS_MACHINE == IMAGE_FILE_MACHINE_AMD64);
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

static BOOL WINAPI DetourProcessViaHelperA(
    DWORD targetPid, LPCSTR dllName, WORD targetMachine, WORD nativeMachine,
    PDETOUR_CREATE_PROCESS_ROUTINEA createProcess)
{
    auto helper = AllocExeHelper(targetPid, dllName, targetMachine);
    if (helper == NULL) {
        return FALSE;
    }

    BOOL result = FALSE;
    DWORD error = NO_ERROR;
    CHAR executable[MAX_PATH]{};
    const size_t commandCapacity =
        strlen(helper->dll) + ARRAYSIZE("rundll32.exe \"\",#1");
    std::vector<CHAR> command(commandCapacity);
    PROCESS_INFORMATION processInformation{};
    STARTUPINFOEXA startupInfo{};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;

    if (!ValidateHelperImage(helper->dll, targetMachine) ||
        !GetHelperExecutableA(targetMachine, executable)) {
        error = GetLastError();
    }
    else if (sprintf_s(command.data(), command.size(),
                       "rundll32.exe \"%s\",#1", helper->dll) < 0) {
        error = ERROR_INSUFFICIENT_BUFFER;
    }
    else {
        DWORD flags = CREATE_SUSPENDED;
        startupInfo.StartupInfo.cb = sizeof(STARTUPINFOA);
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

        if (error == NO_ERROR &&
            !createProcess(executable, command.data(), NULL, NULL, FALSE, flags,
                           NULL, NULL, &startupInfo.StartupInfo,
                           &processInformation)) {
            error = GetLastError();
        }
        else if (error == NO_ERROR &&
                 !DetourCopyPayloadToProcess(
                     processInformation.hProcess, DETOUR_EXE_HELPER_GUID,
                     helper, helper->cb)) {
            error = GetLastError();
            TerminateProcess(processInformation.hProcess, error);
            CloseHandle(processInformation.hProcess);
            CloseHandle(processInformation.hThread);
        }
        else if (error == NO_ERROR) {
            result = FinishHelperProcess(processInformation);
            error = GetLastError();
        }
    }

    DeleteMachineAttributeList(attributes);
    delete[] reinterpret_cast<PBYTE>(helper);
    SetLastError(result ? NO_ERROR : error);
    return result;
}

static BOOL WINAPI DetourProcessViaHelperW(
    DWORD targetPid, LPCSTR dllName, WORD targetMachine, WORD nativeMachine,
    PDETOUR_CREATE_PROCESS_ROUTINEW createProcess)
{
    auto helper = AllocExeHelper(targetPid, dllName, targetMachine);
    if (helper == NULL) {
        return FALSE;
    }

    BOOL result = FALSE;
    DWORD error = NO_ERROR;
    WCHAR executable[MAX_PATH]{};
    std::vector<WCHAR> wideDllName;
    std::vector<WCHAR> command;
    PROCESS_INFORMATION processInformation{};
    STARTUPINFOEXW startupInfo{};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = NULL;

    const int wideLength = MultiByteToWideChar(
        CP_ACP, 0, helper->dll, -1, NULL, 0);
    if (wideLength <= 0) {
        error = GetLastError();
    }
    else {
        wideDllName.resize(static_cast<size_t>(wideLength));
        if (MultiByteToWideChar(
                CP_ACP, 0, helper->dll, -1,
                wideDllName.data(), wideLength) <= 0) {
            error = GetLastError();
        }
    }

    if (error == NO_ERROR &&
        (!ValidateHelperImage(helper->dll, targetMachine) ||
         !GetHelperExecutableW(targetMachine, executable))) {
        error = GetLastError();
    }
    if (error == NO_ERROR) {
        const size_t commandCapacity = wideDllName.size() +
            ARRAYSIZE(L"rundll32.exe \"\",#1");
        command.resize(commandCapacity);
        if (swprintf_s(command.data(), command.size(),
                       L"rundll32.exe \"%ls\",#1",
                       wideDllName.data()) < 0) {
            error = ERROR_INSUFFICIENT_BUFFER;
        }
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

        if (error == NO_ERROR &&
            !createProcess(executable, command.data(), NULL, NULL, FALSE, flags,
                           NULL, NULL, &startupInfo.StartupInfo,
                           &processInformation)) {
            error = GetLastError();
        }
        else if (error == NO_ERROR &&
                 !DetourCopyPayloadToProcess(
                     processInformation.hProcess, DETOUR_EXE_HELPER_GUID,
                     helper, helper->cb)) {
            error = GetLastError();
            TerminateProcess(processInformation.hProcess, error);
            CloseHandle(processInformation.hProcess);
            CloseHandle(processInformation.hThread);
        }
        else if (error == NO_ERROR) {
            result = FinishHelperProcess(processInformation);
            error = GetLastError();
        }
    }

    DeleteMachineAttributeList(attributes);
    delete[] reinterpret_cast<PBYTE>(helper);
    SetLastError(result ? NO_ERROR : error);
    return result;
}

extern "C" BOOL WINAPI DetourCreateProcessWithDllExA(_In_opt_ LPCSTR lpApplicationName,
                                          _Inout_opt_ LPSTR lpCommandLine,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                          _In_ BOOL bInheritHandles,
                                          _In_ DWORD dwCreationFlags,
                                          _In_opt_ LPVOID lpEnvironment,
                                          _In_opt_ LPCSTR lpCurrentDirectory,
                                          _In_ LPSTARTUPINFOA lpStartupInfo,
                                          _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                          _In_ LPCSTR lpDllName,
                                          _In_ const GUID* payloadGuid,
                                          _In_reads_bytes_(payloadSize) LPCVOID payloadData,
                                          _In_ DWORD payloadSize,
                                          _In_opt_ PDETOUR_CREATE_PROCESS_ROUTINEA pfCreateProcessA)
{
    if (payloadGuid == NULL || payloadData == NULL || payloadSize == 0 ||
        payloadSize > MAXDWORD - sizeof(DETOUR_PAYLOAD_HEADER)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (pfCreateProcessA == NULL) {
        pfCreateProcessA = CreateProcessA;
    }

    if (!pfCreateProcessA(lpApplicationName,
                          lpCommandLine,
                          lpProcessAttributes,
                          lpThreadAttributes,
                          bInheritHandles,
                          dwCreationFlags | CREATE_SUSPENDED,
                          lpEnvironment,
                          lpCurrentDirectory,
                          lpStartupInfo,
                          lpProcessInformation)) {
        return FALSE;
    }

    WORD processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    WORD nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL injected = UpdateProcessWithDll(
        lpProcessInformation->hProcess, lpDllName,
        processMachine, nativeMachine);
    DWORD error = injected ? NO_ERROR : GetLastError();
    if (!injected && error == ERROR_EXE_MACHINE_TYPE_MISMATCH &&
        processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
        injected = DetourProcessViaHelperA(
            lpProcessInformation->dwProcessId, lpDllName,
            processMachine, nativeMachine, pfCreateProcessA);
        error = injected ? NO_ERROR : GetLastError();
    }

    if (injected && !DetourCopyPayloadToProcess(
            lpProcessInformation->hProcess, *payloadGuid,
            payloadData, payloadSize)) {
        injected = FALSE;
        error = GetLastError();
    }

    if (!injected) {
        TerminateProcess(lpProcessInformation->hProcess, ~0u);
        CloseHandle(lpProcessInformation->hProcess);
        CloseHandle(lpProcessInformation->hThread);
        ZeroMemory(lpProcessInformation, sizeof(*lpProcessInformation));
        SetLastError(error == NO_ERROR ? ERROR_DLL_INIT_FAILED : error);
        return FALSE;
    }

    if (!(dwCreationFlags & CREATE_SUSPENDED)) {
        if (ResumeThread(lpProcessInformation->hThread) == MAXDWORD) {
            error = GetLastError();
            TerminateProcess(lpProcessInformation->hProcess, ~0u);
            CloseHandle(lpProcessInformation->hProcess);
            CloseHandle(lpProcessInformation->hThread);
            ZeroMemory(lpProcessInformation, sizeof(*lpProcessInformation));
            SetLastError(error);
            return FALSE;
        }
    }

    return TRUE;
}

extern "C" BOOL WINAPI DetourCreateProcessWithDllExW(_In_opt_ LPCWSTR lpApplicationName,
                                          _Inout_opt_  LPWSTR lpCommandLine,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                          _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                          _In_ BOOL bInheritHandles,
                                          _In_ DWORD dwCreationFlags,
                                          _In_opt_ LPVOID lpEnvironment,
                                          _In_opt_ LPCWSTR lpCurrentDirectory,
                                          _In_ LPSTARTUPINFOW lpStartupInfo,
                                          _Out_ LPPROCESS_INFORMATION lpProcessInformation,
                                          _In_ LPCSTR lpDllName,
                                          _In_ const GUID* payloadGuid,
                                          _In_reads_bytes_(payloadSize) LPCVOID payloadData,
                                          _In_ DWORD payloadSize,
                                          _In_opt_ PDETOUR_CREATE_PROCESS_ROUTINEW pfCreateProcessW)
{
    if (payloadGuid == NULL || payloadData == NULL || payloadSize == 0 ||
        payloadSize > MAXDWORD - sizeof(DETOUR_PAYLOAD_HEADER)) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    if (pfCreateProcessW == NULL) {
        pfCreateProcessW = CreateProcessW;
    }

    if (!pfCreateProcessW(lpApplicationName,
                          lpCommandLine,
                          lpProcessAttributes,
                          lpThreadAttributes,
                          bInheritHandles,
                          dwCreationFlags | CREATE_SUSPENDED,
                          lpEnvironment,
                          lpCurrentDirectory,
                          lpStartupInfo,
                          lpProcessInformation)) {
        return FALSE;
    }

    WORD processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    WORD nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    BOOL injected = UpdateProcessWithDll(
        lpProcessInformation->hProcess, lpDllName,
        processMachine, nativeMachine);
    DWORD error = injected ? NO_ERROR : GetLastError();
    if (!injected && error == ERROR_EXE_MACHINE_TYPE_MISMATCH &&
        processMachine != IMAGE_FILE_MACHINE_UNKNOWN) {
        injected = DetourProcessViaHelperW(
            lpProcessInformation->dwProcessId, lpDllName,
            processMachine, nativeMachine, pfCreateProcessW);
        error = injected ? NO_ERROR : GetLastError();
    }

    if (injected && !DetourCopyPayloadToProcess(
            lpProcessInformation->hProcess, *payloadGuid,
            payloadData, payloadSize)) {
        injected = FALSE;
        error = GetLastError();
    }

    if (!injected) {
        TerminateProcess(lpProcessInformation->hProcess, ~0u);
        CloseHandle(lpProcessInformation->hProcess);
        CloseHandle(lpProcessInformation->hThread);
        ZeroMemory(lpProcessInformation, sizeof(*lpProcessInformation));
        SetLastError(error == NO_ERROR ? ERROR_DLL_INIT_FAILED : error);
        return FALSE;
    }

    if (!(dwCreationFlags & CREATE_SUSPENDED)) {
        if (ResumeThread(lpProcessInformation->hThread) == MAXDWORD) {
            error = GetLastError();
            TerminateProcess(lpProcessInformation->hProcess, ~0u);
            CloseHandle(lpProcessInformation->hProcess);
            CloseHandle(lpProcessInformation->hThread);
            ZeroMemory(lpProcessInformation, sizeof(*lpProcessInformation));
            SetLastError(error);
            return FALSE;
        }
    }

    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.

