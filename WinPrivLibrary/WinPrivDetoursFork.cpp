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

The implementation lives in `WinPrivDetoursFork.cpp`. Its C++ transaction API
lives in `WinPrivDetoursFork.h`.

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

#include <winternl.h>
#include <algorithm>
#include <atomic>
#include <climits>
#include <cstddef>
#include <memory>
#include <new>
#include <ranges>
#include <span>
#include <utility>
#include <vector>

using DETOUR_TRAMPOLINE = _DETOUR_TRAMPOLINE;
using PDETOUR_TRAMPOLINE = DETOUR_TRAMPOLINE*;

struct DETOUR_ALIGN
{
    BYTE targetEnd;
    BYTE trampolineEnd;
};

static_assert(sizeof(DETOUR_ALIGN) == 2);

constexpr SIZE_T MM_ALLOCATION_GRANULARITY = 0x10000;
constexpr DWORD DETOUR_THREAD_ENUMERATION_RETRY_LIMIT = 64;

//////////////////////////////////////////////////////////////////////////////
// Instruction relocation

// Copy one instruction from pSrc to pDst, preserving relative targets.
// The return value points to the following source instruction; extra reports
// instruction growth or -1 when the instruction cannot be relocated.

//////////////////////////////////////////////////// X86 and X64 Disassembler.
//
//  Includes full support for all x86 chips prior to the Pentium III, and some newer stuff.
//
#if defined(_M_X64) || defined(_M_IX86)

class CDetourDis
{
  public:
    struct COPYENTRY;

    explicit CDetourDis(LONG& extra);

    PBYTE CopyInstruction(PBYTE pbDst, PBYTE pbSrc, const COPYENTRY* table = s_rceCopyTable);

  public:
    typedef PBYTE (CDetourDis::* COPYFUNC)(PBYTE pbDst, PBYTE pbSrc);

    // nFlagBits flags.
    enum {
        ADDRESS     = 0x1u,
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
        COPYFUNC    pfCopy = nullptr;       // Custom instruction handler.
    };

  protected:
// These macros define common uses of nFixedSize, nFixedSize16, nModOffset, nRelOffset, nFlagBits, pfCopy.
#define ENTRY_DataIgnored           0, 0, 0, 0, 0,
#define ENTRY_CopyBytes1            { 1, 1, 0, 0, 0 }
#ifdef _M_X64
#define ENTRY_CopyBytes1Address     { 9, 5, 0, 0, ADDRESS }
#else
#define ENTRY_CopyBytes1Address     { 5, 3, 0, 0, ADDRESS }
#endif
#define ENTRY_CopyBytes2            { 2, 2, 0, 0, 0 }
#define ENTRY_CopyBytes2Jump        { ENTRY_DataIgnored &CDetourDis::CopyBytesJump }
#define ENTRY_CopyBytes2CantJump    { 2, 2, 0, 1, 0 }
#define ENTRY_CopyBytes3            { 3, 3, 0, 0, 0 }
#define ENTRY_CopyBytes3Or5         { 5, 3, 0, 0, 0 }
#ifdef _M_X64
#define ENTRY_CopyBytes3Or5Rax      { 5, 3, 0, 0, RAX }
#define ENTRY_CopyBytes3Or5Target   { 5, 5, 0, 1, 0 }
#else
#define ENTRY_CopyBytes3Or5Rax      { 5, 3, 0, 0, 0 }
#define ENTRY_CopyBytes3Or5Target   { 5, 3, 0, 1, 0 }
#endif
#define ENTRY_CopyBytes4            { 4, 4, 0, 0, 0 }
#define ENTRY_CopyBytes5Or7         { 7, 5, 0, 0, 0 }
#define ENTRY_CopyBytes2Mod         { 2, 2, 1, 0, 0 }
#define ENTRY_CopyBytes2Mod1        { 3, 3, 1, 0, 0 }
#define ENTRY_CopyBytes2ModOperand  { 6, 4, 1, 0, 0 }
#define ENTRY_CopyBytes3Mod         { 3, 3, 2, 0, 0 } // SSE3 0F 38 opcode modrm
#define ENTRY_CopyBytes3Mod1        { 4, 4, 2, 0, 0 } // SSE3 0F 3A opcode modrm .. imm8
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
#define ENTRY_CopyBytesXop          { 5, 5, 4, 0, 0 } // 0x8F xop1 xop2 opcode modrm
#define ENTRY_CopyBytesXop1         { 6, 6, 4, 0, 0 } // 0x8F xop1 xop2 opcode modrm ... imm8
#define ENTRY_CopyBytesXop4         { 9, 9, 4, 0, 0 } // 0x8F xop1 xop2 opcode modrm ... imm32
#define ENTRY_Invalid               { ENTRY_DataIgnored }

    PBYTE CopyBytes(const COPYENTRY& entry, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyBytesPrefix(PBYTE pbDst, PBYTE pbSrc);
#ifdef _M_X64
    PBYTE CopyBytesRax(PBYTE pbDst, PBYTE pbSrc);
#endif
    PBYTE CopyBytesJump(PBYTE pbDst, PBYTE pbSrc);

    PBYTE Invalid(PBYTE pbSrc);

    void AdjustTarget(PBYTE pbDst, PBYTE pbSrc,
                      UINT cbTargetOffset, UINT cbTargetSize);

  protected:
    PBYTE Copy0F(PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy0F78(PBYTE pbDst, PBYTE pbSrc); // vmread, 66/extrq/ib/ib, F2/insertq/ib/ib
    PBYTE Copy66(PBYTE pbDst, PBYTE pbSrc);
    PBYTE Copy67(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF2(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF6(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyF7(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyC7(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVex2(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVex3(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyVexEvexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc, BYTE p);
    PBYTE CopyEvex(PBYTE pbDst, PBYTE pbSrc);
    PBYTE CopyXop(PBYTE pbDst, PBYTE pbSrc);
#ifdef _M_X64
    PBYTE CopyRex2(PBYTE pbDst, PBYTE pbSrc); // AMD64 only, Intel APX REX2
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

static PBYTE DetourCopyInstruction(PBYTE pDst, PBYTE pSrc, LONG& extra)
{
    CDetourDis oDetourDisasm(extra);
    return oDetourDisasm.CopyInstruction(pDst, pSrc);
}

/////////////////////////////////////////////////////////// Disassembler Code.
//
CDetourDis::CDetourDis(LONG& extra) :
    m_lExtra(extra)
{
    m_lExtra = 0;
}

PBYTE CDetourDis::CopyInstruction(PBYTE pbDst, PBYTE pbSrc, const COPYENTRY* table)
{
    // Figure out how big the instruction is, do the appropriate copy,
    // and relocate any relative target.
    //
    const COPYENTRY& entry = table[pbSrc[0]];
    return entry.pfCopy != nullptr
        ? (this->*entry.pfCopy)(pbDst, pbSrc)
        : CopyBytes(entry, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyBytes(const COPYENTRY& entry, PBYTE pbDst, PBYTE pbSrc)
{
    UINT nBytesFixed;

    UINT const nModOffset = entry.nModOffset;
    UINT const nFlagBits = entry.nFlagBits;
    UINT const nFixedSize = entry.nFixedSize;
    UINT const nFixedSize16 = entry.nFixedSize16;

    // A zero-sized entry without a custom handler marks an invalid opcode.
    if (nFixedSize == 0) {
        return Invalid(pbSrc);
    }

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
    UINT nRelOffset = entry.nRelOffset;
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
    return pbSrc + nBytes;
}

PBYTE CDetourDis::CopyBytesPrefix(PBYTE pbDst, PBYTE pbSrc)
{
    pbDst[0] = pbSrc[0];
    return CopyInstruction(pbDst + 1, pbSrc + 1);
}

#ifdef _M_X64
PBYTE CDetourDis::CopyBytesRax(PBYTE pbDst, PBYTE pbSrc)
{ // AMD64 only
    if (pbSrc[0] & 0x8) {
        m_bRaxOverride = true;
    }
    return CopyBytesPrefix(pbDst, pbSrc);
}
#endif

PBYTE CDetourDis::CopyBytesJump(PBYTE pbDst, PBYTE pbSrc)
{
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
            m_lExtra = -1;
        }
        break;
      case 2:
        *(UNALIGNED SHORT*&)pvTargetAddr = (SHORT)nNewOffset;
        if (nNewOffset < SHRT_MIN || nNewOffset > SHRT_MAX) {
            m_lExtra = -1;
        }
        break;
      case 4:
        *(UNALIGNED LONG*&)pvTargetAddr = (LONG)nNewOffset;
        if (nNewOffset < LONG_MIN || nNewOffset > LONG_MAX) {
            m_lExtra = -1;
        }
        break;
#if defined(_M_X64)
      case 8:
        *(UNALIGNED LONGLONG*&)pvTargetAddr = nNewOffset;
        break;
#endif
    }
}

PBYTE CDetourDis::Invalid(PBYTE pbSrc)
{
    m_lExtra = -1;
    return pbSrc + 1;
}

////////////////////////////////////////////////////// Individual Bytes Codes.
//
PBYTE CDetourDis::Copy0F(PBYTE pbDst, PBYTE pbSrc)
{
    pbDst[0] = pbSrc[0];
    return CopyInstruction(pbDst + 1, pbSrc + 1, s_rceCopyTable0F);
}

PBYTE CDetourDis::Copy0F78(PBYTE pbDst, PBYTE pbSrc)
{
    // vmread, 66/extrq, F2/insertq

    static const COPYENTRY vmread = /* 78 */ ENTRY_CopyBytes2Mod;
    static const COPYENTRY extrq_insertq = /* 78 */ ENTRY_CopyBytes4;


    // For insertq and presumably despite documentation extrq, mode must be 11, not checked.
    // insertq/extrq/78 are followed by two immediate bytes, and given mode == 11, mod/rm byte is always one byte,
    // and the 0x78 makes 4 bytes (not counting the 66/F2/F which are accounted for elsewhere)

    return CopyBytes(m_bF2 || m_bOperandOverride ? extrq_insertq : vmread, pbDst, pbSrc);
}

PBYTE CDetourDis::Copy66(PBYTE pbDst, PBYTE pbSrc)
{   // Operand-size override prefix
    m_bOperandOverride = true;
    return CopyBytesPrefix(pbDst, pbSrc);
}

PBYTE CDetourDis::Copy67(PBYTE pbDst, PBYTE pbSrc)
{   // Address size override prefix
    m_bAddressOverride = true;
    return CopyBytesPrefix(pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF2(PBYTE pbDst, PBYTE pbSrc)
{
    m_bF2 = true;
    return CopyBytesPrefix(pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF6(PBYTE pbDst, PBYTE pbSrc)
{
    // TEST BYTE /0 and /1 (both encodings are TEST per Intel SDM Vol 2A Group 3
    // and AMD APM Vol 3; /1 is an undocumented alias of /0 historically but is
    // now documented in both manuals).
    if (0x00 == (0x30 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 000 or 001
        static const COPYENTRY ce = /* f6 */ ENTRY_CopyBytes2Mod1;
        return CopyBytes(ce, pbDst, pbSrc);
    }
    // DIV /6
    // IDIV /7
    // IMUL /5
    // MUL /4
    // NEG /3
    // NOT /2

    static const COPYENTRY ce = /* f6 */ ENTRY_CopyBytes2Mod;
    return CopyBytes(ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyF7(PBYTE pbDst, PBYTE pbSrc)
{
    // TEST WORD /0 and /1 (see CopyF6 for /1 rationale).
    if (0x00 == (0x30 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 000 or 001
        static const COPYENTRY ce = /* f7 */ ENTRY_CopyBytes2ModOperand;
        return CopyBytes(ce, pbDst, pbSrc);
    }

    // DIV /6
    // IDIV /7
    // IMUL /5
    // MUL /4
    // NEG /3
    // NOT /2
    static const COPYENTRY ce = /* f7 */ ENTRY_CopyBytes2Mod;
    return CopyBytes(ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyC7(PBYTE pbDst, PBYTE pbSrc)
{
    // C7 /7 is XBEGIN rel32 (or rel16 with 66 prefix).
    // It has a relative displacement that must be relocated like CALL/JMP.
    if (0x38 == (0x38 & pbSrc[1])) {    // reg(bits 543) of ModR/M == 111
        static const COPYENTRY ce = /* c7 /7 */ { 6, 4, 0, 2, 0 };
        return CopyBytes(ce, pbDst, pbSrc);
    }
    // MOV /0 r/m, imm16/32
    static const COPYENTRY ce = /* c7 /0 */ ENTRY_CopyBytes2ModOperand;
    return CopyBytes(ce, pbDst, pbSrc);
}

PBYTE CDetourDis::CopyVexEvexCommon(BYTE m, PBYTE pbDst, PBYTE pbSrc, BYTE p)
// m is first instead of last in the hopes of pbDst/pbSrc being
// passed along efficiently in the registers they were already in.
{
    static const COPYENTRY ceF38 = /* 38 */ ENTRY_CopyBytes2Mod;
    static const COPYENTRY ceF3A = /* 3A */ ENTRY_CopyBytes2Mod1;

    switch (p & 3) {
    case 0:
    case 2: break;
    case 1: m_bOperandOverride = true; break;
    case 3: m_bF2 = true; break;
    }

    // see https://software.intel.com/content/www/us/en/develop/download/intel-avx512-fp16-architecture-specification.html
    // EVEX maps (with FP16 and APX mmm-bit extension):
    //   mmm=001 (MAP1) and mmm=101 (MAP5) share the legacy 0F opcode structure,
    //     so per-opcode sizing must come from s_rceCopyTable0F (e.g. MAP5 C2 /r ib = VCMPPH/VCMPSH).
    //   mmm=010 (MAP2) and mmm=110 (MAP6) share the legacy 0F 38 structure (ModR/M, no imm).
    //   mmm=011 (MAP3) has the 0F 3A structure (ModR/M + imm8).
    //   mmm=100 (MAP4, APX) mirrors legacy MAP0 opcode structure (per-opcode sizing).
    switch (m) {
    default: return Invalid(pbSrc);
    case 5:  // MAP5 (FP16) - opcode structure mirrors 0F (MAP1).
    case 1:  return CopyInstruction(pbDst, pbSrc, s_rceCopyTable0F);
    case 6:  // MAP6 (FP16) - opcode structure mirrors 0F 38 (MAP2).
    case 2:  return CopyBytes(ceF38, pbDst, pbSrc);
    case 3:  return CopyBytes(ceF3A, pbDst, pbSrc);
    case 4:  // MAP4 (APX) - promoted legacy MAP0 instructions.
             return CopyInstruction(pbDst, pbSrc);
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

PBYTE CDetourDis::CopyVex3(PBYTE pbDst, PBYTE pbSrc)
// 3 byte VEX prefix 0xC4
{
#ifdef _M_IX86
    const static COPYENTRY ceLES = /* C4 */ ENTRY_CopyBytes2Mod;
    if ((pbSrc[1] & 0xC0) != 0xC0) {
        return CopyBytes(ceLES, pbDst, pbSrc);
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

PBYTE CDetourDis::CopyVex2(PBYTE pbDst, PBYTE pbSrc)
// 2 byte VEX prefix 0xC5
{
#ifdef _M_IX86
    const static COPYENTRY ceLDS = /* C5 */ ENTRY_CopyBytes2Mod;
    if ((pbSrc[1] & 0xC0) != 0xC0) {
        return CopyBytes(ceLDS, pbDst, pbSrc);
    }
#endif
    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];
    return CopyVexCommon(1, pbDst + 2, pbSrc + 2);
}

PBYTE CDetourDis::CopyEvex(PBYTE pbDst, PBYTE pbSrc)
// 62, 3 byte payload, x86 with implied prefixes like Vex
// for 32bit, mode 0xC0 else fallback to bound /r
{
    // NOTE: Intel and Wikipedia number these differently.
    // Intel says 0-2, Wikipedia says 1-3.

    BYTE const p0 = pbSrc[1];

#ifdef _M_IX86
    const static COPYENTRY ceBound = /* 62 */ ENTRY_CopyBytes2Mod;
    if ((p0 & 0xC0) != 0xC0) {
        return CopyBytes(ceBound, pbDst, pbSrc);
    }
#endif

    BYTE const p1 = pbSrc[2];

    if ((p1 & 0x04) != 0x04)
        return Invalid(pbSrc);

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
    return CopyVexEvexCommon(p0 & 7u, pbDst + 4, pbSrc + 4, p1 & 3u);
}

PBYTE CDetourDis::CopyXop(PBYTE pbDst, PBYTE pbSrc)
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
        return CopyBytes(cePop, pbDst, pbSrc);

    case 8: // modrm with 8bit immediate
        return CopyBytes(ceXop1, pbDst, pbSrc);

    case 9: // modrm with no immediate
        return CopyBytes(ceXop, pbDst, pbSrc);

    case 10: // modrm with 32bit immediate
        return CopyBytes(ceXop4, pbDst, pbSrc);
    }
}

#ifdef _M_X64
PBYTE CDetourDis::CopyRex2(PBYTE pbDst, PBYTE pbSrc)
// Intel APX REX2 prefix 0xD5 (64-bit mode only)
// Byte 0: D5
// Byte 1: M(7) R4(6) X4(5) B4(4) W(3) R3(2) X3(1) B3(0)
//   M: 0 = opcode from MAP0, 1 = opcode from MAP1 (no 0F escape needed)
//   W: operand size override to 64-bit (same as REX.W)
{
    BYTE const payload = pbSrc[1];

    if (payload & 0x08) { // W bit (bit 3)
        m_bRaxOverride = true;
    }

    pbDst[0] = pbSrc[0];
    pbDst[1] = pbSrc[1];

    const COPYENTRY* table = payload & 0x80 ? s_rceCopyTable0F : s_rceCopyTable;
    return CopyInstruction(pbDst + 2, pbSrc + 2, table);
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
    static PBYTE CopyInstruction(PBYTE pDst, PBYTE pSrc, LONG& extra);

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
    static BYTE CopyB_or_Bl(BYTE* pSource, BYTE* pDest, ULONG instruction);
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
                                  LONG& extra)
{
    DWORD Instruction = GetInstruction(pSrc);

    ULONG CopiedSize;
    if ((Instruction & 0x1f000000) == 0x10000000) {
        CopiedSize = CopyAdr(pSrc, pDst, Instruction);
    } else if ((Instruction & 0xff000010) == 0x54000000) {
        CopiedSize = CopyBcc(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7c000000) == 0x14000000) {
        CopiedSize = CopyB_or_Bl(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7e000000) == 0x34000000) {
        CopiedSize = CopyCbz(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x7e000000) == 0x36000000) {
        CopiedSize = CopyTbz(pSrc, pDst, Instruction);
    } else if ((Instruction & 0x3b000000) == 0x18000000) {
        CopiedSize = CopyLdrLiteral(pSrc, pDst, Instruction);
    } else {
        CopiedSize = PureCopy32(pSrc, pDst);
    }

    extra = CopiedSize - sizeof(DWORD);

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

BYTE CDetourDis::CopyB_or_Bl(BYTE* pSource, BYTE* pDest, ULONG instruction)
{
    Branch26& decoded = (Branch26&)(instruction);
    PULONG pDstInst = (PULONG)(pDest);

    BYTE* pTarget = pSource + decoded.Imm();
    LONG64 delta = pTarget - pDest;

    // output as B or BRL
    if (delta >= -(1 << 27) && (delta < (1 << 27)))
    {
        EmitInstruction(pDstInst, Branch26::Assemble(decoded.s.Link, (LONG)delta));
    }

    // output as MOV x17, Target; BR or BRL x17 (BIG assumption that x17 isn't being used for anything!!)
    else
    {
        EmitMovImmediate(pDstInst, 17, (ULONG_PTR)pTarget);
        EmitInstruction(pDstInst, Br::Assemble(17, decoded.s.Link != 0));
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

static PBYTE DetourCopyInstruction(PBYTE pDst, PBYTE pSrc, LONG& extra)
{
    return CDetourDis::CopyInstruction(pDst, pSrc, extra);
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

#if defined(_M_IX86) || defined(_M_X64)

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xE9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
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

#endif

///////////////////////////////////////////////////////////////////////// X86.
//
#ifdef _M_IX86

struct _DETOUR_TRAMPOLINE
{
    BYTE            rbCode[30];     // target code + jmp to pbRemain
    BYTE            cbRestore;      // size of original target code.
    BYTE            alignCount;     // populated instruction alignment entries.
    DETOUR_ALIGN    rAlign[8];      // target/trampoline instruction boundaries.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 56);

enum {
    SIZE_OF_JMP = 5,
    SIZE_OF_TRAMPOLINE_JMP = 5
};

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

#endif // _M_IX86

///////////////////////////////////////////////////////////////////////// X64.
//
#ifdef _M_X64

struct _DETOUR_TRAMPOLINE
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    BYTE            rbCode[30];     // target code + jmp to pbRemain.
    BYTE            cbRestore;      // size of original target code.
    BYTE            alignCount;     // populated instruction alignment entries.
    DETOUR_ALIGN    rAlign[8];      // target/trampoline instruction boundaries.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
    BYTE            rbCodeIn[8];    // jmp [pbDetour]
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 72);

enum {
    SIZE_OF_JMP = 5,
    SIZE_OF_TRAMPOLINE_JMP = 6
};

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
    // The number is rounded up to 128.
    //
    BYTE            rbCode[128];    // target code + jmp to pbRemain
    BYTE            cbRestore;      // size of original target code.
    BYTE            alignCount;     // populated instruction alignment entries.
    DETOUR_ALIGN    rAlign[8];      // target/trampoline instruction boundaries.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 168);

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

inline std::pair<PBYTE, PBYTE> detour_find_jmp_bounds(PBYTE pbCode)
{
    // Keep trampolines within +/- 2GB of code, including on ARM64 where indirect jumps allow +/- 4GB.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);

#if defined(_M_IX86) || defined(_M_X64)
    // Also keep relocated jumps within range of their original targets or vectors.
    PBYTE pbNew = pbCode;
#ifdef _M_X64
    if (pbCode[0] == 0xff && pbCode[1] == 0x25) {   // jmp [+imm32]
        pbNew = pbCode + 6 + *(UNALIGNED INT32 *)&pbCode[2];
    }
    else
#endif
    if (pbCode[0] == 0xe9) {   // jmp +imm32
        pbNew = pbCode + 5 + *(UNALIGNED INT32 *)&pbCode[1];
    }

    if (pbNew < pbCode) {
        hi = detour_2gb_above((ULONG_PTR)pbNew);
    }
    else {
        lo = detour_2gb_below((ULONG_PTR)pbNew);
    }
#endif

    return { (PBYTE)lo, (PBYTE)hi };
}

//////////////////////////////////////////////// Trampoline Memory Management.
//
struct DETOUR_REGION
{
    DETOUR_REGION *     pNext;  // Next region in list of regions.
    DETOUR_TRAMPOLINE * pFree;  // List of free trampolines in this region.
};
typedef DETOUR_REGION * PDETOUR_REGION;

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

static PVOID detour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi, LONG& error)
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
                error = ERROR_DYNAMIC_CODE_BLOCKED;
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

static PVOID detour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi, LONG& error)
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
                error = ERROR_DYNAMIC_CODE_BLOCKED;
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
                                                  PBYTE pLo,
                                                  PBYTE pHi,
                                                  LONG& error)
{
    PVOID pbTry = NULL;

    // NB: We must always also start the search at an offset from pbTarget
    //     in order to maintain ASLR entropy.

#if defined(_WIN64)
    // Try looking 1GB below or lower.
    if (pbTry == NULL && error != ERROR_DYNAMIC_CODE_BLOCKED && pbTarget > (PBYTE)0x40000000) {
        pbTry = detour_alloc_region_from_hi(pLo, pbTarget - 0x40000000, error);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && error != ERROR_DYNAMIC_CODE_BLOCKED && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, pHi, error);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && error != ERROR_DYNAMIC_CODE_BLOCKED && pbTarget > (PBYTE)0x40000000) {
        pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget, error);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && error != ERROR_DYNAMIC_CODE_BLOCKED && pbTarget < (PBYTE)0xffffffff40000000) {
        pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000, error);
    }
#endif

    // Try anything below.
    if (pbTry == NULL && error != ERROR_DYNAMIC_CODE_BLOCKED) {
        pbTry = detour_alloc_region_from_hi(pLo, pbTarget, error);
    }
    // try anything above.
    if (pbTry == NULL && error != ERROR_DYNAMIC_CODE_BLOCKED) {
        pbTry = detour_alloc_region_from_lo(pbTarget, pHi, error);
    }

    return pbTry;
}

static PDETOUR_TRAMPOLINE detour_alloc_trampoline(PBYTE pbTarget, LONG& error)
{
    error = ERROR_NOT_ENOUGH_MEMORY;

    const auto [pLo, pHi] = detour_find_jmp_bounds(pbTarget);
    const auto usable = [=](const DETOUR_REGION* region) {
        return region != NULL && region->pFree != NULL &&
            (PBYTE)region->pFree >= pLo && (PBYTE)region->pFree <= pHi;
    };

    // Prefer the cached region, then search existing regions for a valid free block.
    if (!usable(s_pRegion)) {
        s_pRegion = s_pRegions;
        while (s_pRegion != NULL && !usable(s_pRegion)) {
            s_pRegion = s_pRegion->pNext;
        }
    }

    // Allocate a region when every existing region is full or outside the jump bounds.
    if (s_pRegion == NULL) {
        // Round pbTarget down to 64KB block.
        // /RTCc RuntimeChecks breaks PtrToUlong.
        pbTarget = detour_alloc_round_down_to_region(pbTarget);
        s_pRegion = (DETOUR_REGION*)detour_alloc_trampoline_allocate_new(pbTarget, pLo, pHi, error);
        if (s_pRegion == NULL) {
            return NULL;
        }
        s_pRegion->pFree = NULL;
        s_pRegion->pNext = s_pRegions;
        s_pRegions = s_pRegion;

        // Put everything but the first trampoline on the free list.
        auto trampolines = ((PDETOUR_TRAMPOLINE)s_pRegion) + 1;
        for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--) {
            trampolines[i].pbRemain = (PBYTE)s_pRegion->pFree;
            s_pRegion->pFree = &trampolines[i];
        }
    }

    // Validate newly allocated regions before consuming their first free block.
    if (!usable(s_pRegion)) {
        return NULL;
    }
    auto pTrampoline = s_pRegion->pFree;
    s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pTrampoline->pbRemain;
    return pTrampoline;
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

static std::atomic_flag s_transactionActive;

#pragma warning(push)
#pragma warning(disable:4324)
struct DetourSuspendedThread
{
    DWORD threadId;
    HANDLE handle;
    CONTEXT originalContext;
    PBYTE relocatedInstructionPointer;
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

using DetourSuspendedThreads = std::vector<
    DetourSuspendedThread, DetourVirtualAllocator<DetourSuspendedThread>>;

static void detour_resume_and_close_threads(
    DetourSuspendedThreads& threads)
{
    // Every recorded thread has a valid handle and remains suspended until this cleanup.
    for (auto& thread : threads) {
        ResumeThread(thread.handle);
    }

    for (auto& thread : threads) {
        CloseHandle(thread.handle);
    }
    threads.clear();
}

static LONG detour_suspend_other_threads(
    DetourSuspendedThreads& threads)
{
    static const auto querySystemInformation = reinterpret_cast<decltype(&NtQuerySystemInformation)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    static const auto statusToError = reinterpret_cast<decltype(&RtlNtStatusToDosError)>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
    if (querySystemInformation == NULL || statusToError == NULL) {
        return ERROR_PROC_NOT_FOUND;
    }

    const DWORD processId = GetCurrentProcessId();
    const DWORD currentThreadId = GetCurrentThreadId();
    DWORD transientRetries = 0;
    std::vector<BYTE, DetourVirtualAllocator<BYTE>> snapshot;
    const auto fail = [&threads](LONG error) { detour_resume_and_close_threads(threads); return error; };

    // Suspend newly discovered threads immediately, then enumerate again. Once
    // an enumeration finds no new thread, every peer that could create another
    // peer is suspended. The VirtualAlloc-backed vector avoids taking the
    // process heap lock after a thread that owns that lock has been suspended.
    for (;;) {
        bool discoveredThread = false;
        bool retryEnumeration = false;
        LONG retryError = ERROR_RETRY;

        // Capture thread IDs in bulk without per-thread Toolhelp calls or heap allocation.
        constexpr NTSTATUS lengthMismatch = static_cast<NTSTATUS>(0xC0000004UL);
        ULONG snapshotBytes = 0;
        NTSTATUS status = lengthMismatch;
        SIZE_T requiredBytes = MM_ALLOCATION_GRANULARITY;
        DWORD sizeRetries = 0;
        while (status == lengthMismatch) {
            if (requiredBytes > snapshot.size()) {
                try { snapshot.resize(requiredBytes); }
                catch (...) { return fail(ERROR_NOT_ENOUGH_MEMORY); }
            }
            status = querySystemInformation(SystemProcessInformation, snapshot.data(),
                static_cast<ULONG>(snapshot.size()), &snapshotBytes);
            if (status == lengthMismatch) {
                if (++sizeRetries > DETOUR_THREAD_ENUMERATION_RETRY_LIMIT ||
                    snapshot.size() > MAXDWORD / 2 || snapshotBytes > MAXDWORD - MM_ALLOCATION_GRANULARITY) {
                    return fail(ERROR_NOT_ENOUGH_MEMORY);
                }
                requiredBytes = std::max<SIZE_T>(snapshot.size() * 2,
                    static_cast<SIZE_T>(snapshotBytes) + MM_ALLOCATION_GRANULARITY);
            }
        }
        if (status < 0) {
            return fail(static_cast<LONG>(statusToError(status)));
        }
        if (snapshotBytes < sizeof(SYSTEM_PROCESS_INFORMATION) || snapshotBytes > snapshot.size()) {
            return fail(ERROR_BAD_LENGTH);
        }

        // Walk process records, then inspect only this process's thread array.
        const SYSTEM_PROCESS_INFORMATION* process = NULL;
        SIZE_T processOffset = 0;
        for (;;) {
            const SIZE_T remaining = snapshotBytes - processOffset;
            if (remaining < sizeof(SYSTEM_PROCESS_INFORMATION)) {
                return fail(ERROR_BAD_LENGTH);
            }
            process = reinterpret_cast<const SYSTEM_PROCESS_INFORMATION*>(snapshot.data() + processOffset);
            const SIZE_T recordBytes = process->NextEntryOffset != 0 ? process->NextEntryOffset : remaining;
            if (recordBytes < sizeof(*process) || recordBytes > remaining) {
                return fail(ERROR_BAD_LENGTH);
            }
            if (reinterpret_cast<ULONG_PTR>(process->UniqueProcessId) == processId) {
                if (process->NumberOfThreads > (recordBytes - sizeof(*process)) / sizeof(SYSTEM_THREAD_INFORMATION)) {
                    return fail(ERROR_BAD_LENGTH);
                }
                break;
            }
            if (process->NextEntryOffset == 0) {
                return fail(ERROR_NOT_FOUND);
            }
            processOffset += process->NextEntryOffset;
        }

        const auto entries = reinterpret_cast<const SYSTEM_THREAD_INFORMATION*>(process + 1);
        for (ULONG i = 0; i < process->NumberOfThreads; ++i) {
            const DWORD threadId = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(entries[i].ClientId.UniqueThread));
            if (threadId == currentThreadId ||
                std::ranges::contains(threads, threadId, &DetourSuspendedThread::threadId)) {
                continue;
            }

            try { threads.reserve(threads.size() + 1); }
            catch (...) { return fail(ERROR_NOT_ENOUGH_MEMORY); }

            // Retry paths resume peers before closing this handle; close hooks can acquire their locks.
            constexpr DWORD access = SYNCHRONIZE | THREAD_QUERY_INFORMATION |
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT;
            std::unique_ptr<void, decltype(&CloseHandle)> thread(OpenThread(access, FALSE, threadId), CloseHandle);
            if (!thread) {
                const LONG error = GetLastError();
                if (error != ERROR_INVALID_PARAMETER) {
                    return fail(error);
                }
                retryEnumeration = true;
                retryError = error;
                continue;
            }

            // A thread ID from the snapshot can be reused before
            // OpenThread runs. Never suspend a recycled foreign ID.
            const DWORD openedProcessId = GetProcessIdOfThread(thread.get());
            if (openedProcessId != processId) {
                if (openedProcessId == 0) {
                    const LONG error = GetLastError();
                    if (WaitForSingleObject(thread.get(), 0) != WAIT_OBJECT_0 && error != ERROR_INVALID_PARAMETER) {
                        return fail(error);
                    }
                    retryError = error;
                }
                retryEnumeration = true;
                detour_resume_and_close_threads(threads);
                continue;
            }
            // Terminating peers can reject suspension before their handles become signaled.
            if (SuspendThread(thread.get()) == MAXDWORD) {
                const LONG error = GetLastError();
                if (WaitForSingleObject(thread.get(), 0) != WAIT_OBJECT_0 &&
                    error != ERROR_INVALID_PARAMETER && error != ERROR_ACCESS_DENIED) {
                    return fail(error);
                }
                retryEnumeration = true;
                retryError = error;
                detour_resume_and_close_threads(threads);
                continue;
            }

            DetourSuspendedThread candidate{
                .threadId = threadId,
                .handle = thread.get(),
                .originalContext = {},
                .relocatedInstructionPointer = NULL,
            };
#if defined(_M_IX86)
            candidate.originalContext.ContextFlags = CONTEXT_CONTROL;
#elif defined(_M_X64) || defined(_M_ARM64)
            candidate.originalContext.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
#endif
            if (!GetThreadContext(thread.get(), &candidate.originalContext)) {
                const LONG error = GetLastError();
                const DWORD wait = WaitForSingleObject(thread.get(), 0);
                if (wait != WAIT_OBJECT_0) {
                    ResumeThread(thread.get());
                }
                if (wait != WAIT_OBJECT_0 && error != ERROR_INVALID_PARAMETER && error != ERROR_ACCESS_DENIED) {
                    return fail(error);
                }
                retryEnumeration = true;
                retryError = error;
                detour_resume_and_close_threads(threads);
                continue;
            }
            threads.push_back(candidate);
            (void)thread.release();
            discoveredThread = true;
        }

        if (retryEnumeration) {
            if (++transientRetries > DETOUR_THREAD_ENUMERATION_RETRY_LIMIT) {
                return fail(retryError);
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

static auto& detour_context_instruction_pointer(CONTEXT& context)
{
#if defined(_M_IX86)
    return context.Eip;
#elif defined(_M_X64)
    return context.Rip;
#elif defined(_M_ARM64)
    return context.Pc;
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

static LONG detour_relocate_suspended_threads(
    DetourSuspendedThreads& threads, const auto& operations)
{
    for (auto& thread : threads) {
        const ULONG_PTR instructionPointer =
            detour_context_instruction_pointer(thread.originalContext);
        PBYTE relocated = NULL;

        for (const auto& operation : std::views::reverse(operations)) {
            const auto targetBegin = reinterpret_cast<ULONG_PTR>(operation.pbTarget);
            const auto targetEnd = targetBegin + operation.pTrampoline->cbRestore;
            if (instructionPointer >= targetBegin &&
                instructionPointer < targetEnd) {

                relocated = detour_align_target_to_trampoline(
                    operation.pTrampoline,
                    static_cast<BYTE>(instructionPointer - targetBegin));
                break;
            }
        }

        if (relocated != NULL &&
            reinterpret_cast<ULONG_PTR>(relocated) != instructionPointer) {
            thread.relocatedInstructionPointer = relocated;
        }
    }

    // Verify context writes are permitted before changing any instruction pointer.
    for (auto& thread : threads) {
        if (thread.relocatedInstructionPointer != NULL &&
            !SetThreadContext(thread.handle, &thread.originalContext)) {
            return GetLastError();
        }
    }

    for (SIZE_T threadIndex = 0; threadIndex < threads.size(); ++threadIndex) {
        auto& thread = threads[threadIndex];
        if (thread.relocatedInstructionPointer == NULL) {
            continue;
        }
        CONTEXT relocatedContext = thread.originalContext;
        detour_context_instruction_pointer(relocatedContext) =
            reinterpret_cast<ULONG_PTR>(thread.relocatedInstructionPointer);
        if (!SetThreadContext(thread.handle, &relocatedContext)) {
            const LONG error = GetLastError();
            for (SIZE_T i = 0; i < threadIndex; ++i) {
                auto& prior = threads[i];
                if (prior.relocatedInstructionPointer != NULL) {
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

winpriv::detours::transaction::transaction() noexcept :
    error_(dynamicCode_.Result())
{
    // One transaction owns the writable trampoline regions until completion or abort.
    if (error_ != NO_ERROR) return;
    if (s_transactionActive.test_and_set()) {
        error_ = ERROR_INVALID_OPERATION;
        dynamicCode_.Restore();
        return;
    }

    active_ = true;
    error_ = detour_writable_trampoline_regions();
    if (error_ != NO_ERROR) {
        abort();
    }
}

winpriv::detours::transaction::~transaction()
{
    abort();
}

void winpriv::detours::transaction::abort() noexcept
{
    if (!active_) return;

    // Return unpublished trampolines and restore every staged target's protection.
    for (auto& o : std::views::reverse(std::span(operations_.data(), operationCount_))) {
        DWORD dwOld;
        VirtualProtect(o.pbTarget, o.pTrampoline->cbRestore, o.dwPerm, &dwOld);
        detour_free_trampoline(o.pTrampoline);
    }
    operationCount_ = 0;

    detour_runnable_trampoline_regions();
    dynamicCode_.Restore();
    active_ = false;
    s_transactionActive.clear();
}

LONG winpriv::detours::transaction::commit() noexcept
{
    if (!active_) return error_;

    // Prepare every peer's instruction pointer before publishing any hook.
    DetourSuspendedThreads suspendedThreads;
    const auto operations = std::span(operations_.data(), operationCount_);
    if (error_ == NO_ERROR && !operations.empty()) {
        error_ = detour_suspend_other_threads(suspendedThreads);
        if (error_ == NO_ERROR) {
            error_ = detour_relocate_suspended_threads(suspendedThreads, operations);
        }
    }
    if (error_ != NO_ERROR) {
        detour_resume_and_close_threads(suspendedThreads);
        abort();
        return error_;
    }

    // Publish hooks and the original-function pointers while peers remain suspended.
    for (auto& o : std::views::reverse(operations)) {
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

    // Restore executable protections and flush generated code before resuming peers.
    HANDLE hProcess = GetCurrentProcess();
    for (auto& o : std::views::reverse(operations)) {
        DWORD dwOld;
        VirtualProtect(o.pbTarget, o.pTrampoline->cbRestore, o.dwPerm, &dwOld);
        FlushInstructionCache(hProcess, o.pbTarget, o.pTrampoline->cbRestore);
    }
    detour_runnable_trampoline_regions();
    detour_resume_and_close_threads(suspendedThreads);
    operationCount_ = 0;
    dynamicCode_.Restore();
    active_ = false;
    s_transactionActive.clear();
    return error_;
}

///////////////////////////////////////////////////////////// Transacted APIs.
//
LONG winpriv::detours::transaction::stage(PVOID* ppPointer, PVOID pDetour) noexcept
{
    if (pDetour == NULL) {
        return ERROR_INVALID_PARAMETER;
    }
    if (*ppPointer == NULL) {
        return ERROR_INVALID_HANDLE;
    }

    PBYTE pbTarget = detour_skip_jmp((PBYTE)*ppPointer);
    pDetour = detour_skip_jmp((PBYTE)pDetour);

    if (pDetour == (PVOID)pbTarget) {
        return NO_ERROR;
    }

    if (operationCount_ == operations_.size()) {
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    LONG allocationError = NO_ERROR;
    PDETOUR_TRAMPOLINE pTrampoline = detour_alloc_trampoline(pbTarget, allocationError);
    if (pTrampoline == NULL) {
        return allocationError;
    }

    const auto fail = [&](LONG error) {
        detour_free_trampoline(pTrampoline);
        return error;
    };

    PBYTE pbSrc = pbTarget;
    PBYTE pbTrampoline = pTrampoline->rbCode;
    PBYTE pbPool = pbTrampoline + sizeof(pTrampoline->rbCode);
    ULONG cbTarget = 0;

    pTrampoline->cbRestore = 0;
    pTrampoline->alignCount = 0;
    ZeroMemory(pTrampoline->rAlign, sizeof(pTrampoline->rAlign));

    while (cbTarget < SIZE_OF_JMP) {
        if (pTrampoline->alignCount == ARRAYSIZE(pTrampoline->rAlign)) {
            return fail(ERROR_INVALID_BLOCK);
        }

        PBYTE pbOp = pbSrc;
        LONG lExtra = 0;

        pbSrc = DetourCopyInstruction(pbTrampoline, pbSrc, lExtra);
        if (lExtra < 0) {
            return fail(ERROR_INVALID_BLOCK);
        }
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
        cbTarget > MAXBYTE) {
        return fail(ERROR_INVALID_BLOCK);
    }

    if (pbTrampoline > pbPool ||
        pbPool - pbTrampoline < SIZE_OF_TRAMPOLINE_JMP) {
        return fail(ERROR_INVALID_BLOCK);
    }

    pTrampoline->cbRestore = (BYTE)cbTarget;

    pTrampoline->pbRemain = pbTarget + cbTarget;
    pTrampoline->pbDetour = (PBYTE)pDetour;

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

    DWORD dwOld = 0;
    if (!VirtualProtect(pbTarget, cbTarget, PAGE_EXECUTE_READWRITE, &dwOld)) {
        return fail(GetLastError());
    }

    operations_[operationCount_++] = {
        .ppbPointer = ppPointer,
        .pbTarget = pbTarget,
        .pTrampoline = pTrampoline,
        .dwPerm = dwOld,
    };

    return NO_ERROR;
}
