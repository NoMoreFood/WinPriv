//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivLibrary.h"
#include <algorithm>
#include <cerrno>
#include <limits>

static LONGLONG iMockTimeOffset = 0;
static auto TrueNtQuerySystemTime = LoadNtFunction<NTSTATUS(NTAPI*)(PLARGE_INTEGER)>("NtQuerySystemTime");
static auto TrueRtlGetSystemTimePrecise = LoadNtFunction<LONGLONG(NTAPI*)()>("RtlGetSystemTimePrecise");
static auto TrueNtQuerySystemInformation = &NtQuerySystemInformation;
static auto TrueGetSystemTimeAsFileTime = &GetSystemTimeAsFileTime;
static auto TrueGetSystemTimePreciseAsFileTime = &GetSystemTimePreciseAsFileTime;
static auto TrueGetSystemTime = &GetSystemTime;
static auto TrueGetLocalTime = &GetLocalTime;
static auto TrueGetDateFormatA = &GetDateFormatA;
static auto TrueGetDateFormatW = &GetDateFormatW;
static auto TrueGetDateFormatEx = &GetDateFormatEx;
static auto TrueGetTimeFormatA = &GetTimeFormatA;
static auto TrueGetTimeFormatW = &GetTimeFormatW;
static auto TrueGetTimeFormatEx = &GetTimeFormatEx;
static decltype(TrueGetSystemTimeAsFileTime) TrueBaseGetSystemTimeAsFileTime = nullptr;
static decltype(TrueGetSystemTimePreciseAsFileTime) TrueBaseGetSystemTimePreciseAsFileTime = nullptr;
static decltype(TrueGetSystemTime) TrueBaseGetSystemTime = nullptr;
static decltype(TrueGetLocalTime) TrueBaseGetLocalTime = nullptr;

static LONGLONG ShiftMockTime(LONGLONG iTime)
{
	// Saturate extreme dates instead of allowing a signed clock value to overflow.
	constexpr LONGLONG iMaxTime = (std::numeric_limits<LONGLONG>::max)();
	return std::clamp(iTime, -(std::min)(iMockTimeOffset, 0LL), iMaxTime - (std::max)(iMockTimeOffset, 0LL)) +
		iMockTimeOffset;
}

static NTSTATUS NTAPI DetourNtQuerySystemTime(PLARGE_INTEGER pTime)
{
	const NTSTATUS iStatus = TrueNtQuerySystemTime(pTime);
	if (iStatus >= 0) pTime->QuadPart = ShiftMockTime(pTime->QuadPart);
	return iStatus;
}

static LONGLONG NTAPI DetourRtlGetSystemTimePrecise()
{
	return ShiftMockTime(TrueRtlGetSystemTimePrecise());
}

static NTSTATUS NTAPI DetourNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS eClass,
	PVOID pInformation, ULONG iLength, PULONG pReturnLength)
{
	const NTSTATUS iStatus = TrueNtQuerySystemInformation(eClass, pInformation, iLength, pReturnLength);
	if (iStatus < 0 || eClass != static_cast<SYSTEM_INFORMATION_CLASS>(3) || iLength < 2 * sizeof(LARGE_INTEGER))
		return iStatus;

	// Keep the time-of-day query's boot/current pair consistent for uptime calculations.
	auto pTimes = static_cast<PLARGE_INTEGER>(pInformation);
	pTimes[0].QuadPart = ShiftMockTime(pTimes[0].QuadPart);
	pTimes[1].QuadPart = ShiftMockTime(pTimes[1].QuadPart);
	return iStatus;
}

static void WINAPI DetourGetSystemTimeAsFileTime(LPFILETIME pTime)
{
	// Win32 fast paths can read shared kernel data without calling NtQuerySystemTime.
	LARGE_INTEGER tTime{};
	DetourNtQuerySystemTime(&tTime);
	pTime->dwLowDateTime = tTime.LowPart;
	pTime->dwHighDateTime = tTime.HighPart;
}

static void WINAPI DetourGetSystemTimePreciseAsFileTime(LPFILETIME pTime)
{
	// Call the native trampoline directly so a nested hook cannot apply the offset twice.
	if (TrueRtlGetSystemTimePrecise != nullptr)
	{
		const LONGLONG iTime = DetourRtlGetSystemTimePrecise();
		pTime->dwLowDateTime = static_cast<DWORD>(iTime);
		pTime->dwHighDateTime = static_cast<DWORD>(iTime >> 32);
		return;
	}
	TrueGetSystemTimePreciseAsFileTime(pTime);
	const LONGLONG iTime = ShiftMockTime(static_cast<LONGLONG>(pTime->dwHighDateTime) << 32 | pTime->dwLowDateTime);
	pTime->dwLowDateTime = static_cast<DWORD>(iTime);
	pTime->dwHighDateTime = static_cast<DWORD>(iTime >> 32);
}

static void WINAPI DetourGetSystemTime(LPSYSTEMTIME pTime)
{
	const DWORD iLastError = GetLastError();
	FILETIME tTime{};
	DetourGetSystemTimeAsFileTime(&tTime);
	FileTimeToSystemTime(&tTime, pTime);
	SetLastError(iLastError);
}

static void WINAPI DetourGetLocalTime(LPSYSTEMTIME pTime)
{
	// Convert shifted UTC using the daylight-saving rules of the resulting date.
	const DWORD iLastError = GetLastError();
	SYSTEMTIME tUtc{};
	DetourGetSystemTime(&tUtc);
	SystemTimeToTzSpecificLocalTimeEx(nullptr, &tUtc, pTime);
	SetLastError(iLastError);
}

static int WINAPI DetourGetDateFormatA(LCID iLocale, DWORD iFlags, const SYSTEMTIME* pTime,
	LPCSTR sFormat, LPSTR sOutput, int iCount)
{
	SYSTEMTIME tTime{};
	if (pTime == nullptr) { DetourGetLocalTime(&tTime); pTime = &tTime; }
	return TrueGetDateFormatA(iLocale, iFlags, pTime, sFormat, sOutput, iCount);
}

static int WINAPI DetourGetDateFormatW(LCID iLocale, DWORD iFlags, const SYSTEMTIME* pTime,
	LPCWSTR sFormat, LPWSTR sOutput, int iCount)
{
	SYSTEMTIME tTime{};
	if (pTime == nullptr) { DetourGetLocalTime(&tTime); pTime = &tTime; }
	return TrueGetDateFormatW(iLocale, iFlags, pTime, sFormat, sOutput, iCount);
}

static int WINAPI DetourGetDateFormatEx(LPCWSTR sLocale, DWORD iFlags, const SYSTEMTIME* pTime,
	LPCWSTR sFormat, LPWSTR sOutput, int iCount, LPCWSTR sCalendar)
{
	SYSTEMTIME tTime{};
	if (pTime == nullptr) { DetourGetLocalTime(&tTime); pTime = &tTime; }
	return TrueGetDateFormatEx(sLocale, iFlags, pTime, sFormat, sOutput, iCount, sCalendar);
}

static int WINAPI DetourGetTimeFormatA(LCID iLocale, DWORD iFlags, const SYSTEMTIME* pTime,
	LPCSTR sFormat, LPSTR sOutput, int iCount)
{
	SYSTEMTIME tTime{};
	if (pTime == nullptr) { DetourGetLocalTime(&tTime); pTime = &tTime; }
	return TrueGetTimeFormatA(iLocale, iFlags, pTime, sFormat, sOutput, iCount);
}

static int WINAPI DetourGetTimeFormatW(LCID iLocale, DWORD iFlags, const SYSTEMTIME* pTime,
	LPCWSTR sFormat, LPWSTR sOutput, int iCount)
{
	SYSTEMTIME tTime{};
	if (pTime == nullptr) { DetourGetLocalTime(&tTime); pTime = &tTime; }
	return TrueGetTimeFormatW(iLocale, iFlags, pTime, sFormat, sOutput, iCount);
}

static int WINAPI DetourGetTimeFormatEx(LPCWSTR sLocale, DWORD iFlags, const SYSTEMTIME* pTime,
	LPCWSTR sFormat, LPWSTR sOutput, int iCount)
{
	SYSTEMTIME tTime{};
	if (pTime == nullptr) { DetourGetLocalTime(&tTime); pTime = &tTime; }
	return TrueGetTimeFormatEx(sLocale, iFlags, pTime, sFormat, sOutput, iCount);
}

template <winpriv::detours::function_pointer Function>
static void AttachClockDetour(winpriv::detours::transaction& transaction, Function& target,
	Function& baseTarget, Function replacement, LPCSTR sName)
{
	// API-set imports can resolve to separate KernelBase implementations of the same clock.
	baseTarget = reinterpret_cast<Function>(GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), sName));
	if (baseTarget == target) baseTarget = nullptr;
	transaction.attach(target, replacement);
	if (baseTarget != nullptr) transaction.attach(baseTarget, replacement);
}

void AttachTimeHooks(winpriv::detours::transaction& transaction)
{
	// The launcher resolves calendar arithmetic once; every descendant receives the same tick delta.
	WCHAR sOffset[24]{};
	const DWORD iLength = GetEnvironmentVariableW(WINPRIV_EV_MOCK_TIME, sOffset, ARRAYSIZE(sOffset));
	WCHAR* pEnd = nullptr;
	errno = 0;
	const LONGLONG iOffset = _wcstoi64(sOffset, &pEnd, 10);
	if (iLength == 0 || iLength >= ARRAYSIZE(sOffset) || *pEnd != L'\0' || errno == ERANGE ||
		iOffset == (std::numeric_limits<LONGLONG>::min)()) return;
	iMockTimeOffset = iOffset;
	if (iMockTimeOffset == 0) return;

	transaction.attach(TrueNtQuerySystemTime, DetourNtQuerySystemTime);
	if (TrueRtlGetSystemTimePrecise != nullptr)
		transaction.attach(TrueRtlGetSystemTimePrecise, DetourRtlGetSystemTimePrecise);
	transaction.attach(TrueNtQuerySystemInformation, DetourNtQuerySystemInformation);
	AttachClockDetour(transaction, TrueGetSystemTimeAsFileTime, TrueBaseGetSystemTimeAsFileTime,
		DetourGetSystemTimeAsFileTime, "GetSystemTimeAsFileTime");
	AttachClockDetour(transaction, TrueGetSystemTimePreciseAsFileTime, TrueBaseGetSystemTimePreciseAsFileTime,
		DetourGetSystemTimePreciseAsFileTime, "GetSystemTimePreciseAsFileTime");
	AttachClockDetour(transaction, TrueGetSystemTime, TrueBaseGetSystemTime, DetourGetSystemTime, "GetSystemTime");
	AttachClockDetour(transaction, TrueGetLocalTime, TrueBaseGetLocalTime, DetourGetLocalTime, "GetLocalTime");

	// A null formatting input requests the current local date/time; explicit inputs remain conversions.
	transaction.attach(TrueGetDateFormatA, DetourGetDateFormatA);
	transaction.attach(TrueGetDateFormatW, DetourGetDateFormatW);
	transaction.attach(TrueGetDateFormatEx, DetourGetDateFormatEx);
	transaction.attach(TrueGetTimeFormatA, DetourGetTimeFormatA);
	transaction.attach(TrueGetTimeFormatW, DetourGetTimeFormatW);
	transaction.attach(TrueGetTimeFormatEx, DetourGetTimeFormatEx);
}
