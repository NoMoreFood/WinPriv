#pragma once
#include <windows.h>

struct LoadingProbeResult
{
    DWORD registryValue;
    DWORD fileSize;
    DWORD attachCount;
    DWORD calls;
};

#if defined(WINPRIV_LOADING_PROBE)
#define WINPRIV_PROBE_IMPORT
#else
#define WINPRIV_PROBE_IMPORT __declspec(dllimport)
#endif

extern "C" WINPRIV_PROBE_IMPORT DWORD __cdecl WinPrivLoadingQuery(LPCWSTR key, LPCWSTR valueName,
    LPCWSTR file, BOOL ansi, volatile LONG* detachCount, LoadingProbeResult* result);

using LoadingProbeQuery = decltype(&WinPrivLoadingQuery);

using LoadingExportResolver = FARPROC(WINAPI*)(HMODULE, LPCSTR);

struct LoadingLifecycleState
{
    DWORD callbacks[4];
    DWORD entries[4];
    DWORD failures;
    DWORD queries;
    DWORD delayLoads;
    DWORD delayUnloads;
    DWORD registryValue;
    DWORD fileSize;
};

using LoadingLifecycleQuery = DWORD(__cdecl*)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, BOOL,
    LoadingLifecycleState*, LoadingProbeResult*);

DWORD CheckLoadingProbe(HMODULE module, LPCWSTR key, LPCWSTR valueName, LPCWSTR file,
    volatile LONG* detached, LoadingProbeResult& result, LoadingExportResolver resolve = nullptr);
DWORD TestManualLoading(LPCWSTR path, LPCWSTR key, LPCWSTR valueName, LPCWSTR file,
    DWORD expectedValue, DWORD expectedSize, DWORD& completed, DWORD& lifecycleCases);
