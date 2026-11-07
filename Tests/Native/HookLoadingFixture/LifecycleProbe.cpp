#include "LoadingProbe.h"
#include <delayimp.h>

extern "C" LoadingLifecycleState WinPrivLifecycleState{};
static LoadingLifecycleState* finalState;
static __declspec(thread) DWORD threadValue = 0x13579bdf;
static __declspec(thread) DWORD threadId;
static __declspec(thread) DWORD threadCalls;

static bool ValidThread()
{
    return threadId == GetCurrentThreadId() && threadValue == (0x13579bdf ^ threadId ^ threadCalls);
}

static void NTAPI LifecycleCallback(PVOID, DWORD reason, PVOID)
{
    auto& state = WinPrivLifecycleState;
    if (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH)
    {
        if (threadValue != 0x13579bdf || threadId != 0 || threadCalls != 0) ++state.failures;
        threadId = GetCurrentThreadId();
        threadValue ^= threadId;
    }
    else if (!ValidThread()) ++state.failures;
    if (state.callbacks[reason] != state.entries[reason]) ++state.failures;
    ++state.callbacks[reason];

    // Exercise hooks in TLS callbacks before the corresponding DllMain notification, using only Win32 APIs.
    WCHAR key[256]{}, name[128]{}, file[32768]{};
    const DWORD keyLength = GetEnvironmentVariableW(L"WINPRIV_LOADING_TLS_KEY", key, ARRAYSIZE(key));
    const DWORD nameLength = GetEnvironmentVariableW(L"WINPRIV_LOADING_TLS_VALUE", name, ARRAYSIZE(name));
    const DWORD fileLength = GetEnvironmentVariableW(L"WINPRIV_LOADING_TLS_FILE", file, ARRAYSIZE(file));
    if (keyLength == 0 || keyLength >= ARRAYSIZE(key) || nameLength == 0 || nameLength >= ARRAYSIZE(name) ||
        fileLength == 0 || fileLength >= ARRAYSIZE(file)) ++state.failures;
    HKEY opened = nullptr;
    DWORD value = 0, type = 0, size = sizeof(value);
    LSTATUS status = RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_QUERY_VALUE, &opened);
    if (status == ERROR_SUCCESS)
    {
        status = RegQueryValueExW(opened, name, nullptr, &type, reinterpret_cast<BYTE*>(&value), &size);
        RegCloseKey(opened);
    }
    const HANDLE handle = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    LARGE_INTEGER length{};
    if (handle == INVALID_HANDLE_VALUE) ++state.failures;
    else
    {
        if (!GetFileSizeEx(handle, &length)) ++state.failures;
        CloseHandle(handle);
    }
    if (status != ERROR_SUCCESS || type != REG_DWORD || size != sizeof(value)) ++state.failures;
    if (reason == DLL_PROCESS_ATTACH)
    {
        state.registryValue = value;
        state.fileSize = length.LowPart;
    }
    else if (state.registryValue != value || state.fileSize != length.LowPart) ++state.failures;
}

// Keep a real PE TLS callback array even when whole-program optimization removes unused data.
#pragma section(".CRT$XLB", read)
extern "C" __declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK WinPrivTlsCallback = LifecycleCallback;
#if defined(_M_IX86)
#pragma comment(linker, "/INCLUDE:__tls_used")
#pragma comment(linker, "/INCLUDE:_WinPrivTlsCallback")
#else
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:WinPrivTlsCallback")
#endif

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    auto& state = WinPrivLifecycleState;
    if (!ValidThread()) ++state.failures;
    if (state.callbacks[reason] != state.entries[reason] + 1) ++state.failures;
    ++state.entries[reason];
    if (reason == DLL_PROCESS_DETACH && finalState != nullptr) *finalState = state;
    return TRUE;
}

static FARPROC WINAPI DelayNotification(unsigned notification, PDelayLoadInfo)
{
    if (notification == dliNotePreLoadLibrary) ++WinPrivLifecycleState.delayLoads;
    return nullptr;
}

extern "C" const PfnDliHook __pfnDliNotifyHook2 = DelayNotification;

extern "C" DWORD __cdecl WinPrivLifecycleQuery(LPCWSTR key, LPCWSTR valueName, LPCWSTR file,
    DWORD expectedCall, BOOL unload, LoadingLifecycleState* detached, LoadingProbeResult* result)
{
    finalState = detached;
    if (!ValidThread()) return ERROR_INVALID_DATA;
    if (unload)
    {
        if (!__FUnloadDelayLoadedDLL2("WinPrivLoadingProbe.dll")) return ERROR_MOD_NOT_FOUND;
        ++WinPrivLifecycleState.delayUnloads;
        return ERROR_SUCCESS;
    }

    // The first call resolves a real delay thunk; later calls must retain this thread's private TLS state.
    if (++threadCalls != expectedCall) return ERROR_INVALID_DATA;
    threadValue = 0x13579bdf ^ threadId ^ threadCalls;
    ++WinPrivLifecycleState.queries;
    return WinPrivLoadingQuery(key, valueName, file, FALSE, nullptr, result);
}
