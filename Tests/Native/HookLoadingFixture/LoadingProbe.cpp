#include "LoadingProbe.h"
#include <string>

extern "C" DWORD WinPrivLoadingAttachCount = 0;
static DWORD calls;
static volatile LONG* detachCounter;

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) ++WinPrivLoadingAttachCount;
    if (reason == DLL_PROCESS_DETACH && detachCounter != nullptr) InterlockedIncrement(detachCounter);
    return TRUE;
}

extern "C" DWORD __cdecl WinPrivLoadingQuery(LPCWSTR key, LPCWSTR valueName,
    LPCWSTR file, BOOL ansi, volatile LONG* detachCount, LoadingProbeResult* result)
{
    if (key == nullptr || valueName == nullptr || result == nullptr) return ERROR_INVALID_PARAMETER;
    *result = {};
    detachCounter = detachCount;
    result->attachCount = WinPrivLoadingAttachCount;
    result->calls = ++calls;

    // Exercise imports from a caller whose complete image can leave the process.
    HKEY opened = nullptr;
    DWORD type = 0;
    DWORD size = sizeof(result->registryValue);
    LSTATUS status;
    if (ansi)
    {
        const auto convert = [](LPCWSTR text)
        {
            const int length = WideCharToMultiByte(CP_ACP, 0, text, -1, nullptr, 0, nullptr, nullptr);
            std::string converted(length, '\0');
            WideCharToMultiByte(CP_ACP, 0, text, -1, converted.data(), length, nullptr, nullptr);
            return converted;
        };
        const auto keyA = convert(key);
        const auto nameA = convert(valueName);
        status = RegOpenKeyExA(HKEY_CURRENT_USER, keyA.c_str(), 0, KEY_QUERY_VALUE, &opened);
        if (status == ERROR_SUCCESS)
            status = RegQueryValueExA(opened, nameA.c_str(), nullptr, &type,
                reinterpret_cast<BYTE*>(&result->registryValue), &size);
    }
    else
    {
        status = RegOpenKeyExW(HKEY_CURRENT_USER, key, 0, KEY_QUERY_VALUE, &opened);
        if (status == ERROR_SUCCESS)
            status = RegQueryValueExW(opened, valueName, nullptr, &type,
                reinterpret_cast<BYTE*>(&result->registryValue), &size);
    }
    if (opened != nullptr) RegCloseKey(opened);
    if (status != ERROR_SUCCESS) return status;
    if (type != REG_DWORD || size != sizeof(DWORD)) return ERROR_INVALID_DATA;
    if (file == nullptr) return ERROR_SUCCESS;

    // File redirection must survive the same unload and relocation cycle as registry hooks.
    const HANDLE handle = CreateFileW(file, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (handle == INVALID_HANDLE_VALUE) return GetLastError();
    LARGE_INTEGER length{};
    const BOOL read = GetFileSizeEx(handle, &length);
    const DWORD error = read ? ERROR_SUCCESS : GetLastError();
    CloseHandle(handle);
    result->fileSize = length.LowPart;
    return error;
}
