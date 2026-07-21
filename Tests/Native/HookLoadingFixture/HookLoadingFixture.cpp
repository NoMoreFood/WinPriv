#include <windows.h>

#include <cstdio>
#include <cwchar>

#if (defined(WINPRIV_LOADING_MODE_IMPORT) + defined(WINPRIV_LOADING_MODE_DELAY) + defined(WINPRIV_LOADING_MODE_DYNAMIC)) != 1
#error Exactly one WinPriv hook-loading mode must be selected.
#endif

namespace
{
    using RegOpenKeyExWFunction = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
    using RegQueryValueExWFunction = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
    using RegCloseKeyFunction = LSTATUS(WINAPI*)(HKEY);

    struct RegistryApi final
    {
        HMODULE module = nullptr;
        RegOpenKeyExWFunction openKey = nullptr;
        RegQueryValueExWFunction queryValue = nullptr;
        RegCloseKeyFunction closeKey = nullptr;
    };

#if defined(WINPRIV_LOADING_MODE_IMPORT)
    constexpr auto ModeName = L"normal-import";
#elif defined(WINPRIV_LOADING_MODE_DELAY)
    constexpr auto ModeName = L"delay-load";
#else
    constexpr auto ModeName = L"load-library";
#endif

    bool ResolveRegistryApi(RegistryApi& api) noexcept
    {
#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
        api.module = LoadLibraryW(L"advapi32.dll");
        if (api.module == nullptr) return false;

        api.openKey = reinterpret_cast<RegOpenKeyExWFunction>(
            GetProcAddress(api.module, "RegOpenKeyExW"));
        api.queryValue = reinterpret_cast<RegQueryValueExWFunction>(
            GetProcAddress(api.module, "RegQueryValueExW"));
        api.closeKey = reinterpret_cast<RegCloseKeyFunction>(
            GetProcAddress(api.module, "RegCloseKey"));
        return api.openKey != nullptr && api.queryValue != nullptr && api.closeKey != nullptr;
#else
        // The normal executable resolves these through its ordinary import
        // table.  The delay-load executable uses the MSVC delay helper because
        // advapi32.dll is listed in its DelayLoadDLLs linker setting.
        api.openKey = RegOpenKeyExW;
        api.queryValue = RegQueryValueExW;
        api.closeKey = RegCloseKey;
        return true;
#endif
    }

    void ReleaseRegistryApi(RegistryApi& api) noexcept
    {
        if (api.module != nullptr)
        {
            FreeLibrary(api.module);
            api.module = nullptr;
        }
    }

    int Fail(const wchar_t* stage, const LSTATUS status) noexcept
    {
        std::fwprintf(stderr, L"WinPriv hook-loading fixture failed at %ls (status=%lu).\n",
            stage, static_cast<unsigned long>(status));
        return 1;
    }
}

int wmain(const int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 3)
    {
        std::fwprintf(stderr,
            L"Usage: %ls <HKCU-subkey> <value-name>\n", arguments[0]);
        return 2;
    }

    RegistryApi api;
    if (!ResolveRegistryApi(api))
    {
        const DWORD error = GetLastError();
        ReleaseRegistryApi(api);
        return Fail(L"resolve", static_cast<LSTATUS>(error));
    }

    HKEY key = nullptr;
    const LSTATUS openStatus = api.openKey(
        HKEY_CURRENT_USER, arguments[1], 0, KEY_QUERY_VALUE, &key);
    if (openStatus != ERROR_SUCCESS)
    {
        ReleaseRegistryApi(api);
        return Fail(L"RegOpenKeyExW", openStatus);
    }

    DWORD type = REG_NONE;
    DWORD value = 0;
    DWORD size = sizeof(value);
    const LSTATUS queryStatus = api.queryValue(
        key, arguments[2], nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size);
    const LSTATUS closeStatus = api.closeKey(key);
    ReleaseRegistryApi(api);

    if (queryStatus != ERROR_SUCCESS) return Fail(L"RegQueryValueExW", queryStatus);
    if (closeStatus != ERROR_SUCCESS) return Fail(L"RegCloseKey", closeStatus);
    if (type != REG_DWORD || size != sizeof(value)) return Fail(L"result-shape", ERROR_INVALID_DATA);

    std::wprintf(
        L"{\"schemaVersion\":1,\"mode\":\"%ls\",\"value\":%lu}\n",
        ModeName, static_cast<unsigned long>(value));
    return 0;
}
