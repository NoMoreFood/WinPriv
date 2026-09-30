#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <memory>
#include <string>
#include <type_traits>
#include <vector>

#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
#include "../../../WinPrivLibrary/WinPrivDetoursFork.h"
#endif

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

    using RegOpenKeyExAFunction = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
    using RegQueryValueExAFunction = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);

#if defined(_M_AMD64)
    constexpr auto CurrentArchitecture = L"x64";
#elif defined(_M_IX86)
    constexpr auto CurrentArchitecture = L"x86";
#elif defined(_M_ARM64)
    constexpr auto CurrentArchitecture = L"ARM64";
#else
    constexpr auto CurrentArchitecture = L"unknown";
#endif

    std::string WideToAnsi(const std::wstring& wide)
    {
        if (wide.empty()) return {};
        const int len = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
        if (len <= 0) return {};
        std::string ansi(static_cast<size_t>(len), '\0');
        WideCharToMultiByte(CP_ACP, 0, wide.c_str(), static_cast<int>(wide.size()), ansi.data(), len, nullptr, nullptr);
        return ansi;
    }

    std::wstring QuoteArgumentW(const std::wstring& arg)
    {
        if (arg.find_first_of(L" \t\n\v\"") == std::wstring::npos && !arg.empty())
        {
            return arg;
        }
        std::wstring quoted;
        quoted.push_back(L'"');
        size_t backslashes = 0;
        for (const wchar_t c : arg)
        {
            if (c == L'\\')
            {
                ++backslashes;
            }
            else if (c == L'"')
            {
                quoted.append(backslashes * 2 + 1, L'\\');
                quoted.push_back(L'"');
                backslashes = 0;
            }
            else
            {
                quoted.append(backslashes, L'\\');
                quoted.push_back(c);
                backslashes = 0;
            }
        }
        quoted.append(backslashes * 2, L'\\');
        quoted.push_back(L'"');
        return quoted;
    }

    std::string QuoteArgumentA(const std::string& arg)
    {
        if (arg.find_first_of(" \t\n\v\"") == std::string::npos && !arg.empty())
        {
            return arg;
        }
        std::string quoted;
        quoted.push_back('"');
        size_t backslashes = 0;
        for (const char c : arg)
        {
            if (c == '\\')
            {
                ++backslashes;
            }
            else if (c == '"')
            {
                quoted.append(backslashes * 2 + 1, '\\');
                quoted.push_back('"');
                backslashes = 0;
            }
            else
            {
                quoted.append(backslashes, '\\');
                quoted.push_back(c);
                backslashes = 0;
            }
        }
        quoted.append(backslashes * 2, '\\');
        quoted.push_back('"');
        return quoted;
    }

    LSTATUS QueryDwordW(
        RegOpenKeyExWFunction openKey,
        RegQueryValueExWFunction queryVal,
        RegCloseKeyFunction closeKey,
        const wchar_t* subKey,
        const wchar_t* valueName,
        DWORD& resultValue)
    {
        HKEY key = nullptr;
        LSTATUS status = openKey(HKEY_CURRENT_USER, subKey, 0, KEY_QUERY_VALUE, &key);
        if (status != ERROR_SUCCESS) return status;
        DWORD type = REG_NONE;
        DWORD val = 0;
        DWORD size = sizeof(val);
        status = queryVal(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size);
        closeKey(key);
        if (status != ERROR_SUCCESS) return status;
        if (type != REG_DWORD || size != sizeof(val)) return ERROR_INVALID_DATA;
        resultValue = val;
        return ERROR_SUCCESS;
    }

    LSTATUS QueryDwordA(
        RegOpenKeyExAFunction openKeyA,
        RegQueryValueExAFunction queryValA,
        RegCloseKeyFunction closeKey,
        const char* subKeyA,
        const char* valueNameA,
        DWORD& resultValue)
    {
        HKEY key = nullptr;
        LSTATUS status = openKeyA(HKEY_CURRENT_USER, subKeyA, 0, KEY_QUERY_VALUE, &key);
        if (status != ERROR_SUCCESS) return status;
        DWORD type = REG_NONE;
        DWORD val = 0;
        DWORD size = sizeof(val);
        status = queryValA(key, valueNameA, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size);
        closeKey(key);
        if (status != ERROR_SUCCESS) return status;
        if (type != REG_DWORD || size != sizeof(val)) return ERROR_INVALID_DATA;
        resultValue = val;
        return ERROR_SUCCESS;
    }

    LSTATUS ExecuteQuery(
        const std::wstring& mode,
        const std::wstring& subKey,
        const std::wstring& valueName,
        DWORD& queriedValue)
    {
        queriedValue = 0;
        if (mode == L"static-import" || mode == L"delay-load")
        {
#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
            return ERROR_NOT_SUPPORTED;
#else
            return QueryDwordW(RegOpenKeyExW, RegQueryValueExW, RegCloseKey, subKey.c_str(), valueName.c_str(), queriedValue);
#endif
        }
        else if (mode == L"static-import-ansi" || mode == L"delay-load-ansi")
        {
#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
            return ERROR_NOT_SUPPORTED;
#else
            const std::string subKeyA = WideToAnsi(subKey);
            const std::string valueNameA = WideToAnsi(valueName);
            return QueryDwordA(RegOpenKeyExA, RegQueryValueExA, RegCloseKey, subKeyA.c_str(), valueNameA.c_str(), queriedValue);
#endif
        }
        else if (mode == L"load-library")
        {
            HMODULE mod = LoadLibraryW(L"advapi32.dll");
            if (mod == nullptr) return static_cast<LSTATUS>(GetLastError());
            auto openKey = reinterpret_cast<RegOpenKeyExWFunction>(GetProcAddress(mod, "RegOpenKeyExW"));
            auto queryVal = reinterpret_cast<RegQueryValueExWFunction>(GetProcAddress(mod, "RegQueryValueExW"));
            auto closeKey = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(mod, "RegCloseKey"));
            if (!openKey || !queryVal || !closeKey)
            {
                FreeLibrary(mod);
                return ERROR_PROC_NOT_FOUND;
            }
            const LSTATUS status = QueryDwordW(openKey, queryVal, closeKey, subKey.c_str(), valueName.c_str(), queriedValue);
            FreeLibrary(mod);
            return status;
        }
        else if (mode == L"load-library-ansi")
        {
            HMODULE mod = LoadLibraryW(L"advapi32.dll");
            if (mod == nullptr) return static_cast<LSTATUS>(GetLastError());
            auto openKeyA = reinterpret_cast<RegOpenKeyExAFunction>(GetProcAddress(mod, "RegOpenKeyExA"));
            auto queryValA = reinterpret_cast<RegQueryValueExAFunction>(GetProcAddress(mod, "RegQueryValueExA"));
            auto closeKey = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(mod, "RegCloseKey"));
            if (!openKeyA || !queryValA || !closeKey)
            {
                FreeLibrary(mod);
                return ERROR_PROC_NOT_FOUND;
            }
            const std::string subKeyA = WideToAnsi(subKey);
            const std::string valueNameA = WideToAnsi(valueName);
            const LSTATUS status = QueryDwordA(openKeyA, queryValA, closeKey, subKeyA.c_str(), valueNameA.c_str(), queriedValue);
            FreeLibrary(mod);
            return status;
        }
        else if (mode == L"get-module-handle")
        {
            HMODULE mod = GetModuleHandleW(L"advapi32.dll");
            if (mod == nullptr)
            {
                HMODULE loaded = LoadLibraryW(L"advapi32.dll");
                mod = GetModuleHandleW(L"advapi32.dll");
                if (loaded != nullptr) FreeLibrary(loaded);
            }
            if (mod == nullptr) return static_cast<LSTATUS>(GetLastError());
            auto openKey = reinterpret_cast<RegOpenKeyExWFunction>(GetProcAddress(mod, "RegOpenKeyExW"));
            auto queryVal = reinterpret_cast<RegQueryValueExWFunction>(GetProcAddress(mod, "RegQueryValueExW"));
            auto closeKey = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(mod, "RegCloseKey"));
            if (!openKey || !queryVal || !closeKey) return ERROR_PROC_NOT_FOUND;
            return QueryDwordW(openKey, queryVal, closeKey, subKey.c_str(), valueName.c_str(), queriedValue);
        }
        else if (mode == L"get-module-handle-ansi")
        {
            HMODULE mod = GetModuleHandleW(L"advapi32.dll");
            if (mod == nullptr)
            {
                HMODULE loaded = LoadLibraryW(L"advapi32.dll");
                mod = GetModuleHandleW(L"advapi32.dll");
                if (loaded != nullptr) FreeLibrary(loaded);
            }
            if (mod == nullptr) return static_cast<LSTATUS>(GetLastError());
            auto openKeyA = reinterpret_cast<RegOpenKeyExAFunction>(GetProcAddress(mod, "RegOpenKeyExA"));
            auto queryValA = reinterpret_cast<RegQueryValueExAFunction>(GetProcAddress(mod, "RegQueryValueExA"));
            auto closeKey = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(mod, "RegCloseKey"));
            if (!openKeyA || !queryValA || !closeKey) return ERROR_PROC_NOT_FOUND;
            const std::string subKeyA = WideToAnsi(subKey);
            const std::string valueNameA = WideToAnsi(valueName);
            return QueryDwordA(openKeyA, queryValA, closeKey, subKeyA.c_str(), valueNameA.c_str(), queriedValue);
        }
        else if (mode == L"reload-library")
        {
            DWORD firstValue = 0;
            HMODULE mod1 = LoadLibraryW(L"advapi32.dll");
            if (mod1 == nullptr) return static_cast<LSTATUS>(GetLastError());
            auto open1 = reinterpret_cast<RegOpenKeyExWFunction>(GetProcAddress(mod1, "RegOpenKeyExW"));
            auto query1 = reinterpret_cast<RegQueryValueExWFunction>(GetProcAddress(mod1, "RegQueryValueExW"));
            auto close1 = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(mod1, "RegCloseKey"));
            if (!open1 || !query1 || !close1)
            {
                FreeLibrary(mod1);
                return ERROR_PROC_NOT_FOUND;
            }
            const LSTATUS st1 = QueryDwordW(open1, query1, close1, subKey.c_str(), valueName.c_str(), firstValue);
            FreeLibrary(mod1);
            if (st1 != ERROR_SUCCESS) return st1;

            DWORD secondValue = 0;
            HMODULE mod2 = LoadLibraryW(L"advapi32.dll");
            if (mod2 == nullptr) return static_cast<LSTATUS>(GetLastError());
            auto open2 = reinterpret_cast<RegOpenKeyExWFunction>(GetProcAddress(mod2, "RegOpenKeyExW"));
            auto query2 = reinterpret_cast<RegQueryValueExWFunction>(GetProcAddress(mod2, "RegQueryValueExW"));
            auto close2 = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(mod2, "RegCloseKey"));
            if (!open2 || !query2 || !close2)
            {
                FreeLibrary(mod2);
                return ERROR_PROC_NOT_FOUND;
            }
            const LSTATUS st2 = QueryDwordW(open2, query2, close2, subKey.c_str(), valueName.c_str(), secondValue);
            FreeLibrary(mod2);
            if (st2 != ERROR_SUCCESS) return st2;

            if (firstValue != secondValue) return ERROR_INVALID_DATA;
            queriedValue = secondValue;
            return ERROR_SUCCESS;
        }

        return ERROR_INVALID_PARAMETER;
    }

    int RunChainTest(const int argumentCount, wchar_t* arguments[])
    {
        std::wstring mode = ModeName;
        std::wstring subKey;
        std::wstring valueName;
        DWORD expectedValue = 0;
        bool expectedSpecified = false;
        bool useCreateProcessA = false;
        std::wstring nextExe;
        std::vector<std::wstring> nextArgs;

        for (int i = 2; i < argumentCount; ++i)
        {
            if (wcscmp(arguments[i], L"--mode") == 0 && i + 1 < argumentCount)
            {
                mode = arguments[++i];
            }
            else if (wcscmp(arguments[i], L"--key") == 0 && i + 1 < argumentCount)
            {
                subKey = arguments[++i];
            }
            else if (wcscmp(arguments[i], L"--value-name") == 0 && i + 1 < argumentCount)
            {
                valueName = arguments[++i];
            }
            else if (wcscmp(arguments[i], L"--expected") == 0 && i + 1 < argumentCount)
            {
                expectedValue = static_cast<DWORD>(std::wcstoul(arguments[++i], nullptr, 0));
                expectedSpecified = true;
            }
            else if (wcscmp(arguments[i], L"--use-createprocess-a") == 0)
            {
                useCreateProcessA = true;
            }
            else if (wcscmp(arguments[i], L"--next") == 0 && i + 1 < argumentCount)
            {
                nextExe = arguments[++i];
                for (int j = i + 1; j < argumentCount; ++j)
                {
                    nextArgs.push_back(arguments[j]);
                }
                break;
            }
        }

        if (subKey.empty() || valueName.empty() || !expectedSpecified)
        {
            return Fail(L"missing-parameters", ERROR_INVALID_PARAMETER);
        }

        DWORD queriedValue = 0;
        const LSTATUS status = ExecuteQuery(mode, subKey, valueName, queriedValue);
        if (status != ERROR_SUCCESS)
        {
            return Fail(L"ExecuteQuery", status);
        }

        const bool matched = (queriedValue == expectedValue);
        std::wprintf(
            L"{\"schemaVersion\":1,\"event\":\"chain-verification\",\"pid\":%lu,\"arch\":\"%ls\",\"binaryMode\":\"%ls\",\"requestedMode\":\"%ls\",\"queriedValue\":%lu,\"expectedValue\":%lu,\"matched\":%ls}\n",
            GetCurrentProcessId(),
            CurrentArchitecture,
            ModeName,
            mode.c_str(),
            static_cast<unsigned long>(queriedValue),
            static_cast<unsigned long>(expectedValue),
            matched ? L"true" : L"false"
        );
        std::fflush(stdout);

        if (!matched)
        {
            return Fail(L"value-mismatch", ERROR_INVALID_DATA);
        }

        if (!nextExe.empty())
        {
            std::vector<std::wstring> fullChildArgs;
            fullChildArgs.push_back(nextExe);
            for (const auto& a : nextArgs)
            {
                fullChildArgs.push_back(a);
            }

            PROCESS_INFORMATION processInfo{};
            DWORD childExitCode = MAXDWORD;

            if (useCreateProcessA)
            {
                const std::string nextExeA = WideToAnsi(nextExe);
                std::string commandLineA;
                for (size_t k = 0; k < fullChildArgs.size(); ++k)
                {
                    if (k > 0) commandLineA.push_back(' ');
                    commandLineA += QuoteArgumentA(WideToAnsi(fullChildArgs[k]));
                }

                STARTUPINFOA startupInfoA{};
                startupInfoA.cb = sizeof(startupInfoA);
                startupInfoA.dwFlags = STARTF_USESTDHANDLES;
                startupInfoA.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
                startupInfoA.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
                startupInfoA.hStdError = GetStdHandle(STD_ERROR_HANDLE);

                std::vector<char> cmdBuffer(commandLineA.begin(), commandLineA.end());
                cmdBuffer.push_back('\0');

                if (!CreateProcessA(nextExeA.c_str(), cmdBuffer.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startupInfoA, &processInfo))
                {
                    return Fail(L"CreateProcessA", GetLastError());
                }
            }
            else
            {
                std::wstring commandLineW;
                for (size_t k = 0; k < fullChildArgs.size(); ++k)
                {
                    if (k > 0) commandLineW.push_back(L' ');
                    commandLineW += QuoteArgumentW(fullChildArgs[k]);
                }

                STARTUPINFOW startupInfoW{};
                startupInfoW.cb = sizeof(startupInfoW);
                startupInfoW.dwFlags = STARTF_USESTDHANDLES;
                startupInfoW.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
                startupInfoW.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
                startupInfoW.hStdError = GetStdHandle(STD_ERROR_HANDLE);

                std::vector<wchar_t> cmdBuffer(commandLineW.begin(), commandLineW.end());
                cmdBuffer.push_back(L'\0');

                if (!CreateProcessW(nextExe.c_str(), cmdBuffer.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &startupInfoW, &processInfo))
                {
                    return Fail(L"CreateProcessW", GetLastError());
                }
            }

            WaitForSingleObject(processInfo.hProcess, INFINITE);
            if (!GetExitCodeProcess(processInfo.hProcess, &childExitCode))
            {
                const DWORD err = GetLastError();
                CloseHandle(processInfo.hThread);
                CloseHandle(processInfo.hProcess);
                return Fail(L"GetExitCodeProcess", err);
            }
            CloseHandle(processInfo.hThread);
            CloseHandle(processInfo.hProcess);

            if (childExitCode != 0)
            {
                return static_cast<int>(childExitCode);
            }
        }

        return 0;
    }
}

struct MitigationProcess final
{
    PROCESS_INFORMATION process{};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;

    ~MitigationProcess()
    {
        if (process.hThread != nullptr) CloseHandle(process.hThread);
        if (process.hProcess != nullptr) CloseHandle(process.hProcess);
        if (attributes != nullptr) DeleteProcThreadAttributeList(attributes);
    }
};

int LaunchMitigatedProcess(const int argumentCount, wchar_t* arguments[])
{
    const bool strictCfg = wcscmp(arguments[2], L"strict-cfg") == 0;
    const bool dynamicCode = wcscmp(arguments[2], L"dynamic-code") == 0;
    const bool allowOptOut = wcscmp(arguments[2], L"dynamic-code-optout") == 0;
    if (!strictCfg && !dynamicCode && !allowOptOut) return Fail(L"mitigation-name", ERROR_INVALID_PARAMETER);

    DWORD64 mitigation[]{
        strictCfg ? PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON :
        allowOptOut ? PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON_ALLOW_OPT_OUT :
            PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON,
        strictCfg ? PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON : 0
    };
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    std::vector<BYTE> attributeStorage(attributeBytes);
    MitigationProcess child;
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeStorage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &attributeBytes))
        return Fail(L"InitializeProcThreadAttributeList", GetLastError());
    child.attributes = attributes;
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        &mitigation, sizeof(mitigation), nullptr, nullptr))
        return Fail(L"UpdateProcThreadAttribute", GetLastError());

    std::wstring command;
    for (int index = 3; index < argumentCount; ++index)
    {
        if (!command.empty()) command.push_back(L' ');
        command.push_back(L'"');
        size_t backslashes = 0;
        for (const wchar_t* cursor = arguments[index]; *cursor != L'\0'; ++cursor)
        {
            if (*cursor == L'\\')
            {
                ++backslashes;
                continue;
            }
            command.append(*cursor == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
            command.push_back(*cursor);
            backslashes = 0;
        }
        command.append(backslashes * 2, L'\\');
        command.push_back(L'"');
    }

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    startup.lpAttributeList = attributes;
    if (!CreateProcessW(arguments[3], command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, nullptr, nullptr, &startup.StartupInfo, &child.process))
        return Fail(L"CreateProcessW", GetLastError());

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg{};
    const bool queried = strictCfg ?
        GetProcessMitigationPolicy(child.process.hProcess, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) != FALSE :
        GetProcessMitigationPolicy(child.process.hProcess, ProcessDynamicCodePolicy, &acg, sizeof(acg)) != FALSE;
    if (!queried || (strictCfg && (!cfg.EnableControlFlowGuard || !cfg.StrictMode)) ||
        ((dynamicCode || allowOptOut) && (!acg.ProhibitDynamicCode || acg.AllowThreadOptOut != allowOptOut)))
    {
        TerminateProcess(child.process.hProcess, ERROR_NOT_SUPPORTED);
        WaitForSingleObject(child.process.hProcess, INFINITE);
        return Fail(L"GetProcessMitigationPolicy", ERROR_NOT_SUPPORTED);
    }

    std::wprintf(L"{\"schemaVersion\":1,\"mitigation\":\"%ls\",\"enforced\":true}\n", arguments[2]);
    std::fflush(stdout);
    if (ResumeThread(child.process.hThread) == static_cast<DWORD>(-1))
    {
        const DWORD error = GetLastError();
        TerminateProcess(child.process.hProcess, error);
        WaitForSingleObject(child.process.hProcess, INFINITE);
        return Fail(L"ResumeThread", error);
    }
    if (WaitForSingleObject(child.process.hProcess, INFINITE) != WAIT_OBJECT_0)
        return Fail(L"WaitForSingleObject", GetLastError());
    DWORD exitCode = 0;
    if (!GetExitCodeProcess(child.process.hProcess, &exitCode)) return Fail(L"GetExitCodeProcess", GetLastError());
    return static_cast<int>(exitCode);
}

#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
int QueryDynamicCodeCapability(const bool allowOptOut)
{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
    policy.ProhibitDynamicCode = 1;
    policy.AllowThreadOptOut = allowOptOut;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"SetProcessMitigationPolicy", GetLastError());
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"GetProcessMitigationPolicy", GetLastError());

    SetLastError(NO_ERROR);
    void* allocation = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    const DWORD allocationError = allocation == nullptr ? GetLastError() : NO_ERROR;
    if (allocation != nullptr) VirtualFree(allocation, 0, MEM_RELEASE);
    std::wprintf(L"{\"schemaVersion\":1,\"capability\":\"dynamic-code\",\"processDynamicCode\":%lu,"
        L"\"allowThreadOptOut\":%lu,\"allocationSucceeded\":%ls,\"allocationError\":%lu}\n",
        static_cast<DWORD>(policy.ProhibitDynamicCode), static_cast<DWORD>(policy.AllowThreadOptOut),
        allocation != nullptr ? L"true" : L"false", allocationError);
    return 0;
}

__declspec(noinline) DWORD WINAPI MitigationOriginal(const DWORD value)
{
    return value * 3 + 7;
}

__declspec(noinline) DWORD WINAPI MitigationReplacement(const DWORD value)
{
    return value * 5 + 11;
}

struct DetourThreadState final
{
    std::atomic<bool> stop = false;
    std::atomic<DWORD> calls = 0;
    std::atomic<DWORD> invalidValues = 0;
    std::atomic<DWORD> createdThreads = 0;
    HANDLE ready = nullptr;
    HANDLE release = nullptr;
};

DWORD WINAPI DetourCallWorker(LPVOID parameter)
{
    auto& state = *static_cast<DetourThreadState*>(parameter);
    auto volatile call = &MitigationOriginal;
    while (!state.stop.load())
    {
        const DWORD value = call(11);
        if (value != 40 && value != 66) ++state.invalidValues;
        if (++state.calls % 256 == 0) Sleep(0);
    }
    return NO_ERROR;
}

DWORD WINAPI DetourChurnWorker(LPVOID parameter)
{
    auto& state = *static_cast<DetourThreadState*>(parameter);
    while (!state.stop.load())
    {
        std::unique_ptr<void, decltype(&CloseHandle)> child(CreateThread(nullptr, 0, [](LPVOID context) -> DWORD {
            auto& shared = *static_cast<DetourThreadState*>(context);
            auto volatile call = &MitigationOriginal;
            for (DWORD iteration = 0; iteration < 256; ++iteration)
            {
                const DWORD value = call(11);
                if (value != 40 && value != 66) ++shared.invalidValues;
                ++shared.calls;
            }
            return NO_ERROR;
        }, parameter, 0, nullptr), CloseHandle);
        if (!child) return GetLastError();
        ++state.createdThreads;
        if (WaitForSingleObject(child.get(), INFINITE) != WAIT_OBJECT_0) return GetLastError();
    }
    return NO_ERROR;
}

DWORD WINAPI DetourHeapWorker(LPVOID parameter)
{
    auto& state = *static_cast<DetourThreadState*>(parameter);
    if (!HeapLock(GetProcessHeap())) return GetLastError();
    SetEvent(state.ready);
    WaitForSingleObject(state.release, INFINITE);
    return HeapUnlock(GetProcessHeap()) ? NO_ERROR : GetLastError();
}

int TestThreadEnumeration(const wchar_t* scenario)
{
    const bool churn = wcscmp(scenario, L"churn") == 0;
    const bool heapLock = wcscmp(scenario, L"heap-lock") == 0;
    const bool inaccessible = wcscmp(scenario, L"inaccessible") == 0;
    if (!churn && !heapLock && !inaccessible) return Fail(L"thread-scenario", ERROR_INVALID_PARAMETER);

    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    if (inaccessible)
    {
        // Disable inherited debug access so the empty thread DACL is enforced for every runner token.
        std::unique_ptr<std::remove_pointer_t<HMODULE>, decltype(&FreeLibrary)> security(
            LoadLibraryW(L"advapi32.dll"), FreeLibrary);
        if (!security) return Fail(L"LoadLibraryW", GetLastError());
        const auto openToken = reinterpret_cast<decltype(&OpenProcessToken)>(
            GetProcAddress(security.get(), "OpenProcessToken"));
        const auto lookupPrivilege = reinterpret_cast<decltype(&LookupPrivilegeValueW)>(
            GetProcAddress(security.get(), "LookupPrivilegeValueW"));
        const auto adjustPrivileges = reinterpret_cast<decltype(&AdjustTokenPrivileges)>(
            GetProcAddress(security.get(), "AdjustTokenPrivileges"));
        if (!openToken || !lookupPrivilege || !adjustPrivileges) return Fail(L"GetProcAddress", ERROR_PROC_NOT_FOUND);

        HANDLE rawToken = nullptr;
        if (!openToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &rawToken))
            return Fail(L"OpenProcessToken", GetLastError());
        Handle token(rawToken, CloseHandle);
        TOKEN_PRIVILEGES privileges{ .PrivilegeCount = 1 };
        if (!lookupPrivilege(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid) ||
            !adjustPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr))
            return Fail(L"DisableDebugPrivilege", GetLastError());
        const DWORD error = GetLastError();
        if (error != NO_ERROR && error != ERROR_NOT_ALL_ASSIGNED) return Fail(L"DisableDebugPrivilege", error);
    }

    Handle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle);
    Handle release(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle);
    if (!ready || !release) return Fail(L"CreateEventW", GetLastError());
    DetourThreadState state;
    state.ready = ready.get();
    state.release = release.get();
    std::vector<Handle> workers;
    workers.reserve(5);
    const auto stopWorkers = [&]() -> LONG {
        state.stop = true;
        SetEvent(release.get());
        for (const auto& worker : workers)
        {
            if (WaitForSingleObject(worker.get(), 5000) != WAIT_OBJECT_0) return ERROR_TIMEOUT;
            DWORD exitCode = NO_ERROR;
            if (!GetExitCodeThread(worker.get(), &exitCode)) return GetLastError();
            if (exitCode != NO_ERROR) return static_cast<LONG>(exitCode);
        }
        return NO_ERROR;
    };
    const auto fail = [&](const wchar_t* stage, LONG error) { stopWorkers(); return Fail(stage, error); };

    // Keep peers executing the patched function throughout attachment and detachment.
    for (DWORD index = 0; index < 4; ++index)
    {
        workers.emplace_back(CreateThread(nullptr, 0, DetourCallWorker, &state, 0, nullptr), CloseHandle);
        if (!workers.back()) return fail(L"CreateThread", GetLastError());
    }
    while (state.calls.load() == 0) Sleep(1);

    // Force thread churn, a held heap lock, or a peer that cannot be opened for suspension.
    ACL emptyAcl{ ACL_REVISION, 0, sizeof(ACL), 0, 0 };
    SECURITY_DESCRIPTOR descriptor{};
    descriptor.Revision = SECURITY_DESCRIPTOR_REVISION;
    descriptor.Control = SE_DACL_PRESENT;
    descriptor.Dacl = &emptyAcl;
    SECURITY_ATTRIBUTES attributes{ sizeof(attributes), &descriptor, FALSE };
    const auto worker = churn ? DetourChurnWorker : heapLock ? DetourHeapWorker : DetourCallWorker;
    DWORD peerId = 0;
    workers.emplace_back(CreateThread(inaccessible ? &attributes : nullptr, 0, worker, &state, 0, &peerId),
        CloseHandle);
    if (!workers.back()) return fail(L"CreateThread", GetLastError());
    if (heapLock && WaitForSingleObject(ready.get(), 5000) != WAIT_OBJECT_0)
        return fail(L"HeapLock", ERROR_TIMEOUT);
    if (inaccessible)
    {
        Handle denied(OpenThread(THREAD_SUSPEND_RESUME, FALSE, peerId), CloseHandle);
        const DWORD error = GetLastError();
        if (denied || error != ERROR_ACCESS_DENIED) return fail(L"thread-access", ERROR_INVALID_DATA);
    }

    auto target = &MitigationOriginal;
    auto volatile call = &MitigationOriginal;
    LONG commitError = NO_ERROR;
    DWORD iterations = 0;
    for (; iterations < 32; ++iterations)
    {
        for (const auto action : { winpriv::detours::action::attach, winpriv::detours::action::detach })
        {
            winpriv::detours::transaction transaction;
            const LONG apply = transaction.apply(action, target, MitigationReplacement);
            commitError = transaction.commit();
            if (apply != NO_ERROR || commitError != NO_ERROR)
            {
                if (commitError == NO_ERROR) commitError = apply;
                break;
            }
            const DWORD expected = action == winpriv::detours::action::attach ? 66 : 40;
            if (call(11) != expected || target(11) != 40) ++state.invalidValues;
        }
        if (commitError != NO_ERROR) break;
    }
    const LONG joined = stopWorkers();
    if (joined != NO_ERROR) return Fail(L"join-workers", joined);
    std::wprintf(L"{\"schemaVersion\":1,\"scenario\":\"%ls\",\"iterations\":%lu,\"commitError\":%ld,"
        L"\"calls\":%lu,\"createdThreads\":%lu,\"invalidValues\":%lu,\"originalPointer\":%ls,\"finalValue\":%lu}\n",
        scenario, iterations, commitError, state.calls.load(), state.createdThreads.load(), state.invalidValues.load(),
        target == &MitigationOriginal ? L"true" : L"false", call(11));
    return 0;
}

int TestDynamicCodeAllocation()
{
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
    policy.ProhibitDynamicCode = 1;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"SetProcessMitigationPolicy", GetLastError());
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &policy, sizeof(policy)) ||
        !policy.ProhibitDynamicCode || policy.AllowThreadOptOut)
        return Fail(L"GetProcessMitigationPolicy", ERROR_NOT_SUPPORTED);

    auto target = &MitigationOriginal;
    winpriv::detours::transaction transaction;
    if (!transaction) return Fail(L"DetourTransactionBegin", transaction.commit());
    const LONG attach = transaction.apply(winpriv::detours::action::attach, target, MitigationReplacement);
    const LONG commit = transaction.commit();
    std::wprintf(L"{\"schemaVersion\":1,\"mitigation\":\"dynamic-code\",\"enforced\":true,"
        L"\"attachError\":%ld,\"commitError\":%ld,\"originalPointer\":%ls,\"value\":%lu}\n",
        attach, commit, target == &MitigationOriginal ? L"true" : L"false", target(11));
    return 0;
}

int TestDynamicCodeOptOut(const wchar_t* scenario)
{
    const bool abort = wcscmp(scenario, L"abort") == 0;
    const bool failedCommit = wcscmp(scenario, L"failed-commit") == 0;
    const bool nested = wcscmp(scenario, L"nested") == 0;
    const bool preexisting = wcscmp(scenario, L"preexisting") == 0;
    const bool bridge = wcscmp(scenario, L"c-bridge") == 0;
    if (!abort && !failedCommit && !nested && !preexisting && !bridge && wcscmp(scenario, L"attach-detach") != 0)
        return Fail(L"optout-scenario", ERROR_INVALID_PARAMETER);

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
    policy.ProhibitDynamicCode = 1;
    policy.AllowThreadOptOut = 1;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"SetProcessMitigationPolicy", GetLastError());
    DWORD threadBefore = 0;
    if (preexisting)
    {
        DWORD allowed = THREAD_DYNAMIC_CODE_ALLOW;
        if (!SetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &allowed, sizeof(allowed)))
            return Fail(L"SetThreadInformation", GetLastError());
    }
    if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &threadBefore, sizeof(threadBefore)))
        return Fail(L"GetThreadInformation", GetLastError());

    auto target = &MitigationOriginal;
    auto volatile call = &MitigationOriginal;
    DWORD threadDuring = MAXDWORD;
    DWORD threadAfterNested = MAXDWORD;
    DWORD threadAfterInvalid = MAXDWORD;
    DWORD threadAfterCommit = MAXDWORD;
    LONG attach = ERROR_INVALID_OPERATION;
    LONG commit = ERROR_INVALID_OPERATION;
    LONG invalidApply = NO_ERROR;
    LONG nestedCommit = NO_ERROR;
    bool nestedActive = false;
    PVOID invalidTarget = nullptr;
    if (nested)
    {
        const LONG begin = DetourTransactionBegin();
        if (begin != NO_ERROR) return Fail(L"outer-transaction", begin);
        {
            winpriv::detours::transaction inner;
            nestedActive = static_cast<bool>(inner);
            nestedCommit = inner.commit();
        }
        const bool queried = GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy,
            &threadAfterNested, sizeof(threadAfterNested)) != FALSE;
        const DWORD queryError = GetLastError();
        const LONG aborted = DetourTransactionAbort();
        if (!queried || aborted != NO_ERROR) return Fail(L"outer-abort", queried ? aborted : queryError);
    }
    if (bridge)
    {
        invalidApply = DetourAttachTransaction(&invalidTarget, reinterpret_cast<PVOID>(MitigationReplacement));
        if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy,
            &threadAfterInvalid, sizeof(threadAfterInvalid)))
            return Fail(L"GetThreadInformation", GetLastError());
        attach = DetourAttachTransaction(reinterpret_cast<PVOID*>(&target),
            reinterpret_cast<PVOID>(MitigationReplacement));
        commit = attach;
        if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy,
            &threadAfterCommit, sizeof(threadAfterCommit)))
            return Fail(L"GetThreadInformation", GetLastError());
    }
    else
    {
        winpriv::detours::transaction transaction;
        if (!transaction) return Fail(L"DetourTransactionBegin", transaction.commit());
        if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &threadDuring, sizeof(threadDuring)))
            return Fail(L"GetThreadInformation", GetLastError());
        attach = transaction.apply(winpriv::detours::action::attach, target, MitigationReplacement);
        if (failedCommit)
        {
            decltype(target) missing = nullptr;
            invalidApply = transaction.apply(winpriv::detours::action::attach, missing, MitigationReplacement);
        }
        if (!abort)
        {
            commit = transaction.commit();
            if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy,
                &threadAfterCommit, sizeof(threadAfterCommit)))
                return Fail(L"GetThreadInformation", GetLastError());
        }
    }
    DWORD threadAfterScope = MAXDWORD;
    if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &threadAfterScope, sizeof(threadAfterScope)))
        return Fail(L"GetThreadInformation", GetLastError());
    const DWORD hookedValue = call(11);
    const DWORD trampolineValue = target(11);
    LONG detach = ERROR_INVALID_OPERATION;
    LONG detachCommit = ERROR_INVALID_OPERATION;
    DWORD threadDuringDetach = MAXDWORD;
    if (!abort && !failedCommit && attach == NO_ERROR && commit == NO_ERROR)
    {
        winpriv::detours::transaction transaction;
        if (!transaction) return Fail(L"detach-transaction", transaction.commit());
        if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy,
            &threadDuringDetach, sizeof(threadDuringDetach)))
            return Fail(L"GetThreadInformation", GetLastError());
        detach = transaction.apply(winpriv::detours::action::detach, target, MitigationReplacement);
        detachCommit = transaction.commit();
    }
    DWORD threadAfterDetach = MAXDWORD;
    if (!GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy,
        &threadAfterDetach, sizeof(threadAfterDetach)) ||
        !GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"query-final-policy", GetLastError());
    std::wprintf(L"{\"schemaVersion\":1,\"scenario\":\"%ls\",\"processDynamicCode\":%lu,\"allowThreadOptOut\":%lu,"
        L"\"threadBefore\":%lu,\"threadDuring\":%lu,\"threadAfterNested\":%lu,\"threadAfterCommit\":%lu,"
        L"\"threadAfterScope\":%lu,\"threadDuringDetach\":%lu,\"threadAfterDetach\":%lu,"
        L"\"attachError\":%ld,\"commitError\":%ld,\"invalidApplyError\":%ld,\"nestedActive\":%ls,"
        L"\"threadAfterInvalid\":%lu,\"invalidPointerUnchanged\":%ls,"
        L"\"nestedCommitError\":%ld,\"detachError\":%ld,\"detachCommitError\":%ld,"
        L"\"hookedValue\":%lu,\"trampolineValue\":%lu,\"finalValue\":%lu,\"originalPointer\":%ls}\n",
        scenario, static_cast<DWORD>(policy.ProhibitDynamicCode), static_cast<DWORD>(policy.AllowThreadOptOut),
        threadBefore, threadDuring, threadAfterNested, threadAfterCommit, threadAfterScope, threadDuringDetach,
        threadAfterDetach, attach, commit, invalidApply, nestedActive ? L"true" : L"false",
        threadAfterInvalid, invalidTarget == nullptr ? L"true" : L"false", nestedCommit,
        detach, detachCommit, hookedValue, trampolineValue, call(11),
        target == &MitigationOriginal ? L"true" : L"false");
    return 0;
}
#endif

int wmain(const int argumentCount, wchar_t* arguments[])
{
#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
    if (argumentCount == 3 && wcscmp(arguments[1], L"--dynamic-code-capability") == 0)
    {
        if (wcscmp(arguments[2], L"strict") != 0 && wcscmp(arguments[2], L"optout") != 0)
            return Fail(L"capability-mode", ERROR_INVALID_PARAMETER);
        return QueryDynamicCodeCapability(wcscmp(arguments[2], L"optout") == 0);
    }
    if (argumentCount == 3 && wcscmp(arguments[1], L"--startup-timestamp") == 0)
    {
        LARGE_INTEGER counter{}, frequency{};
        QueryPerformanceCounter(&counter);
        QueryPerformanceFrequency(&frequency);
        FILE* output = nullptr;
        if (_wfopen_s(&output, arguments[2], L"w") != 0) return Fail(L"startup-output", ERROR_OPEN_FAILED);
        std::fwprintf(output, L"%lld %lld\n", counter.QuadPart, frequency.QuadPart);
        std::fclose(output);
        return 0;
    }
    if (argumentCount == 3 && wcscmp(arguments[1], L"--thread-enumeration") == 0)
        return TestThreadEnumeration(arguments[2]);
    if (argumentCount == 2 && wcscmp(arguments[1], L"--dynamic-code-allocation") == 0)
        return TestDynamicCodeAllocation();
    if (argumentCount == 3 && wcscmp(arguments[1], L"--dynamic-code-optout") == 0)
        return TestDynamicCodeOptOut(arguments[2]);
#endif

    if (argumentCount >= 4 && wcscmp(arguments[1], L"--launch-mitigation") == 0)
        return LaunchMitigatedProcess(argumentCount, arguments);

    if (argumentCount >= 2 && wcscmp(arguments[1], L"--chain-test") == 0)
        return RunChainTest(argumentCount, arguments);

    const bool descendant = argumentCount == 4 && wcscmp(arguments[1], L"--query-descendant") == 0;
    if (argumentCount != 3 && !descendant)
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
        HKEY_CURRENT_USER, arguments[descendant ? 2 : 1], 0, KEY_QUERY_VALUE, &key);
    if (openStatus != ERROR_SUCCESS)
    {
        ReleaseRegistryApi(api);
        return Fail(L"RegOpenKeyExW", openStatus);
    }

    DWORD type = REG_NONE;
    DWORD value = 0;
    DWORD size = sizeof(value);
    const LSTATUS queryStatus = api.queryValue(
        key, arguments[descendant ? 3 : 2], nullptr, &type, reinterpret_cast<LPBYTE>(&value), &size);
    const LSTATUS closeStatus = api.closeKey(key);
    ReleaseRegistryApi(api);

    if (queryStatus != ERROR_SUCCESS) return Fail(L"RegQueryValueExW", queryStatus);
    if (closeStatus != ERROR_SUCCESS) return Fail(L"RegCloseKey", closeStatus);
    if (type != REG_DWORD || size != sizeof(value)) return Fail(L"result-shape", ERROR_INVALID_DATA);

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
    DWORD threadPolicy = MAXDWORD;
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &policy, sizeof(policy)) ||
        !GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &threadPolicy, sizeof(threadPolicy)))
        return Fail(L"query-policy", GetLastError());
    std::wprintf(L"{\"schemaVersion\":1,\"mode\":\"%ls\",\"value\":%lu,\"processDynamicCode\":%lu,"
        L"\"allowThreadOptOut\":%lu,\"threadDynamicCode\":%lu}\n", ModeName, static_cast<unsigned long>(value),
        static_cast<DWORD>(policy.ProhibitDynamicCode), static_cast<DWORD>(policy.AllowThreadOptOut), threadPolicy);
    if (descendant)
    {
        wchar_t launchMode[] = L"--launch-mitigation";
        wchar_t mitigation[] = L"dynamic-code-optout";
        wchar_t* childArguments[]{ arguments[0], launchMode, mitigation, arguments[0], arguments[2], arguments[3] };
        std::fflush(stdout);
        return LaunchMitigatedProcess(static_cast<int>(std::size(childArguments)), childArguments);
    }
    return 0;
}
