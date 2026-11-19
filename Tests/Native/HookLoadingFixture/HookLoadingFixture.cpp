#include <windows.h>
#include <sqlext.h>

#include <array>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <vector>

#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
#include "../../../WinPrivLibrary/WinPrivDetoursFork.h"
int TestSmartCardSessionRouting();
int TestSmartCardEnrollment();
int TestProcessLogon();
int TestProcessControl();
DWORD TestDetourContextRollback();
#if defined(_M_ARM64)
DWORD TestDetourArm64Branches();
#endif
int TestPrivilegeEnumeration();
#endif

#if (defined(WINPRIV_LOADING_MODE_IMPORT) + defined(WINPRIV_LOADING_MODE_DELAY) + defined(WINPRIV_LOADING_MODE_DYNAMIC)) != 1
#error Exactly one WinPriv hook-loading mode must be selected.
#endif

#if defined(WINPRIV_LOADING_MODE_IMPORT)
static constexpr auto ModeName = L"normal-import";
#elif defined(WINPRIV_LOADING_MODE_DELAY)
static constexpr auto ModeName = L"delay-load";
#else
static constexpr auto ModeName = L"load-library";
#endif

#if defined(_M_AMD64)
static constexpr auto CurrentArchitecture = L"x64";
#elif defined(_M_IX86)
static constexpr auto CurrentArchitecture = L"x86";
#elif defined(_M_ARM64)
static constexpr auto CurrentArchitecture = L"ARM64";
#else
static constexpr auto CurrentArchitecture = L"unknown";
#endif

struct HandleCloser { void operator()(HANDLE handle) const noexcept { if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); } };
struct ModuleCloser { void operator()(HMODULE module) const noexcept { if (module) FreeLibrary(module); } };
using UniqueHandle = std::unique_ptr<void, HandleCloser>;
using UniqueModule = std::unique_ptr<std::remove_pointer_t<HMODULE>, ModuleCloser>;

using RegOpenKeyExWFunction = LSTATUS(WINAPI*)(HKEY, LPCWSTR, DWORD, REGSAM, PHKEY);
using RegQueryValueExWFunction = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegOpenKeyExAFunction = LSTATUS(WINAPI*)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
using RegQueryValueExAFunction = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using RegCloseKeyFunction = LSTATUS(WINAPI*)(HKEY);

static int Fail(const wchar_t* stage, const LSTATUS status) noexcept
{
    std::fwprintf(stderr, L"WinPriv hook-loading fixture failed at %ls (status=%lu).\n",
        stage, static_cast<unsigned long>(status));
    return 1;
}

static std::string WideToAnsi(const std::wstring& wide)
{
    if (wide.empty()) return {};
    const int len = WideCharToMultiByte(CP_ACP, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string ansi(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_ACP, 0, wide.c_str(), static_cast<int>(wide.size()), ansi.data(), len, nullptr, nullptr);
    return ansi;
}

template <typename Char>
static std::basic_string<Char> QuoteArgument(const std::basic_string<Char>& arg)
{
    constexpr Char quote = static_cast<Char>('"');
    constexpr Char slash = static_cast<Char>('\\');
    const Char delimiters[] = { static_cast<Char>(' '), static_cast<Char>('\t'),
        static_cast<Char>('\n'), static_cast<Char>('\v'), quote, static_cast<Char>('\0') };
    if (!arg.empty() && arg.find_first_of(delimiters) == std::basic_string<Char>::npos) return arg;

    std::basic_string<Char> quoted;
    quoted.push_back(quote);
    size_t backslashes = 0;
    for (const Char c : arg)
    {
        if (c == slash) { ++backslashes; continue; }
        quoted.append(c == quote ? backslashes * 2 + 1 : backslashes, slash);
        quoted.push_back(c);
        backslashes = 0;
    }
    quoted.append(backslashes * 2, slash);
    quoted.push_back(quote);
    return quoted;
}

template <typename StartupInfo>
static void InitStdHandles(StartupInfo& startup) noexcept
{
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
}

template <typename Character>
static LSTATUS QueryDword(auto openKey, auto queryVal, RegCloseKeyFunction closeKey,
    const Character* subKey, const Character* valueName, DWORD& resultValue)
{
    HKEY key = nullptr;
    LSTATUS status = openKey(HKEY_CURRENT_USER, subKey, 0, KEY_QUERY_VALUE, &key);
    if (status != ERROR_SUCCESS) return status;
    DWORD type = REG_NONE, val = 0, size = sizeof(val);
    status = queryVal(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(&val), &size);
    const LSTATUS closeStatus = closeKey(key);
    if (status != ERROR_SUCCESS) return status;
    if (closeStatus != ERROR_SUCCESS) return closeStatus;
    if (type != REG_DWORD || size != sizeof(val)) return ERROR_INVALID_DATA;
    resultValue = val;
    return ERROR_SUCCESS;
}

static LSTATUS ExecuteQuery(const std::wstring& mode, const std::wstring& subKey,
    const std::wstring& valueName, DWORD& queriedValue)
{
    queriedValue = 0;
    const bool ansi = mode.ends_with(L"-ansi");
    const std::wstring_view base = ansi ? std::wstring_view(mode).substr(0, mode.size() - 5) : std::wstring_view(mode);

    // Static and delay-load modes invoke advapi32 directly via the executable's import table.
    if (base == L"static-import" || base == L"normal-import" || base == L"delay-load")
    {
#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
        return ERROR_NOT_SUPPORTED;
#else
        if (!ansi)
            return QueryDword(RegOpenKeyExW, RegQueryValueExW, RegCloseKey, subKey.c_str(), valueName.c_str(), queriedValue);
        const std::string subKeyA = WideToAnsi(subKey), valueNameA = WideToAnsi(valueName);
        return QueryDword(RegOpenKeyExA, RegQueryValueExA, RegCloseKey, subKeyA.c_str(), valueNameA.c_str(), queriedValue);
#endif
    }

    // Dynamic modes resolve advapi32 at runtime via LoadLibrary, GetModuleHandle, or a reload cycle.
    UniqueModule owned;
    HMODULE module = nullptr;
    if (base == L"reload-library" && !ansi)
    {
        UniqueModule first(LoadLibraryExW(L"advapi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
        if (!first) return static_cast<LSTATUS>(GetLastError());
        first.reset();
        owned.reset(LoadLibraryExW(L"advapi32.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
        module = owned.get();
    }
    else if (base == L"load-library")
    {
        owned.reset(LoadLibraryW(L"advapi32.dll"));
        module = owned.get();
    }
    else if (base == L"get-module-handle")
    {
        module = GetModuleHandleW(L"advapi32.dll");
        if (module == nullptr)
        {
            owned.reset(LoadLibraryW(L"advapi32.dll"));
            module = GetModuleHandleW(L"advapi32.dll");
        }
    }
    else
    {
        return ERROR_INVALID_PARAMETER;
    }
    if (module == nullptr) return static_cast<LSTATUS>(GetLastError());

    const auto closeKey = reinterpret_cast<RegCloseKeyFunction>(GetProcAddress(module, "RegCloseKey"));
    if (!ansi)
    {
        const auto openKey = reinterpret_cast<RegOpenKeyExWFunction>(GetProcAddress(module, "RegOpenKeyExW"));
        const auto queryVal = reinterpret_cast<RegQueryValueExWFunction>(GetProcAddress(module, "RegQueryValueExW"));
        if (!openKey || !queryVal || !closeKey) return ERROR_PROC_NOT_FOUND;
        return QueryDword(openKey, queryVal, closeKey, subKey.c_str(), valueName.c_str(), queriedValue);
    }
    const auto openKeyA = reinterpret_cast<RegOpenKeyExAFunction>(GetProcAddress(module, "RegOpenKeyExA"));
    const auto queryValA = reinterpret_cast<RegQueryValueExAFunction>(GetProcAddress(module, "RegQueryValueExA"));
    if (!openKeyA || !queryValA || !closeKey) return ERROR_PROC_NOT_FOUND;
    const std::string subKeyA = WideToAnsi(subKey), valueNameA = WideToAnsi(valueName);
    return QueryDword(openKeyA, queryValA, closeKey, subKeyA.c_str(), valueNameA.c_str(), queriedValue);
}

static int TestLibraryLoading(const int argumentCount, wchar_t* arguments[])
{
    // Verify registry, file-redirect, and dynamic/datafile DLL loading interoperate across fixture modes.
    if (argumentCount != 7) return Fail(L"library-loading-args", ERROR_INVALID_PARAMETER);
    const std::wstring subKey = arguments[2], valueName = arguments[3], filePath = arguments[4];
    const DWORD expectedValue = static_cast<DWORD>(std::wcstoul(arguments[5], nullptr, 0));
    const LONGLONG expectedSize = std::wcstoll(arguments[6], nullptr, 0);

    DWORD primaryValue = 0, reloadedValue = 0;
    if (const LSTATUS status = ExecuteQuery(ModeName, subKey, valueName, primaryValue); status != ERROR_SUCCESS)
        return Fail(L"primary-query", status);
    if (const LSTATUS status = ExecuteQuery(L"reload-library", subKey, valueName, reloadedValue); status != ERROR_SUCCESS)
        return Fail(L"reload-query", status);

    UniqueModule execDll(LoadLibraryExW(L"version.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
    UniqueModule dataDll(LoadLibraryExW(L"version.dll", nullptr, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_SEARCH_SYSTEM32));
    if (!execDll || !dataDll) return Fail(L"LoadLibraryExW", static_cast<LSTATUS>(GetLastError()));
    dataDll.reset();
    execDll.reset();

    UniqueHandle file(CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
    if (!file || file.get() == INVALID_HANDLE_VALUE) return Fail(L"CreateFileW", static_cast<LSTATUS>(GetLastError()));
    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file.get(), &fileSize)) return Fail(L"GetFileSizeEx", static_cast<LSTATUS>(GetLastError()));

    const bool matched = primaryValue == expectedValue && reloadedValue == expectedValue && fileSize.QuadPart == expectedSize;
    std::wprintf(L"{\"schemaVersion\":1,\"event\":\"library-loading\",\"mode\":\"%ls\",\"primaryValue\":%lu,"
        L"\"reloadedValue\":%lu,\"fileSize\":%lld,\"matched\":%ls}\n",
        ModeName, static_cast<unsigned long>(primaryValue), static_cast<unsigned long>(reloadedValue),
        fileSize.QuadPart, matched ? L"true" : L"false");
    std::fflush(stdout);
    return matched ? 0 : Fail(L"library-loading-mismatch", ERROR_INVALID_DATA);
}

static int RunChainTest(const int argumentCount, wchar_t* arguments[])
{
    std::wstring mode = ModeName, subKey, valueName, nextExe;
    DWORD expectedValue = 0;
    bool expectedSpecified = false, useCreateProcessA = false, createSuspended = false;
    std::vector<std::wstring> nextArgs;

    for (int i = 2; i < argumentCount; ++i)
    {
        if (wcscmp(arguments[i], L"--mode") == 0 && i + 1 < argumentCount) mode = arguments[++i];
        else if (wcscmp(arguments[i], L"--key") == 0 && i + 1 < argumentCount) subKey = arguments[++i];
        else if (wcscmp(arguments[i], L"--value-name") == 0 && i + 1 < argumentCount) valueName = arguments[++i];
        else if (wcscmp(arguments[i], L"--expected") == 0 && i + 1 < argumentCount)
        {
            expectedValue = static_cast<DWORD>(std::wcstoul(arguments[++i], nullptr, 0));
            expectedSpecified = true;
        }
        else if (wcscmp(arguments[i], L"--use-createprocess-a") == 0) useCreateProcessA = true;
        else if (wcscmp(arguments[i], L"--create-suspended") == 0) createSuspended = true;
        else if (wcscmp(arguments[i], L"--next") == 0 && i + 1 < argumentCount)
        {
            nextExe = arguments[++i];
            nextArgs.assign(arguments + i + 1, arguments + argumentCount);
            break;
        }
    }

    if (subKey.empty() || valueName.empty() || !expectedSpecified)
        return Fail(L"missing-parameters", ERROR_INVALID_PARAMETER);

    DWORD queriedValue = 0;
    if (const LSTATUS status = ExecuteQuery(mode, subKey, valueName, queriedValue); status != ERROR_SUCCESS)
        return Fail(L"ExecuteQuery", status);

    const bool matched = queriedValue == expectedValue;
    std::wprintf(L"{\"schemaVersion\":1,\"event\":\"chain-verification\",\"pid\":%lu,\"arch\":\"%ls\","
        L"\"binaryMode\":\"%ls\",\"requestedMode\":\"%ls\",\"queriedValue\":%lu,\"expectedValue\":%lu,\"matched\":%ls}\n",
        GetCurrentProcessId(), CurrentArchitecture, ModeName, mode.c_str(),
        static_cast<unsigned long>(queriedValue), static_cast<unsigned long>(expectedValue), matched ? L"true" : L"false");
    std::fflush(stdout);
    if (!matched) return Fail(L"value-mismatch", ERROR_INVALID_DATA);
    if (nextExe.empty()) return 0;

    std::vector<std::wstring> fullChildArgs{ nextExe };
    fullChildArgs.insert(fullChildArgs.end(), nextArgs.begin(), nextArgs.end());
    PROCESS_INFORMATION processInfo{};
    const DWORD creationFlags = createSuspended ? CREATE_SUSPENDED : 0;

    if (useCreateProcessA)
    {
        const std::string nextExeA = WideToAnsi(nextExe);
        std::string commandLineA;
        for (const auto& arg : fullChildArgs)
        {
            if (!commandLineA.empty()) commandLineA.push_back(' ');
            commandLineA += QuoteArgument(WideToAnsi(arg));
        }
        STARTUPINFOA startupInfoA{ .cb = sizeof(startupInfoA) };
        InitStdHandles(startupInfoA);
        if (!CreateProcessA(nextExeA.c_str(), commandLineA.data(), nullptr, nullptr, TRUE,
            creationFlags, nullptr, nullptr, &startupInfoA, &processInfo))
            return Fail(L"CreateProcessA", GetLastError());
    }
    else
    {
        std::wstring commandLineW;
        for (const auto& arg : fullChildArgs)
        {
            if (!commandLineW.empty()) commandLineW.push_back(L' ');
            commandLineW += QuoteArgument(arg);
        }
        STARTUPINFOW startupInfoW{ .cb = sizeof(startupInfoW) };
        InitStdHandles(startupInfoW);
        if (!CreateProcessW(nextExe.c_str(), commandLineW.data(), nullptr, nullptr, TRUE,
            creationFlags, nullptr, nullptr, &startupInfoW, &processInfo))
            return Fail(L"CreateProcessW", GetLastError());
    }

    UniqueHandle childProcess(processInfo.hProcess), childThread(processInfo.hThread);
    // The primary thread must retain the caller's suspension until the caller resumes it.
    if (createSuspended && ResumeThread(childThread.get()) != 1)
    {
        TerminateProcess(childProcess.get(), ERROR_INVALID_STATE);
        WaitForSingleObject(childProcess.get(), INFINITE);
        return Fail(L"suspend-count", ERROR_INVALID_STATE);
    }
    WaitForSingleObject(childProcess.get(), INFINITE);
    DWORD childExitCode = MAXDWORD;
    if (!GetExitCodeProcess(childProcess.get(), &childExitCode)) return Fail(L"GetExitCodeProcess", GetLastError());
    return static_cast<int>(childExitCode);
}

struct MitigationProcess final
{
    PROCESS_INFORMATION process{};
    LPPROC_THREAD_ATTRIBUTE_LIST attributes = nullptr;
    std::wstring profile;
    HRESULT(WINAPI* deleteProfile)(PCWSTR) = nullptr;

    ~MitigationProcess()
    {
        if (process.hThread != nullptr) CloseHandle(process.hThread);
        if (process.hProcess != nullptr) CloseHandle(process.hProcess);
        if (attributes != nullptr) DeleteProcThreadAttributeList(attributes);
        if (!profile.empty()) deleteProfile(profile.c_str());
    }
};

static bool HasAppContainerToken(HANDLE process)
{
    HANDLE handle = nullptr;
    if (!OpenProcessToken(process, TOKEN_QUERY, &handle)) return false;
    UniqueHandle token(handle);
    DWORD isAppContainer = 0, length = 0;
    return GetTokenInformation(token.get(), TokenIsAppContainer, &isAppContainer, sizeof(isAppContainer), &length) &&
        isAppContainer != 0;
}

static int LaunchMitigatedProcess(const int argumentCount, wchar_t* arguments[])
{
    const bool strictCfg = wcscmp(arguments[2], L"strict-cfg") == 0;
    const bool dynamicCode = wcscmp(arguments[2], L"dynamic-code") == 0;
    const bool allowOptOut = wcscmp(arguments[2], L"dynamic-code-optout") == 0;
    const bool signedOnly = wcscmp(arguments[2], L"microsoft-signed") == 0;
    const bool appContainer = wcscmp(arguments[2], L"app-container") == 0;
    if (!strictCfg && !dynamicCode && !allowOptOut && !signedOnly && !appContainer)
        return Fail(L"mitigation-name", ERROR_INVALID_PARAMETER);

    DWORD64 mitigation[]{
        strictCfg ? PROCESS_CREATION_MITIGATION_POLICY_CONTROL_FLOW_GUARD_ALWAYS_ON :
        allowOptOut ? PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON_ALLOW_OPT_OUT :
        signedOnly ? PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON :
            PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON,
        strictCfg ? PROCESS_CREATION_MITIGATION_POLICY2_STRICT_CONTROL_FLOW_GUARD_ALWAYS_ON : 0
    };
    SIZE_T attributeBytes = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attributeBytes);
    std::vector<BYTE> attributeStorage(attributeBytes);
    MitigationProcess child;
    auto attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeStorage.data());
    if (!attributes || !InitializeProcThreadAttributeList(attributes, 1, 0, &attributeBytes))
        return Fail(L"InitializeProcThreadAttributeList", GetLastError());
    child.attributes = attributes;

    // AppContainer launches need a registered profile, which is removed after the child exits.
    SECURITY_CAPABILITIES capabilities{};
    if (appContainer)
    {
        const HMODULE userenv = LoadLibraryW(L"userenv.dll");
        const auto createProfile = userenv == nullptr ? nullptr : reinterpret_cast<HRESULT(WINAPI*)(PCWSTR, PCWSTR,
            PCWSTR, PSID_AND_ATTRIBUTES, DWORD, PSID*)>(GetProcAddress(userenv, "CreateAppContainerProfile"));
        child.deleteProfile = userenv == nullptr ? nullptr :
            reinterpret_cast<HRESULT(WINAPI*)(PCWSTR)>(GetProcAddress(userenv, "DeleteAppContainerProfile"));
        if (createProfile == nullptr || child.deleteProfile == nullptr) return Fail(L"userenv", ERROR_PROC_NOT_FOUND);
        const std::wstring profile = L"WinPrivFixture-" + std::to_wstring(GetCurrentProcessId());
        const HRESULT result = createProfile(profile.c_str(), profile.c_str(), profile.c_str(), nullptr, 0,
            &capabilities.AppContainerSid);
        if (FAILED(result)) return Fail(L"CreateAppContainerProfile", static_cast<LSTATUS>(result));
        child.profile = profile;
    }
    if (!UpdateProcThreadAttribute(attributes, 0,
        appContainer ? PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES : PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        appContainer ? static_cast<PVOID>(&capabilities) : static_cast<PVOID>(&mitigation),
        appContainer ? sizeof(capabilities) : sizeof(mitigation), nullptr, nullptr))
        return Fail(L"UpdateProcThreadAttribute", GetLastError());

    std::wstring command;
    for (int index = 3; index < argumentCount; ++index)
    {
        if (!command.empty()) command.push_back(L' ');
        command += QuoteArgument(std::wstring(arguments[index]));
    }

    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    STARTUPINFOEXW startup{};
    startup.StartupInfo.cb = sizeof(startup);
    InitStdHandles(startup.StartupInfo);
    startup.lpAttributeList = attributes;
    if (!CreateProcessW(arguments[3], command.data(), nullptr, nullptr, TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED, nullptr, nullptr, &startup.StartupInfo, &child.process))
        return Fail(L"CreateProcessW", GetLastError());

    PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfg{};
    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY acg{};
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
    const HANDLE process = child.process.hProcess;
    bool enforced = false;
    if (appContainer) enforced = HasAppContainerToken(process);
    else if (strictCfg)
        enforced = GetProcessMitigationPolicy(process, ProcessControlFlowGuardPolicy, &cfg, sizeof(cfg)) &&
            cfg.EnableControlFlowGuard && cfg.StrictMode;
    else if (signedOnly)
        enforced = GetProcessMitigationPolicy(process, ProcessSignaturePolicy, &signature, sizeof(signature)) &&
            signature.MicrosoftSignedOnly;
    else
        enforced = GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy, &acg, sizeof(acg)) &&
            acg.ProhibitDynamicCode && acg.AllowThreadOptOut == allowOptOut;
    std::wprintf(L"{\"schemaVersion\":1,\"mitigation\":\"%ls\",\"enforced\":%ls}\n", arguments[2],
        enforced ? L"true" : L"false");
    std::fflush(stdout);
    if (!enforced)
    {
        TerminateProcess(child.process.hProcess, ERROR_NOT_SUPPORTED);
        WaitForSingleObject(child.process.hProcess, INFINITE);
        return Fail(appContainer ? L"TokenIsAppContainer" : L"GetProcessMitigationPolicy", ERROR_NOT_SUPPORTED);
    }

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
static int QueryDynamicCodeCapability(const bool allowOptOut)
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
    const bool allocated = allocation != nullptr;
    const DWORD allocationError = allocated ? NO_ERROR : GetLastError();
    if (allocated) VirtualFree(allocation, 0, MEM_RELEASE);
    std::wprintf(L"{\"schemaVersion\":1,\"capability\":\"dynamic-code\",\"processDynamicCode\":%lu,"
        L"\"allowThreadOptOut\":%lu,\"allocationSucceeded\":%ls,\"allocationError\":%lu}\n",
        static_cast<DWORD>(policy.ProhibitDynamicCode), static_cast<DWORD>(policy.AllowThreadOptOut),
        allocated ? L"true" : L"false", allocationError);
    return 0;
}

__declspec(noinline) static DWORD WINAPI MitigationOriginal(const DWORD value) { return value * 3 + 7; }
__declspec(noinline) static DWORD WINAPI MitigationReplacement(const DWORD value) { return value * 5 + 11; }

template <size_t Index>
__declspec(noinline) static DWORD WINAPI ThreadOriginal(const DWORD value)
{
    return value * 3 + 7 + static_cast<DWORD>(Index);
}

static constexpr auto ThreadOriginals = []<size_t... Indices>(std::index_sequence<Indices...>)
{
    return std::array{ &ThreadOriginal<Indices>... };
}(std::make_index_sequence<32>{});

struct DetourThreadState final
{
    std::atomic<bool> stop = false;
    std::atomic<DWORD> calls = 0;
    std::atomic<DWORD> invalidValues = 0;
    std::atomic<DWORD> createdThreads = 0;
    HANDLE ready = nullptr;
    HANDLE release = nullptr;
};

static DWORD WINAPI DetourCallWorker(LPVOID parameter)
{
    auto& state = *static_cast<DetourThreadState*>(parameter);
    while (!state.stop.load())
    {
        const size_t index = state.calls.load() % ThreadOriginals.size();
        auto volatile call = ThreadOriginals[index];
        const DWORD value = call(11);
        if (value != 40 + index && value != 66) ++state.invalidValues;
        if (++state.calls % 256 == 0) Sleep(0);
    }
    return NO_ERROR;
}

static DWORD WINAPI DetourChurnWorker(LPVOID parameter)
{
    auto& state = *static_cast<DetourThreadState*>(parameter);
    while (!state.stop.load())
    {
        UniqueHandle child(CreateThread(nullptr, 0, [](LPVOID context) -> DWORD {
            auto& shared = *static_cast<DetourThreadState*>(context);
            for (DWORD iteration = 0; iteration < 256; ++iteration)
            {
                const size_t index = iteration % ThreadOriginals.size();
                auto volatile call = ThreadOriginals[index];
                const DWORD value = call(11);
                if (value != 40 + index && value != 66) ++shared.invalidValues;
                ++shared.calls;
            }
            return NO_ERROR;
        }, parameter, 0, nullptr));
        if (!child) return GetLastError();
        ++state.createdThreads;
        if (WaitForSingleObject(child.get(), INFINITE) != WAIT_OBJECT_0) return GetLastError();
    }
    return NO_ERROR;
}

static DWORD WINAPI DetourHeapWorker(LPVOID parameter)
{
    auto& state = *static_cast<DetourThreadState*>(parameter);
    if (!HeapLock(GetProcessHeap())) return GetLastError();
    SetEvent(state.ready);
    WaitForSingleObject(state.release, INFINITE);
    return HeapUnlock(GetProcessHeap()) ? NO_ERROR : GetLastError();
}

static int TestThreadEnumeration(const wchar_t* scenario)
{
    const bool churn = wcscmp(scenario, L"churn") == 0;
    const bool heapLock = wcscmp(scenario, L"heap-lock") == 0;
    const bool inaccessible = wcscmp(scenario, L"inaccessible") == 0;
    if (!churn && !heapLock && !inaccessible) return Fail(L"thread-scenario", ERROR_INVALID_PARAMETER);

    if (inaccessible)
    {
        const DWORD rollbackError = TestDetourContextRollback();
        if (rollbackError != NO_ERROR) return Fail(L"context-rollback", rollbackError);

        // Disable inherited debug access so the empty thread DACL is enforced for every runner token.
        UniqueModule security(LoadLibraryW(L"advapi32.dll"));
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
        UniqueHandle token(rawToken);
        TOKEN_PRIVILEGES privileges{ .PrivilegeCount = 1 };
        if (!lookupPrivilege(nullptr, SE_DEBUG_NAME, &privileges.Privileges[0].Luid) ||
            !adjustPrivileges(token.get(), FALSE, &privileges, 0, nullptr, nullptr))
            return Fail(L"DisableDebugPrivilege", GetLastError());
        const DWORD error = GetLastError();
        if (error != NO_ERROR && error != ERROR_NOT_ALL_ASSIGNED) return Fail(L"DisableDebugPrivilege", error);
    }

    UniqueHandle ready(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    UniqueHandle release(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!ready || !release) return Fail(L"CreateEventW", GetLastError());
    DetourThreadState state{ .ready = ready.get(), .release = release.get() };
    std::vector<UniqueHandle> workers;
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

    // Keep peers executing the patched function throughout hook publication.
    for (DWORD index = 0; index < 4; ++index)
    {
        workers.emplace_back(CreateThread(nullptr, 0, DetourCallWorker, &state, 0, nullptr));
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
    workers.emplace_back(CreateThread(inaccessible ? &attributes : nullptr, 0, worker, &state, 0, &peerId));
    if (!workers.back()) return fail(L"CreateThread", GetLastError());
    if (heapLock && WaitForSingleObject(ready.get(), 5000) != WAIT_OBJECT_0) return fail(L"HeapLock", ERROR_TIMEOUT);
    if (inaccessible)
    {
        UniqueHandle denied(OpenThread(THREAD_SUSPEND_RESUME, FALSE, peerId));
        if (denied || GetLastError() != ERROR_ACCESS_DENIED) return fail(L"thread-access", ERROR_INVALID_DATA);
    }

    auto targets = ThreadOriginals;
    LONG commitError = NO_ERROR;
    DWORD iterations = 0;
    for (; iterations < targets.size(); ++iterations)
    {
        winpriv::detours::transaction transaction;
        transaction.attach(targets[iterations], MitigationReplacement);
        commitError = transaction.commit();
        if (commitError != NO_ERROR) break;
        auto volatile call = ThreadOriginals[iterations];
        if (call(11) != 66 || targets[iterations](11) != 40 + iterations) ++state.invalidValues;
    }
    auto volatile call = ThreadOriginals[0];
    const LONG joined = stopWorkers();
    if (joined != NO_ERROR) return Fail(L"join-workers", joined);
    std::wprintf(L"{\"schemaVersion\":1,\"scenario\":\"%ls\",\"iterations\":%lu,\"commitError\":%ld,"
        L"\"calls\":%lu,\"createdThreads\":%lu,\"invalidValues\":%lu,\"originalPointer\":%ls,\"finalValue\":%lu}\n",
        scenario, iterations, commitError, state.calls.load(), state.createdThreads.load(), state.invalidValues.load(),
        targets[0] == ThreadOriginals[0] ? L"true" : L"false", call(11));
    return 0;
}

static int TestRejectedDetours()
{
    // A rejected operation must abort every staged hook and preserve the original code and pointer.
    DWORD cases = 0;
    for (DWORD invalid = 0; invalid < 4; ++invalid)
    {
        auto target = &MitigationOriginal;
        winpriv::detours::transaction transaction;
        transaction.attach(target, MitigationReplacement);
        const LONG attached = transaction.error();
        decltype(target) missing = nullptr;
        if (invalid == 0) transaction.attach(target, static_cast<decltype(target)>(nullptr));
        else if (invalid == 1) transaction.attach(missing, MitigationReplacement);
        else transaction.attach(target, MitigationReplacement,
            invalid == 2 ? L"WinPrivMissingHookLibrary.dll" : L"kernel32.dll", "WinPrivMissingHookExport");
        const LONG rejected = transaction.error();
        auto skipped = ThreadOriginals[0];
        transaction.attach(skipped, MitigationReplacement);
        const LONG committed = transaction.commit();
        auto volatile call = &MitigationOriginal;
        constexpr LONG errors[]{
            ERROR_INVALID_PARAMETER, ERROR_INVALID_HANDLE, ERROR_MOD_NOT_FOUND, ERROR_PROC_NOT_FOUND };
        if (attached != NO_ERROR || rejected != errors[invalid] ||
            committed != rejected || transaction.error() != rejected || target != &MitigationOriginal ||
            skipped != ThreadOriginals[0] || call(11) != 40 || skipped(11) != 40)
            return Fail(L"invalid-transaction", ERROR_INVALID_DATA);
        ++cases;
    }

    // Completed transactions reject further attachments without reacquiring ownership.
    {
        auto target = &MitigationOriginal;
        winpriv::detours::transaction transaction;
        if (transaction.commit() != NO_ERROR || transaction.commit() != NO_ERROR)
            return Fail(L"empty-transaction", ERROR_INVALID_DATA);
        transaction.attach(target, MitigationReplacement);
        if (transaction.error() != ERROR_INVALID_OPERATION || transaction.commit() != ERROR_INVALID_OPERATION ||
            target != &MitigationOriginal)
            return Fail(L"completed-transaction", ERROR_INVALID_DATA);
        ++cases;
    }
#if defined(_M_IX86) || defined(_M_X64)
    // LOOP has no longer displacement form; reserved opcodes also cannot produce a valid trampoline.
    for (const auto& code : { std::array<BYTE, 8>{ 0xe2, 0x00, 0xb8, 42, 0, 0, 0, 0xc3 },
        std::array<BYTE, 8>{ 0x0f, 0x04, 0x90, 0x90, 0x90, 0x90, 0x90, 0xc3 } })
    {
        const auto release = [](PVOID memory) { VirtualFree(memory, 0, MEM_RELEASE); };
        std::unique_ptr<void, decltype(release)> memory(
            VirtualAlloc(nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE), release);
        if (!memory) return Fail(L"VirtualAlloc", GetLastError());
        memcpy(memory.get(), code.data(), code.size());
        DWORD previous = 0;
        if (!VirtualProtect(memory.get(), 4096, PAGE_EXECUTE_READ, &previous) ||
            !FlushInstructionCache(GetCurrentProcess(), memory.get(), code.size()))
            return Fail(L"prepare-code", GetLastError());
        auto target = reinterpret_cast<decltype(&MitigationOriginal)>(memory.get());
        winpriv::detours::transaction transaction;
        transaction.attach(target, MitigationReplacement);
        const LONG rejected = transaction.error();
        const LONG committed = transaction.commit();
        MEMORY_BASIC_INFORMATION information{};
        if (rejected != ERROR_INVALID_BLOCK || committed != rejected ||
            reinterpret_cast<PVOID>(target) != memory.get() ||
            memcmp(memory.get(), code.data(), code.size()) != 0 ||
            VirtualQuery(memory.get(), &information, sizeof(information)) != sizeof(information) ||
            information.Protect != PAGE_EXECUTE_READ)
            return Fail(L"unsupported-relocation", ERROR_INVALID_DATA);
        ++cases;
    }
#endif
    std::wprintf(L"{\"schemaVersion\":1,\"rejectedCases\":%lu}\n", cases);
    return 0;
}

static int TestDynamicCodeAllocation()
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
    if (transaction.error() != NO_ERROR) return Fail(L"begin-transaction", transaction.error());
    transaction.attach(target, MitigationReplacement);
    const LONG attach = transaction.error();
    const LONG commit = transaction.commit();
    std::wprintf(L"{\"schemaVersion\":1,\"mitigation\":\"dynamic-code\",\"enforced\":true,"
        L"\"attachError\":%ld,\"commitError\":%ld,\"originalPointer\":%ls,\"value\":%lu}\n",
        attach, commit, target == &MitigationOriginal ? L"true" : L"false", target(11));
    return 0;
}

static int TestDynamicCodeOptOut(const wchar_t* scenario)
{
    const bool abort = wcscmp(scenario, L"abort") == 0;
    const bool failedCommit = wcscmp(scenario, L"failed-commit") == 0;
    const bool nested = wcscmp(scenario, L"nested") == 0;
    const bool preexisting = wcscmp(scenario, L"preexisting") == 0;
    if (!abort && !failedCommit && !nested && !preexisting && wcscmp(scenario, L"attach") != 0)
        return Fail(L"optout-scenario", ERROR_INVALID_PARAMETER);

    PROCESS_MITIGATION_DYNAMIC_CODE_POLICY policy{};
    policy.ProhibitDynamicCode = 1;
    policy.AllowThreadOptOut = 1;
    if (!SetProcessMitigationPolicy(ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"SetProcessMitigationPolicy", GetLastError());
    if (preexisting)
    {
        DWORD allowed = THREAD_DYNAMIC_CODE_ALLOW;
        if (!SetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &allowed, sizeof(allowed)))
            return Fail(L"SetThreadInformation", GetLastError());
    }
    const auto readThreadPolicy = [](DWORD& value) {
        return GetThreadInformation(GetCurrentThread(), ThreadDynamicCodePolicy, &value, sizeof(value)) != FALSE;
    };

    DWORD threadBefore = 0, threadDuring = MAXDWORD, threadAfterNested = MAXDWORD;
    DWORD threadAfterCommit = MAXDWORD, threadAfterScope = MAXDWORD;
    if (!readThreadPolicy(threadBefore)) return Fail(L"GetThreadInformation", GetLastError());

    auto target = &MitigationOriginal;
    auto volatile call = &MitigationOriginal;
    LONG attach = ERROR_INVALID_OPERATION, commit = ERROR_INVALID_OPERATION;
    LONG invalidApply = NO_ERROR, nestedCommit = NO_ERROR;
    bool nestedActive = false;
    {
        winpriv::detours::transaction transaction;
        if (transaction.error() != NO_ERROR) return Fail(L"begin-transaction", transaction.error());
        if (!readThreadPolicy(threadDuring)) return Fail(L"GetThreadInformation", GetLastError());
        if (nested)
        {
            {
                winpriv::detours::transaction inner;
                nestedActive = inner.error() == NO_ERROR;
                inner.attach(target, MitigationReplacement);
                nestedCommit = inner.commit();
            }
            if (!readThreadPolicy(threadAfterNested)) return Fail(L"GetThreadInformation", GetLastError());
        }
        transaction.attach(target, MitigationReplacement);
        attach = transaction.error();
        if (failedCommit)
        {
            decltype(target) missing = nullptr;
            transaction.attach(missing, MitigationReplacement);
            invalidApply = transaction.error();
        }
        if (!abort)
        {
            commit = transaction.commit();
            if (!readThreadPolicy(threadAfterCommit)) return Fail(L"GetThreadInformation", GetLastError());
        }
    }
    if (!readThreadPolicy(threadAfterScope)) return Fail(L"GetThreadInformation", GetLastError());
    const DWORD hookedValue = call(11), trampolineValue = target(11);
    if (!GetProcessMitigationPolicy(GetCurrentProcess(), ProcessDynamicCodePolicy, &policy, sizeof(policy)))
        return Fail(L"query-final-policy", GetLastError());
    std::wprintf(L"{\"schemaVersion\":1,\"scenario\":\"%ls\",\"processDynamicCode\":%lu,\"allowThreadOptOut\":%lu,"
        L"\"threadBefore\":%lu,\"threadDuring\":%lu,\"threadAfterNested\":%lu,\"threadAfterCommit\":%lu,"
        L"\"threadAfterScope\":%lu,\"attachError\":%ld,\"commitError\":%ld,\"invalidApplyError\":%ld,"
        L"\"nestedActive\":%ls,\"nestedCommitError\":%ld,"
        L"\"hookedValue\":%lu,\"trampolineValue\":%lu,\"originalPointer\":%ls}\n",
        scenario, static_cast<DWORD>(policy.ProhibitDynamicCode), static_cast<DWORD>(policy.AllowThreadOptOut),
        threadBefore, threadDuring, threadAfterNested, threadAfterCommit, threadAfterScope,
        attach, commit, invalidApply, nestedActive ? L"true" : L"false", nestedCommit, hookedValue, trampolineValue,
        target == &MitigationOriginal ? L"true" : L"false");
    return 0;
}
#endif

int wmain(const int argumentCount, wchar_t* arguments[])
{
    if (argumentCount == 2 && wcscmp(arguments[1], L"--optional-hook-libraries") == 0)
    {
        // Inspect dependencies before the fixture invokes any optional feature APIs.
        std::wprintf(L"{\"odbc\":%ls,\"amsi\":%ls,\"wldp\":%ls}\n",
            GetModuleHandleW(L"odbc32.dll") != nullptr ? L"true" : L"false",
            GetModuleHandleW(L"amsi.dll") != nullptr ? L"true" : L"false",
            GetModuleHandleW(L"wldp.dll") != nullptr ? L"true" : L"false");
        return 0;
    }
#if defined(WINPRIV_LOADING_MODE_DYNAMIC)
    if (argumentCount == 2 && wcscmp(arguments[1], L"--smartcard-session-routing") == 0) return TestSmartCardSessionRouting();
    if (argumentCount == 2 && wcscmp(arguments[1], L"--smartcard-enrollment") == 0) return TestSmartCardEnrollment();
    if (argumentCount == 2 && wcscmp(arguments[1], L"--process-logon") == 0) return TestProcessLogon();
    if (argumentCount == 2 && wcscmp(arguments[1], L"--process-control") == 0) return TestProcessControl();
    if (argumentCount == 2 && wcscmp(arguments[1], L"--privilege-enumeration") == 0) return TestPrivilegeEnumeration();
    if (argumentCount == 2 && wcscmp(arguments[1], L"--rejected-detours") == 0) return TestRejectedDetours();
#if defined(_M_ARM64)
    if (argumentCount == 2 && wcscmp(arguments[1], L"--arm64-branches") == 0)
    {
        const DWORD error = TestDetourArm64Branches();
        return error == NO_ERROR ? 0 : Fail(L"arm64-branches", error);
    }
#endif
#endif
    if (argumentCount >= 2 && wcscmp(arguments[1], L"--library-loading") == 0)
        return TestLibraryLoading(argumentCount, arguments);
    if (argumentCount == 2 && wcscmp(arguments[1], L"--hook-exceptions") == 0)
    {
        // Exercise repeated C++ unwinding inside the hooks while unrelated application exceptions still work.
        UniqueModule odbc(LoadLibraryW(L"odbc32.dll"));
        if (!odbc) return Fail(L"load-odbc", GetLastError());
        const auto allocate = reinterpret_cast<decltype(&SQLAllocHandle)>(GetProcAddress(odbc.get(), "SQLAllocHandle"));
        const auto release = reinterpret_cast<decltype(&SQLFreeHandle)>(GetProcAddress(odbc.get(), "SQLFreeHandle"));
        const auto setEnvironment = reinterpret_cast<decltype(&SQLSetEnvAttr)>(GetProcAddress(odbc.get(), "SQLSetEnvAttr"));
        const auto connect = reinterpret_cast<decltype(&SQLDriverConnectW)>(GetProcAddress(odbc.get(), "SQLDriverConnectW"));
        if (!allocate || !release || !setEnvironment || !connect) return Fail(L"odbc-exports", ERROR_PROC_NOT_FOUND);
        std::atomic<int> completed = 0;
        std::vector<std::thread> threads;
        for (int thread = 0; thread < 4; ++thread)
        {
            threads.emplace_back([&]
            {
                SQLHENV environment = nullptr;
                SQLHDBC connection = nullptr;
                if (!SQL_SUCCEEDED(allocate(SQL_HANDLE_ENV, SQL_NULL_HANDLE, &environment))) return;
                if (SQL_SUCCEEDED(setEnvironment(environment, SQL_ATTR_ODBC_VERSION,
                    reinterpret_cast<SQLPOINTER>(SQL_OV_ODBC3), 0)) &&
                    SQL_SUCCEEDED(allocate(SQL_HANDLE_DBC, environment, &connection)))
                {
                    for (int iteration = 0; iteration < 25; ++iteration)
                    {
                        WCHAR text[] = L"Driver={WinPrivMissing};Server=ORIGINAL;";
                        if (connect(connection, nullptr, text, SQL_NTS, nullptr, 0, nullptr,
                            SQL_DRIVER_NOPROMPT) != SQL_ERROR) break;
                        try
                        {
                            try { throw iteration; }
                            catch (...) { throw; }
                        }
                        catch (int value)
                        {
                            if (value == iteration) ++completed;
                        }
                    }
                    release(SQL_HANDLE_DBC, connection);
                }
                release(SQL_HANDLE_ENV, environment);
            });
        }
        for (auto& thread : threads) thread.join();
        std::wprintf(L"{\"completed\":%d}\n", completed.load());
        return completed == 100 ? 0 : Fail(L"exception-recovery", ERROR_INVALID_STATE);
    }

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
        if (_wfopen_s(&output, arguments[2], L"w") != 0 || output == nullptr)
            return Fail(L"startup-output", ERROR_OPEN_FAILED);
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
        std::fwprintf(stderr, L"Usage: %ls <HKCU-subkey> <value-name>\n", arguments[0]);
        return 2;
    }

    DWORD value = 0;
    if (const LSTATUS status = ExecuteQuery(ModeName, arguments[descendant ? 2 : 1], arguments[descendant ? 3 : 2], value);
        status != ERROR_SUCCESS)
        return Fail(L"ExecuteQuery", status);

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
