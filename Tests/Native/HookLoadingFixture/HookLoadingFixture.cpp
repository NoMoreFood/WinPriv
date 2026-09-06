#include <windows.h>

#include <cstdio>
#include <cwchar>
#include <iterator>
#include <string>
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
__declspec(noinline) DWORD WINAPI MitigationOriginal(const DWORD value)
{
    return value * 3 + 7;
}

__declspec(noinline) DWORD WINAPI MitigationReplacement(const DWORD value)
{
    return value * 5 + 11;
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
    if (argumentCount == 2 && wcscmp(arguments[1], L"--dynamic-code-allocation") == 0)
        return TestDynamicCodeAllocation();
    if (argumentCount == 3 && wcscmp(arguments[1], L"--dynamic-code-optout") == 0)
        return TestDynamicCodeOptOut(arguments[2]);
#endif

    if (argumentCount >= 4 && wcscmp(arguments[1], L"--launch-mitigation") == 0)
        return LaunchMitigatedProcess(argumentCount, arguments);

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
