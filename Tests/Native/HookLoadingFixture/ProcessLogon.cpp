#include "../../../WinPrivLibrary/WinPrivLibrary.h"

#define _NTDEF_
using PNTSTATUS = NTSTATUS*;
#include <NTSecAPI.h>
#include <cstdio>

static struct
{
    DWORD firstError, retryError;
    NTSTATUS enumerateStatus, grantStatus, revokeStatus;
    bool assigned, createFails, extended, explicitDesktop, parametersValid;
    DWORD logons, grants, revokes, creates, closes;
} state{};

static BOOL WINAPI TestLogon(LPCWSTR user, LPCWSTR domain, LPCWSTR password, DWORD type,
    DWORD provider, PHANDLE token)
{
    state.parametersValid &= wcscmp(user, L"user") == 0 && wcscmp(domain, L"domain") == 0 &&
        wcscmp(password, L"password") == 0 && type == LOGON32_LOGON_INTERACTIVE &&
        provider == LOGON32_PROVIDER_DEFAULT;
    const DWORD error = ++state.logons == 1 ? state.firstError : state.retryError;
    if (error == ERROR_SUCCESS) *token = reinterpret_cast<HANDLE>(1);
    SetLastError(error);
    return error == ERROR_SUCCESS;
}

static BOOL WINAPI TestLookup(LPCWSTR, LPCWSTR account, PSID sid, LPDWORD sidSize,
    LPWSTR domain, LPDWORD domainSize, PSID_NAME_USE)
{
    state.parametersValid &= wcscmp(account, L"domain\\user") == 0;
    *sidSize = SECURITY_MAX_SID_SIZE;
    *domainSize = 2;
    if (sid != nullptr && domain != nullptr) return TRUE;
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return FALSE;
}

static NTSTATUS NTAPI TestOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES,
    ACCESS_MASK access, PLSA_HANDLE policy)
{
    state.parametersValid &= access == (POLICY_LOOKUP_NAMES | POLICY_CREATE_ACCOUNT);
    *policy = reinterpret_cast<LSA_HANDLE>(2);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TestEnumerate(LSA_HANDLE, PSID, PLSA_UNICODE_STRING* rights, PULONG count)
{
    static WCHAR name[] = L"seinteractivelogonright";
    static LSA_UNICODE_STRING right{ sizeof(name) - sizeof(WCHAR), sizeof(name), name };
    *rights = state.assigned ? &right : nullptr;
    *count = state.assigned ? 1u : 0u;
    return state.enumerateStatus;
}

static NTSTATUS NTAPI TestGrant(LSA_HANDLE, PSID, PLSA_UNICODE_STRING right, ULONG count)
{
    state.parametersValid &= count == 1 && wcscmp(right->Buffer, SE_INTERACTIVE_LOGON_NAME) == 0;
    ++state.grants;
    return state.grantStatus;
}

static NTSTATUS NTAPI TestRevoke(LSA_HANDLE, PSID, BOOLEAN all, PLSA_UNICODE_STRING right, ULONG count)
{
    state.parametersValid &= !all && count == 1 && wcscmp(right->Buffer, SE_INTERACTIVE_LOGON_NAME) == 0;
    ++state.revokes;
    return state.revokeStatus;
}

static NTSTATUS NTAPI TestPolicyCleanup(PVOID)
{
    SetLastError(ERROR_INVALID_HANDLE);
    return STATUS_SUCCESS;
}

static BOOL WINAPI TestClose(HANDLE)
{
    ++state.closes;
    SetLastError(ERROR_INVALID_HANDLE);
    return TRUE;
}

static BOOL WINAPI TestCreate(HANDLE token, DWORD flags, LPCWSTR application, LPWSTR command,
    DWORD creationFlags, LPVOID environment, LPCWSTR directory, LPSTARTUPINFOW startup,
    LPPROCESS_INFORMATION process)
{
    ++state.creates;
    state.parametersValid &= token == reinterpret_cast<HANDLE>(1) && flags == LOGON_WITH_PROFILE &&
        wcscmp(application, L"application") == 0 && wcscmp(command, L"command") == 0 &&
        creationFlags == (CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
            (state.extended ? EXTENDED_STARTUPINFO_PRESENT : 0u)) &&
        environment == reinterpret_cast<PVOID>(3) && wcscmp(directory, L"directory") == 0 &&
        wcscmp(startup->lpDesktop, state.explicitDesktop ? L"WinSta0\\Default" : L"Default") == 0 &&
        startup->dwFlags == STARTF_USESHOWWINDOW && startup->wShowWindow == SW_HIDE && process != nullptr;
    if (state.extended)
        state.parametersValid &= reinterpret_cast<LPSTARTUPINFOEXW>(startup)->lpAttributeList ==
            reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(4);
    SetLastError(state.createFails ? ERROR_FILE_NOT_FOUND : ERROR_SUCCESS);
    return !state.createFails;
}

// Exercise policy and handle cleanup failures without changing the workstation's accounts or rights.
#define LogonUserW TestLogon
#define LookupAccountNameW TestLookup
#define LsaOpenPolicy TestOpenPolicy
#define LsaEnumerateAccountRights TestEnumerate
#define LsaAddAccountRights TestGrant
#define LsaRemoveAccountRights TestRevoke
#define LsaClose TestPolicyCleanup
#define LsaFreeMemory TestPolicyCleanup
#define CloseHandle TestClose
#define CreateProcessWithTokenW TestCreate
#include "../../../WinPrivLibrary/WinPrivLibraryLogon.cpp"
#undef LogonUserW
#undef LookupAccountNameW
#undef LsaOpenPolicy
#undef LsaEnumerateAccountRights
#undef LsaAddAccountRights
#undef LsaRemoveAccountRights
#undef LsaClose
#undef LsaFreeMemory
#undef CloseHandle
#undef CreateProcessWithTokenW

int TestProcessLogon()
{
    const struct
    {
        DWORD firstError, retryError;
        NTSTATUS enumerateStatus, grantStatus, revokeStatus;
        bool assigned, createFails;
        DWORD expectedError, logons, grants, revokes, creates;
    } cases[] = {
        { 0, 0, 0, 0, 0, false, false, 0, 1, 0, 0, 1 },
        { ERROR_LOGON_FAILURE, 0, 0, 0, 0, false, false, ERROR_LOGON_FAILURE, 1, 0, 0, 0 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, 0, STATUS_OBJECT_NAME_NOT_FOUND, 0, 0,
            false, false, 0, 2, 1, 0, 1 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, ERROR_LOGON_TYPE_NOT_GRANTED, 0, 0, 0,
            false, false, ERROR_LOGON_TYPE_NOT_GRANTED, 2, 1, 1, 0 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, 0, 0, 0, 0, true, false, ERROR_LOGON_TYPE_NOT_GRANTED, 1, 0, 0, 0 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, 0, STATUS_ACCESS_DENIED, 0, 0,
            false, false, ERROR_ACCESS_DENIED, 1, 0, 0, 0 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, 0, 0, STATUS_ACCESS_DENIED, 0,
            false, false, ERROR_ACCESS_DENIED, 1, 1, 0, 0 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, ERROR_LOGON_FAILURE, 0, 0, 0,
            false, false, ERROR_LOGON_FAILURE, 2, 1, 1, 0 },
        { ERROR_LOGON_TYPE_NOT_GRANTED, ERROR_LOGON_TYPE_NOT_GRANTED, 0, 0, STATUS_ACCESS_DENIED,
            false, false, ERROR_ACCESS_DENIED, 2, 1, 1, 0 },
        { 0, 0, 0, 0, 0, false, true, ERROR_FILE_NOT_FOUND, 1, 0, 0, 1 },
    };

    // Cover ordinary and extended startup information, plus inherited and explicit desktops.
    for (const auto& test : cases)
    {
        for (DWORD mode = 0; mode < 4; ++mode)
        {
            state = { test.firstError, test.retryError, test.enumerateStatus, test.grantStatus, test.revokeStatus,
                test.assigned, test.createFails, (mode & 1) != 0, (mode & 2) != 0, true };
            STARTUPINFOEXW startup{};
            startup.StartupInfo.cb = static_cast<DWORD>(state.extended ? sizeof(startup) : sizeof(STARTUPINFOW));
            startup.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;
            startup.StartupInfo.wShowWindow = SW_HIDE;
            WCHAR desktop[] = L"WinSta0\\Default";
            startup.StartupInfo.lpDesktop = state.explicitDesktop ? desktop : nullptr;
            startup.lpAttributeList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(4);
            PROCESS_INFORMATION process{};
            WCHAR command[] = L"command";
            const BOOL created = DetourCreateProcessWithLogonW(L"user", L"domain", L"password",
                LOGON_WITH_PROFILE, L"application", command, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT |
                (state.extended ? EXTENDED_STARTUPINFO_PRESENT : 0u), reinterpret_cast<PVOID>(3), L"directory",
                &startup.StartupInfo, &process);
            if (created != (test.expectedError == 0) || GetLastError() != test.expectedError ||
                !state.parametersValid || state.logons != test.logons || state.grants != test.grants ||
                state.revokes != test.revokes || state.creates != test.creates || state.closes != test.creates ||
                startup.StartupInfo.lpDesktop != (state.explicitDesktop ? desktop : nullptr))
            {
                std::fwprintf(stderr, L"Process logon failed: first error %lu, mode %lu, last error %lu.\n",
                    test.firstError, mode, GetLastError());
                return 1;
            }
        }
    }

    // Reject unsupported modes and malformed startup information before authenticating or changing policy.
    state = {};
    STARTUPINFOW startup{ sizeof(startup) };
    PROCESS_INFORMATION process{};
    if (DetourCreateProcessWithLogonW(L"user", nullptr, nullptr, LOGON_NETCREDENTIALS_ONLY,
        nullptr, nullptr, 0, nullptr, nullptr, &startup, &process) ||
        GetLastError() != ERROR_INVALID_PARAMETER || state.logons != 0) return 1;
    if (DetourCreateProcessWithLogonW(L"user", nullptr, nullptr, 0, nullptr, nullptr,
        EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr, &startup, &process) ||
        GetLastError() != ERROR_INVALID_PARAMETER || state.logons != 0) return 1;
    std::wprintf(L"{\"schemaVersion\":1,\"logonCases\":%zu}\n", ARRAYSIZE(cases) * 4 + 2);
    return 0;
}
