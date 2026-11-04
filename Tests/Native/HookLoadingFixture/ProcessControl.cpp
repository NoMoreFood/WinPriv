#define UMDF_USING_NTSTATUS
#include <ntstatus.h>
#include "../../../WinPrivShared/WinPrivShared.h"
#include <winternl.h>
#define _NTDEF_
using PNTSTATUS = NTSTATUS*;
#include <ntlsa.h>
#include <TlHelp32.h>
#include <cstdio>

static std::wstring processName;
static DWORD terminationAttempts, sessionQueries;
static bool changedName, changedSession, queryFails;
static int privilegeScenario, policyCloses, privilegePagesFreed;

static NTSTATUS NTAPI TestOpenPolicy(PLSA_UNICODE_STRING, PLSA_OBJECT_ATTRIBUTES, ACCESS_MASK, PLSA_HANDLE policy)
{
    if (privilegeScenario == 1) return STATUS_ACCESS_DENIED;
    *policy = reinterpret_cast<HANDLE>(1);
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TestClosePolicy(LSA_HANDLE)
{
    ++policyCloses;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TestFreePolicyMemory(PVOID)
{
    ++privilegePagesFreed;
    return STATUS_SUCCESS;
}

static NTSTATUS NTAPI TestEnumeratePrivileges(LSA_HANDLE, PLSA_ENUMERATION_HANDLE context,
    PVOID* buffer, ULONG, PULONG count)
{
    *buffer = nullptr;
    *count = 0;
    if (privilegeScenario == 2 && *context == 1) return STATUS_ACCESS_DENIED;
    if (*context == 2) return STATUS_NO_MORE_ENTRIES;
    static WCHAR first[] = L"SeFirstPrivilege", second[] = L"SeSecondPrivilege";
    static POLICY_PRIVILEGE_DEFINITION page{};
    const auto name = *context == 0 ? second : first;
    page.Name = { static_cast<USHORT>(wcslen(name) * sizeof(WCHAR)),
        static_cast<USHORT>((wcslen(name) + 1) * sizeof(WCHAR)), name };
    *buffer = &page;
    *count = 1;
    return ++*context == 1 ? STATUS_MORE_ENTRIES : STATUS_SUCCESS;
}

static BOOL WINAPI TestProcessFirst(HANDLE, LPPROCESSENTRY32W entry)
{
    entry->th32ProcessID = GetCurrentProcessId();
    entry->th32ParentProcessID = entry->th32ProcessID;
    wcscpy_s(entry->szExeFile, changedName ? L"reused-process-id.exe" : processName.c_str());
    return TRUE;
}

static BOOL WINAPI TestProcessNext(HANDLE, LPPROCESSENTRY32W)
{
    return FALSE;
}

static BOOL WINAPI TestProcessSession(DWORD processId, DWORD* session)
{
    if (!ProcessIdToSessionId(processId, session)) return FALSE;
    if (changedSession && ++sessionQueries > 1) ++*session;
    return TRUE;
}

BOOL WINAPI TestProcessImage(HANDLE process, DWORD flags, LPWSTR image, PDWORD size)
{
    return !queryFails && QueryFullProcessImageNameW(process, flags, image, size);
}

static BOOL WINAPI TestTerminate(HANDLE, UINT)
{
    ++terminationAttempts;
    return TRUE;
}

static DWORD WINAPI TestWait(HANDLE, DWORD)
{
    return WAIT_OBJECT_0;
}

// Simulate an obsolete process snapshot while querying a real, safely retained process handle.
#define Process32FirstW TestProcessFirst
#define Process32NextW TestProcessNext
#define ProcessIdToSessionId TestProcessSession
#define QueryFullProcessImageNameW TestProcessImage
#define TerminateProcess TestTerminate
#define WaitForSingleObject TestWait
#define LsaOpenPolicy TestOpenPolicy
#define LsaClose TestClosePolicy
#define LsaFreeMemory TestFreePolicyMemory
#define LsaEnumeratePrivileges TestEnumeratePrivileges
#include "../../../WinPrivShared/WinPrivShared.cpp"
#undef Process32FirstW
#undef Process32NextW
#undef ProcessIdToSessionId
#undef QueryFullProcessImageNameW
#undef TerminateProcess
#undef WaitForSingleObject
#undef LsaOpenPolicy
#undef LsaClose
#undef LsaFreeMemory
#undef LsaEnumeratePrivileges

int TestPrivilegeEnumeration()
{
    // Incomplete policy queries must fail instead of returning an apparently complete privilege list.
    for (privilegeScenario = 0; privilegeScenario < 3; ++privilegeScenario)
    {
        policyCloses = privilegePagesFreed = 0;
        const auto privileges = GetPrivilegeNames();
        if (privilegeScenario == 0)
        {
            if (!privileges || *privileges != std::vector<std::wstring>{ L"SeFirstPrivilege", L"SeSecondPrivilege" })
                return 1;
        }
        else if (privileges) return 2;
        if (policyCloses != (privilegeScenario == 1 ? 0 : 1) ||
            privilegePagesFreed != (privilegeScenario == 0 ? 2 : privilegeScenario == 1 ? 0 : 1)) return 3;
    }
    std::wprintf(L"{\"privilegeEnumerationCases\":3}\n");
    return 0;
}

int TestProcessControl()
{
    std::wstring image(32768, L'\0');
    DWORD size = static_cast<DWORD>(image.size()), session = 0;
    if (!QueryFullProcessImageNameW(GetCurrentProcess(), 0, image.data(), &size) ||
        !ProcessIdToSessionId(GetCurrentProcessId(), &session)) return 1;
    processName = wcsrchr(image.c_str(), L'\\') + 1;
    for (int scenario = 0; scenario < 4; ++scenario)
    {
        terminationAttempts = sessionQueries = 0;
        changedName = scenario == 1;
        changedSession = scenario == 2;
        queryFails = scenario == 3;
        KillProcesses({ changedName ? L"reused-process-id.exe" : processName }, session);
        if (terminationAttempts != (scenario == 0 ? 1u : 0u))
        {
            std::printf("{\"failedScenario\":%d,\"terminationAttempts\":%lu}\n", scenario, terminationAttempts);
            return 1;
        }
    }
    std::puts("{\"processControlCases\":4}");
    return 0;
}
