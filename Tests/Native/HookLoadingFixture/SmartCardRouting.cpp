#include "../../../WinPrivLibrary/WinPrivLibrary.h"
#include <ncrypt.h>
#include <objbase.h>
#include <wtsapi32.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ole32.lib")

static USHORT iProtocol = 0;
static BOOL bQuerySuccess = TRUE;
static DWORD iProtocolSize = sizeof(iProtocol);
static bool bNullProtocol = false;
static DWORD iSessionQueries = 0;
static DWORD iSigningCalls = 0;
static DWORD iSigningFlags = 0;

static BOOL WINAPI QuerySession(HANDLE hServer, DWORD iSession, WTS_INFO_CLASS eClass,
    LPWSTR* pBuffer, DWORD* pSize)
{
    ++iSessionQueries;
    *pBuffer = bQuerySuccess && !bNullProtocol ? reinterpret_cast<LPWSTR>(&iProtocol) : nullptr;
    *pSize = iProtocolSize;
    return hServer == WTS_CURRENT_SERVER_HANDLE && iSession == WTS_CURRENT_SESSION &&
        eClass == WTSClientProtocolType && bQuerySuccess;
}

static void WINAPI FreeSessionMemory(PVOID) {}

static SECURITY_STATUS WINAPI GetKeyProperty(NCRYPT_HANDLE, LPCWSTR sName, PBYTE pOutput,
    DWORD iOutputSize, DWORD* pSize, DWORD)
{
    if (wcscmp(sName, NCRYPT_PROVIDER_HANDLE_PROPERTY) == 0 && iOutputSize >= sizeof(NCRYPT_PROV_HANDLE))
    {
        *reinterpret_cast<NCRYPT_PROV_HANDLE*>(pOutput) = 1;
        *pSize = sizeof(NCRYPT_PROV_HANDLE);
        return ERROR_SUCCESS;
    }
    if (wcscmp(sName, NCRYPT_NAME_PROPERTY) == 0 && iOutputSize >= sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER))
    {
        memcpy(pOutput, MS_SMART_CARD_KEY_STORAGE_PROVIDER, sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER));
        *pSize = sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER);
        return ERROR_SUCCESS;
    }
    return NTE_INVALID_PARAMETER;
}

static SECURITY_STATUS WINAPI FreeKeyObject(NCRYPT_HANDLE) { return ERROR_SUCCESS; }

// Exercise the production hook with controlled session transitions and a smart-card provider.
#define WTSQuerySessionInformationW QuerySession
#define WTSFreeMemory FreeSessionMemory
#define NCryptGetProperty GetKeyProperty
#define NCryptFreeObject FreeKeyObject
#include "../../../WinPrivLibrary/WinPrivLibrarySmartCards.cpp"
#undef WTSQuerySessionInformationW
#undef WTSFreeMemory
#undef NCryptGetProperty
#undef NCryptFreeObject

static SECURITY_STATUS WINAPI SignHash(NCRYPT_KEY_HANDLE, VOID*, PBYTE, DWORD, PBYTE, DWORD,
    DWORD* pResultSize, DWORD iFlags)
{
    ++iSigningCalls;
    iSigningFlags = iFlags;
    *pResultSize = 64;
    return ERROR_SUCCESS;
}

int TestSmartCardSessionRouting()
{
    TrueNCryptSignHash = SignHash;
    const struct
    {
        USHORT protocol;
        BOOL success;
        DWORD size;
        bool nullBuffer;
        bool remote;
    } cases[] = {
        { 0, TRUE, 2, false, false }, { 2, TRUE, 2, false, true },
        { 0, TRUE, 2, false, false }, { 2, TRUE, 2, false, true },
        { 0, TRUE, 2, false, false }, { 2, FALSE, 0, false, false },
        { 2, TRUE, 1, false, false }, { 2, TRUE, 2, true, false },
        { 2, TRUE, 2, false, true },
    };

    // Keep the same hook and key alive across local, remote, and failed session queries.
    DWORD iResultSize = 0;
    for (const auto& test : cases)
    {
        iProtocol = test.protocol;
        bQuerySuccess = test.success;
        iProtocolSize = test.size;
        bNullProtocol = test.nullBuffer;
        const SECURITY_STATUS iStatus = DetourNCryptSignHash(1, nullptr, nullptr, 0, nullptr, 0, &iResultSize, 0);
        if (iStatus != ERROR_SUCCESS || iResultSize != 64 ||
            iSigningFlags != (test.remote ? NCRYPT_SILENT_FLAG : 0u) || iSigningCalls != iSessionQueries)
        {
            std::fwprintf(stderr, L"Smart-card session routing failed at query %lu.\n", iSessionQueries);
            return 1;
        }
    }

    // Silent requests must bypass the session query and preserve their flags.
    if (DetourNCryptSignHash(1, nullptr, nullptr, 0, nullptr, 0, &iResultSize, NCRYPT_SILENT_FLAG) !=
        ERROR_SUCCESS || iSigningFlags != NCRYPT_SILENT_FLAG || iSessionQueries != ARRAYSIZE(cases) ||
        iSigningCalls != ARRAYSIZE(cases) + 1) return 1;
    std::wprintf(L"{\"schemaVersion\":1,\"sessionChecks\":%lu,\"signingCalls\":%lu}\n",
        iSessionQueries, iSigningCalls);
    return 0;
}
