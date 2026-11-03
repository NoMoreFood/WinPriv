#include "../../../WinPrivLibrary/WinPrivLibrary.h"
#include <ncrypt.h>
#include <objbase.h>
#include <wincred.h>
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
static bool bSmartCardProvider = true;
static struct
{
    SECURITY_STATUS firstStatus, retryStatus, pinStatus;
    DWORD promptStatus, calls, prompts, pins, credentialSize;
    DWORD flags[2];
    NCRYPT_KEY_HANDLE key;
    LPCWSTR property;
    PBYTE input;
    DWORD inputSize;
    bool parametersValid, credentialsCleared;
} enrollment{};

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

static SECURITY_STATUS WINAPI GetKeyProperty(NCRYPT_HANDLE hObject, LPCWSTR sName, PBYTE pOutput,
    DWORD iOutputSize, DWORD* pSize, DWORD)
{
    if (hObject == 0) return NTE_INVALID_HANDLE;
    if (wcscmp(sName, NCRYPT_PROVIDER_HANDLE_PROPERTY) == 0 && iOutputSize >= sizeof(NCRYPT_PROV_HANDLE))
    {
        *reinterpret_cast<NCRYPT_PROV_HANDLE*>(pOutput) = 1;
        *pSize = sizeof(NCRYPT_PROV_HANDLE);
        return ERROR_SUCCESS;
    }
    if (wcscmp(sName, NCRYPT_NAME_PROPERTY) == 0 && iOutputSize >= sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER))
    {
        memcpy(pOutput, bSmartCardProvider ? MS_SMART_CARD_KEY_STORAGE_PROVIDER : MS_KEY_STORAGE_PROVIDER,
            bSmartCardProvider ? sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER) : sizeof(MS_KEY_STORAGE_PROVIDER));
        *pSize = sizeof(MS_SMART_CARD_KEY_STORAGE_PROVIDER);
        return ERROR_SUCCESS;
    }
    return NTE_INVALID_PARAMETER;
}

static SECURITY_STATUS WINAPI FreeKeyObject(NCRYPT_HANDLE) { return ERROR_SUCCESS; }

static DWORD WINAPI PromptCredentials(PCREDUI_INFOW, DWORD, ULONG*, LPCVOID, ULONG,
    LPVOID* pOutput, ULONG* pOutputSize, BOOL* pSave, DWORD iFlags)
{
    ++enrollment.prompts;
    enrollment.parametersValid &= pSave == nullptr && (iFlags & ~CREDUIWIN_PACK_32_WOW) == CREDUIWIN_GENERIC;
    if (enrollment.promptStatus != ERROR_SUCCESS) return enrollment.promptStatus;

    // Use real Windows credential packing without displaying UI or authenticating to hardware.
    WCHAR sUser[] = L"Hardware Token";
    WCHAR sPin[] = L"1234";
    DWORD iSize = 0;
    CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, sUser, sPin, nullptr, &iSize);
    *pOutput = CoTaskMemAlloc(iSize);
    if (*pOutput == nullptr) return ERROR_NOT_ENOUGH_MEMORY;
    *pOutputSize = enrollment.credentialSize = iSize;
    return CredPackAuthenticationBufferW(CRED_PACK_GENERIC_CREDENTIALS, sUser, sPin,
        static_cast<PBYTE>(*pOutput), &iSize)
        ? ERROR_SUCCESS : GetLastError();
}

static void WINAPI FreeCredentials(LPVOID pOutput)
{
    // Inspect the credential allocation before freeing it so cleanup assertions never read freed memory.
    for (DWORD i = 0; i < enrollment.credentialSize; ++i)
        enrollment.credentialsCleared &= static_cast<PBYTE>(pOutput)[i] == 0;
    CoTaskMemFree(pOutput);
}

// Exercise the production hooks with controlled sessions and a prompt that cannot display UI.
#define WTSQuerySessionInformationW QuerySession
#define WTSFreeMemory FreeSessionMemory
#define NCryptGetProperty GetKeyProperty
#define NCryptFreeObject FreeKeyObject
#define CredUIPromptForWindowsCredentialsW PromptCredentials
#define CoTaskMemFree FreeCredentials
#include "../../../WinPrivLibrary/WinPrivLibrarySmartCards.cpp"
#undef WTSQuerySessionInformationW
#undef WTSFreeMemory
#undef NCryptGetProperty
#undef NCryptFreeObject
#undef CredUIPromptForWindowsCredentialsW
#undef CoTaskMemFree

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

static SECURITY_STATUS OperationStatus(NCRYPT_KEY_HANDLE hKey, DWORD iFlags)
{
    enrollment.parametersValid &= hKey == enrollment.key && enrollment.calls < ARRAYSIZE(enrollment.flags);
    if (enrollment.calls < ARRAYSIZE(enrollment.flags)) enrollment.flags[enrollment.calls] = iFlags;
    return ++enrollment.calls == 1 ? enrollment.firstStatus : enrollment.retryStatus;
}

static SECURITY_STATUS WINAPI FinalizeKey(NCRYPT_KEY_HANDLE hKey, DWORD iFlags)
{
    return OperationStatus(hKey, iFlags);
}

static SECURITY_STATUS WINAPI SetKeyProperty(NCRYPT_HANDLE hObject, LPCWSTR sProperty,
    PBYTE pInput, DWORD iInputSize, DWORD iFlags)
{
    if (sProperty != nullptr && wcscmp(sProperty, NCRYPT_PIN_PROPERTY) == 0)
    {
        ++enrollment.pins;
        enrollment.parametersValid &= hObject == enrollment.key && iFlags == NCRYPT_SILENT_FLAG &&
            iInputSize == sizeof(L"1234") && memcmp(pInput, L"1234", sizeof(L"1234")) == 0;
        return enrollment.pinStatus;
    }
    enrollment.parametersValid &= sProperty == enrollment.property &&
        pInput == enrollment.input && iInputSize == enrollment.inputSize;
    return OperationStatus(hObject, iFlags);
}

static SECURITY_STATUS WINAPI SignEnrollmentHash(NCRYPT_KEY_HANDLE hKey, VOID*, PBYTE, DWORD,
    PBYTE, DWORD, DWORD*, DWORD iFlags)
{
    return OperationStatus(hKey, iFlags);
}

int TestSmartCardEnrollment()
{
    TrueNCryptFinalizeKey = FinalizeKey;
    TrueNCryptSetProperty = SetKeyProperty;
    TrueNCryptSignHash = SignEnrollmentHash;
    const struct
    {
        USHORT protocol = 2;
        bool smartCard = true;
        NCRYPT_KEY_HANDLE key = 2;
        DWORD flags = 0;
        SECURITY_STATUS firstStatus = NTE_SILENT_CONTEXT, retryStatus = ERROR_SUCCESS, pinStatus = ERROR_SUCCESS;
        DWORD promptStatus = ERROR_SUCCESS;
        SECURITY_STATUS expectedStatus = ERROR_SUCCESS;
        DWORD calls = 2, prompts = 1, pins = 1;
    } cases[] = {
        {},
        { .firstStatus = ERROR_SUCCESS, .calls = 1, .prompts = 0, .pins = 0 },
        { .protocol = 0, .expectedStatus = NTE_SILENT_CONTEXT, .calls = 1, .prompts = 0, .pins = 0 },
        { .smartCard = false, .expectedStatus = NTE_SILENT_CONTEXT, .calls = 1, .prompts = 0, .pins = 0 },
        { .key = 0, .firstStatus = NTE_INVALID_HANDLE, .expectedStatus = NTE_INVALID_HANDLE,
            .calls = 1, .prompts = 0, .pins = 0 },
        { .flags = NCRYPT_SILENT_FLAG, .expectedStatus = NTE_SILENT_CONTEXT,
            .calls = 1, .prompts = 0, .pins = 0 },
        { .firstStatus = SCARD_W_REMOVED_CARD, .expectedStatus = SCARD_W_REMOVED_CARD,
            .calls = 1, .prompts = 0, .pins = 0 },
        { .promptStatus = ERROR_CANCELLED, .expectedStatus = NTE_USER_CANCELLED, .calls = 1, .pins = 0 },
        { .promptStatus = ERROR_ACCESS_DENIED, .expectedStatus = E_ACCESSDENIED, .calls = 1, .pins = 0 },
        { .pinStatus = SCARD_W_WRONG_CHV, .expectedStatus = SCARD_W_WRONG_CHV, .calls = 1 },
        { .retryStatus = SCARD_W_WRONG_CHV, .expectedStatus = SCARD_W_WRONG_CHV },
        { .retryStatus = NTE_SILENT_CONTEXT, .expectedStatus = NTE_SILENT_CONTEXT },
        { .retryStatus = SCARD_W_REMOVED_CARD, .expectedStatus = SCARD_W_REMOVED_CARD },
    };

    // Cover key generation, certificate installation on a fresh handle, and request signing.
    BYTE aCertificate[] = { 0x30, 0x00 };
    DWORD iScenarios = 0;
    for (DWORD iOperation = 0; iOperation < 3; ++iOperation)
    {
        for (const auto& test : cases)
        {
            enrollment = {};
            enrollment.firstStatus = test.firstStatus;
            enrollment.retryStatus = test.retryStatus;
            enrollment.pinStatus = test.pinStatus;
            enrollment.promptStatus = test.promptStatus;
            enrollment.key = test.key;
            enrollment.property = NCRYPT_CERTIFICATE_PROPERTY;
            enrollment.input = aCertificate;
            enrollment.inputSize = sizeof(aCertificate);
            enrollment.parametersValid = enrollment.credentialsCleared = true;
            iProtocol = test.protocol;
            bSmartCardProvider = test.smartCard;
            const DWORD iFlags = test.flags | (iOperation == 0 ? NCRYPT_NO_KEY_VALIDATION :
                iOperation == 1 ? NCRYPT_PERSIST_FLAG : BCRYPT_PAD_PKCS1);
            const SECURITY_STATUS iStatus = iOperation == 0 ? DetourNCryptFinalizeKey(test.key, iFlags) :
                iOperation == 1 ? DetourNCryptSetProperty(test.key, enrollment.property,
                    aCertificate, sizeof(aCertificate), iFlags) :
                DetourNCryptSignHash(test.key, nullptr, nullptr, 0, nullptr, 0, nullptr, iFlags);
            const DWORD iExpectedFlags = iFlags |
                (test.protocol != 0 && test.smartCard && test.key != 0 ? NCRYPT_SILENT_FLAG : 0u);
            if (iStatus != test.expectedStatus || enrollment.calls != test.calls ||
                enrollment.prompts != test.prompts || enrollment.pins != test.pins ||
                enrollment.flags[0] != iExpectedFlags ||
                (test.calls == 2 && enrollment.flags[1] != iExpectedFlags) ||
                !enrollment.parametersValid || !enrollment.credentialsCleared)
            {
                std::fwprintf(stderr, L"Smart-card enrollment failed: operation %lu, scenario %lu, status %#lx.\n",
                    iOperation, iScenarios, static_cast<ULONG>(iStatus));
                return 1;
            }
            ++iScenarios;
        }
    }

    // Unrelated properties, including malformed requests, must bypass PIN handling and preserve their flags.
    for (LPCWSTR sProperty : { NCRYPT_LENGTH_PROPERTY, static_cast<LPCWSTR>(nullptr) })
    {
        enrollment = {};
        enrollment.firstStatus = NTE_NOT_SUPPORTED;
        enrollment.key = 2;
        enrollment.property = sProperty;
        enrollment.input = aCertificate;
        enrollment.inputSize = sizeof(aCertificate);
        enrollment.parametersValid = true;
        if (DetourNCryptSetProperty(2, sProperty, aCertificate, sizeof(aCertificate), 0) != NTE_NOT_SUPPORTED ||
            enrollment.calls != 1 || enrollment.flags[0] != 0 || enrollment.prompts != 0 ||
            enrollment.pins != 0 || !enrollment.parametersValid) return 1;
        ++iScenarios;
    }
    std::wprintf(L"{\"schemaVersion\":1,\"enrollmentScenarios\":%lu}\n", iScenarios);
    return 0;
}
