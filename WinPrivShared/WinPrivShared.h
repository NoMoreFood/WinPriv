#pragma once

#include <Windows.h>

#include <array>
#include <vector>
#include <string>
#include <string_view>
#include <functional>
#include <ranges>

//
// Shared Functions
//

std::vector<std::wstring> EnablePrivs(const std::vector<std::wstring>& vRequestedPrivs);
BOOL AlterCurrentUserPrivs(const std::vector<std::wstring>& vPrivsToGrant, BOOL bAddRights,
	std::vector<std::wstring>* pAddedPrivs = nullptr);
BOOL ModifyAccountRights(const std::wstring& sAccountName, const std::vector<std::wstring>& vRights, BOOL bGrant);
BOOL ClearDenyRights(const std::wstring& sAccountName = L"");
BOOL GrantAllRights(const std::wstring& sAccountName);
std::wstring ArgvToCommandLine(unsigned int iStart, unsigned int iEnd, const std::vector<LPWSTR>& vArgs);
void KillProcesses(const std::vector<std::wstring>& vProcessNames, DWORD iSessionId = MAXDWORD);
bool ParseMockTimeOffset(std::wstring_view sDelta, LONGLONG iCurrentTime, LONGLONG& iOffset);
std::wstring ResolveFileRulePath(std::wstring path);
std::wstring NormalizeHostName(std::wstring_view name);

template <typename Function>
Function LoadNtFunction(LPCSTR name) noexcept
{
	return reinterpret_cast<Function>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name));
}

//
// Environment Variables Used For Interprocess Communication
//

#define WINPRIV_EV_RELAUNCH_MODE L"_WINPRIV_RELAUNCH_PHASE_"
#define WINPRIV_EV_REG_OVERRIDE L"_WINPRIV_REG_OVERRIDE_"
#define WINPRIV_EV_FILE_RULES L"_WINPRIV_FILE_RULES_"
#define WINPRIV_EV_MAC_OVERRIDE L"_WINPRIV_MAC_OVERRIDE_"
#define WINPRIV_EV_BACKUP_RESTORE L"_WINPRIV_BACKUP_RESTORE_"
#define WINPRIV_EV_DISABLE_AMSI L"_WINPRIV_DISABLE_AMSI_"
#define WINPRIV_EV_BREAK_LOCKS L"_WINPRIV_BREAK_LOCKS_"
#define WINPRIV_EV_PRIVLIST L"_WINPRIV_PRIVILEGE_LIST_"
#define WINPRIV_EV_PARENT_PID L"_WINPRIV_EV_PARENT_PID_"
#define WINPRIV_EV_HOST_OVERRIDE L"_WINPRIV_EV_HOST_OVERRIDE_"
#define WINPRIV_EV_ADMIN_IMPERSONATE L"_WINPRIV_EV_ADMIN_IMPERSONATE_"
#define WINPRIV_EV_SERVER_EDITION L"_WINPRIV_EV_SERVER_EDITION_"
#define WINPRIV_EV_RECORD_CRYPTO L"_WINPRIV_EV_RECORD_CRYPTO_"
#define WINPRIV_EV_SQL_CONNECT_SHOW L"_WINPRIV_EV_SQL_CONNECT_SHOW_"
#define WINPRIV_EV_SQL_CONNECT_SEARCH L"_WINPRIV_EV_SQL_CONNECT_SEARCH_"
#define WINPRIV_EV_SQL_CONNECT_REPLACE L"_WINPRIV_EV_SQL_CONNECT_REPLACE_"
#define WINPRIV_EV_MEDIUM_PLUS L"_WINPRIV_EV_MEDIUM_PLUS_"
#define WINPRIV_EV_CLM L"_WINPRIV_EV_CLM_"
#define WINPRIV_EV_MOCK_TIME L"_WINPRIV_EV_MOCK_TIME_"

inline constexpr std::array<LPCWSTR, 19> WinPrivSettingNames{
	WINPRIV_EV_RELAUNCH_MODE, WINPRIV_EV_REG_OVERRIDE, WINPRIV_EV_MAC_OVERRIDE, WINPRIV_EV_BACKUP_RESTORE,
	WINPRIV_EV_DISABLE_AMSI, WINPRIV_EV_BREAK_LOCKS, WINPRIV_EV_PRIVLIST, WINPRIV_EV_PARENT_PID,
	WINPRIV_EV_HOST_OVERRIDE, WINPRIV_EV_ADMIN_IMPERSONATE, WINPRIV_EV_SERVER_EDITION, WINPRIV_EV_RECORD_CRYPTO,
	WINPRIV_EV_SQL_CONNECT_SHOW, WINPRIV_EV_SQL_CONNECT_SEARCH, WINPRIV_EV_SQL_CONNECT_REPLACE,
	WINPRIV_EV_MEDIUM_PLUS, WINPRIV_EV_CLM, WINPRIV_EV_MOCK_TIME, WINPRIV_EV_FILE_RULES,
};

//
// Miscellaneous Environment Variable Helper Functions
//

inline BOOL VariableNotEmpty(const wchar_t* x)
{
	wchar_t ev[2];
	DWORD dwLen = GetEnvironmentVariableW(x, ev, ARRAYSIZE(ev));
	return dwLen > 0;
}

inline BOOL VariableIsSet(const wchar_t* x, const int y)
{
	wchar_t ev[_MAX_ITOSTR_BASE10_COUNT];
	DWORD dwLen = GetEnvironmentVariableW(x, ev, ARRAYSIZE(ev));
	return dwLen > 0 && dwLen < ARRAYSIZE(ev) && _wtoi(ev) == y;
}

//
// Miscellaneous String Helper Functions
//

inline std::wstring TrimString(const std::wstring& string, wchar_t ch)
{
	auto trimmed = string
		| std::views::drop_while([ch](const wchar_t c) { return c == ch; })
		| std::views::reverse
		| std::views::drop_while([ch](const wchar_t c) { return c == ch; })
		| std::views::reverse;

	return { trimmed.begin(), trimmed.end() };
}

inline bool WinPrivUsesConsoleSubsystem()
{
	const auto pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(GetModuleHandleW(nullptr));
	if (pDosHeader == nullptr || pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
	const auto pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(pDosHeader) + pDosHeader->e_lfanew);
	return pNtHeaders->Signature == IMAGE_NT_SIGNATURE &&
		pNtHeaders->OptionalHeader.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI;
}

// generic print message that resembles printf() syntax with
// vardiac variables but will also output to a message box
// if not compiled on a console
#define PrintMessage(format, ...) do { \
		const int iLength = _scwprintf(format, __VA_ARGS__); \
		if (iLength < 0) break; \
		LPWSTR sString = (LPWSTR) calloc((size_t) iLength + 1, sizeof(WCHAR)); \
		if (sString == NULL) break; \
		_snwprintf_s(sString, (size_t) iLength + 1, _TRUNCATE, format, __VA_ARGS__); \
		if (WinPrivUsesConsoleSubsystem()) wprintf(L"%s", sString); else \
			MessageBox(NULL, sString, L"WinPriv Message", MB_OK | MB_SYSTEMMODAL); \
        free(sString); \
	} while (0)


//
// SmartPointer<>. Custom template for WinAPI resource cleanup.
// Automatically invokes the provided cleanup callable in its destructor.
//
template <typename T>
class SmartPointer final
{
public:

	SmartPointer(const SmartPointer&) = delete; // non-copyable
	T operator=(const SmartPointer& lp) = delete; // copy assignment forbidden

	SmartPointer(std::function<void(T)> cleanup, T data) : m_Cleanup(std::move(cleanup)), m_Data(data) {}

	~SmartPointer()
	{
		Cleanup();
	}

	void Cleanup()
	{
		if (m_Data != nullptr && m_Data != INVALID_HANDLE_VALUE)
		{
			m_Cleanup(m_Data);
			m_Data = nullptr;
		}
	}

	operator T()
	{
		return m_Data;
	}

	T* operator&()
	{
		return &m_Data;
	}

	T operator->()
	{
		return m_Data;
	}

	bool operator!()
	{
		return m_Data == nullptr;
	}

private:

	std::function<void(T)> m_Cleanup;
	T m_Data;
};
