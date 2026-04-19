#pragma once

#include <Windows.h>

#ifdef __cplusplus
#include <vector>
#include <string>
#include <functional>
#include <ranges>
#endif

//
// Shared Functions
//
#ifdef __cplusplus
std::vector<std::wstring> EnablePrivs(std::vector<std::wstring> tRequestedPrivs);
BOOL AlterCurrentUserPrivs(const std::vector<std::wstring>& vPrivsToGrant, BOOL bAddRights);
BOOL ModifyAccountRights(const std::wstring& sAccountName, const std::vector<std::wstring>& vRights, BOOL bGrant);
BOOL ClearDenyRights(const std::wstring& sAccountName = L"");
std::wstring ArgvToCommandLine(unsigned int iStart, unsigned int iEnd, const std::vector<LPWSTR>& vArgs);
void KillProcess(const std::wstring& sProcessName);
#endif

//
// Environment Variables Used For Interprocess Communication
//

#define WINPRIV_EV_RELAUNCH_MODE L"_WINPRIV_RELAUNCH_PHASE_"
#define WINPRIV_EV_REG_OVERRIDE L"_WINPRIV_REG_OVERRIDE_"
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

//
// Miscellaneous Unicode String Helper Functions
//

#define UnicodeStringsEqual(x,y) ((x)->Length == (y)->Length && \
	_wcsnicmp((x)->Buffer,(y)->Buffer,(x)->Length / sizeof(WCHAR)) == 0)

#define UnicodeStringPrefix(x,y) (((x)->Length <= (y)->Length) ? \
	_wcsnicmp((x)->Buffer,(y)->Buffer,(x)->Length / sizeof(WCHAR)) == 0 : FALSE)

#define UnicodeStringInit(x) { (wcslen(x) * sizeof(WCHAR)), (wcslen(x) * sizeof(WCHAR)), x }

//
// Miscellaneous Environment Variable Helper Functions
//

inline BOOL VariableNotEmpty(const wchar_t* x)
{
	const wchar_t* ev = _wgetenv(x);
	return ev != NULL && wcslen(ev) > 0;
}

inline BOOL VariableIsSet(const wchar_t* x, const int y)
{
	const wchar_t* ev = _wgetenv(x);
	return ev != NULL && _wtoi(ev) == y;
}

//
// Miscellaneous String Helper Functions
//

#ifdef __cplusplus
inline std::wstring TrimString(const std::wstring& string, wchar_t ch)
{
	auto trimmed = string
		| std::views::drop_while([ch](const wchar_t c) { return c == ch; })
		| std::views::reverse
		| std::views::drop_while([ch](const wchar_t c) { return c == ch; })
		| std::views::reverse;

	return { trimmed.begin(), trimmed.end() };
}
#endif

// generic print message that resembles printf() syntax with
// vardiac variables but will also output to a message box
// if not compiled on a console
#define PrintMessage(format, ...) do { \
		LPWSTR sString = (LPWSTR) calloc((size_t) (_scwprintf(format, __VA_ARGS__) + 1), sizeof(WCHAR)); \
		if (sString == NULL) exit(0); \
		_swprintf(sString, format, __VA_ARGS__); \
		if (GetConsoleWindow() != NULL) wprintf(L"%s", sString); else \
			MessageBox(NULL, sString, L"WinPriv Message", MB_OK | MB_SYSTEMMODAL); \
        free(sString); \
	} while (0)


//
// SmartPointer<>. Custom template for WinAPI resource cleanup.
// Automatically invokes the provided cleanup callable in its destructor.
//
#ifdef __cplusplus
template <typename T>
class SmartPointer final
{
public:

	SmartPointer(const SmartPointer&) = delete; // non-copyable
	T operator=(const SmartPointer& lp) = delete; // copy assignment forbidden

	SmartPointer(std::function<void(T)> cleanup) : m_Cleanup(std::move(cleanup)), m_Data(nullptr) {}
	SmartPointer(std::function<void(T)> cleanup, T data) : m_Cleanup(std::move(cleanup)), m_Data(data) {}

	~SmartPointer()
	{
		Cleanup();
	}

	SmartPointer(SmartPointer&& src) noexcept
	{
		m_Cleanup = std::move(src.m_Cleanup);
		m_Data = src.m_Data;
		src.m_Data = nullptr;
		src.m_Cleanup = nullptr;
	}

	void Cleanup()
	{
		if (m_Data != nullptr && m_Data != INVALID_HANDLE_VALUE)
		{
			m_Cleanup(m_Data);
			m_Data = nullptr;
		}
	}

	SmartPointer& operator=(SmartPointer&& src) noexcept
	{
		if (std::addressof(*this) != std::addressof(src))
		{
			Cleanup();
			m_Cleanup = std::move(src.m_Cleanup);
			m_Data = src.m_Data;
			src.m_Data = nullptr;
			src.m_Cleanup = nullptr;
		}

		return *this;
	}

	void Release() noexcept
	{
		m_Data = nullptr;
	}

	operator T()
	{
		return m_Data;
	}

	T& operator*()
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

	T operator=(T lp)
	{
		Cleanup();
		m_Data = lp;
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
#endif