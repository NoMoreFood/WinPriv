#pragma once

#include <windows.h>

#include <vector>
#include <string>

// 
// Shared Functions
//

std::vector<std::wstring> EnablePrivs(std::vector<std::wstring> tRequestedPrivs);
BOOL AlterCurrentUserPrivs(std::vector<std::wstring> vPrivsToGrant, BOOL bAddRights);

// 
// Environment Variables Used For Interprocess Communication
//

#define WINPRIV_EV_RELAUNCH_MODE L"_WINPRIV_RELAUNCH_PHASE_"
#define WINPRIV_EV_REG_OVERRIDE L"_WINPRIV_REGOVERIDE_"
#define WINPRIV_EV_MAC_OVERRIDE L"_WINPRIV_MACOVERIDE_"
#define WINPRIV_EV_BACKUP_RESTORE L"_WINPRIV_BACKUPRESTORE_"
#define WINPRIV_EV_PRIVLIST L"_WINPRIV_PRIVILEGE_LIST_"
#define WINPRIV_EV_PARENT_PID L"_WINPRIV_EV_PARENT_PID_"

//
// Miscellaneous Unicode String Helper Functions
//

#define UnicodeStringsEqual(x,y) ((x)->Length == (y)->Length && \
	_wcsnicmp((x)->Buffer,(y)->Buffer,(x)->Length / sizeof(WCHAR)) == 0)

#define UnicodeStringPrefix(x,y) (((x)->Length <= (y)->Length) ? \
	_wcsnicmp((x)->Buffer,(y)->Buffer,(x)->Length / sizeof(WCHAR)) == 0 : FALSE)

#define UnicodeStringInit(x) { (wcslen(x) * sizeof(WCHAR)), (wcslen(x) * sizeof(WCHAR)), x }

std::wstring ArgvToCommandLine(unsigned int iStart, unsigned int iEnd, std::vector<LPWSTR> vArgs);

//
// Miscellaneous Environment Variable Helper Functions
//

#define VariableNotEmpty(x) (_wgetenv(x) != NULL && wcslen(_wgetenv(x)) > 0)

#define VariableIsSet(x,y) (_wgetenv(x) != NULL && _wtoi(_wgetenv(x)) == (y))

//
// Miscellaneous String Helper Functions
//

#define TrimBegin(x,y) (x).erase((x).begin(), std::find_if((x).begin(), \
	(x).end(), [](int c) { return !(c == y); }));

#define TrimEnd(x,y) (x).erase(std::find_if((x).rbegin(), \
	(x).rend(), [](int c) { return !(c == y); }).base(), (x).end());

#define TrimString(x,y) do { TrimBegin(x,y); TrimEnd(x,y); } while (0)

#define BeginsWith(x,y) ((x).compare(0, (y).length(), (y)) == 0)

#define EndsWith(x,y) ((x).size() >= (y).size() && \
	(x).compare(mainStr.size() - (y).size(), (x).size(), (x)) == 0)

// generic print message that resembles printf() syntax with 
// vardiac variables but will also output to a message box
// if not compiled on a console
#define PrintMessage(format, ...) do { \
		std::wstring sString(_scwprintf(format, __VA_ARGS__), '\0'); \
		_swprintf((LPWSTR) sString.data(), format, __VA_ARGS__); \
		if (GetConsoleWindow() != NULL) wprintf(L"%s", sString.c_str()); else \
			MessageBox(NULL, sString.c_str(), L"WinPriv Message", MB_OK); \
	} while (0)
