#define CINTERFACE

#include <Windows.h>
#include <CDOSys.h>
#include <Ole2.h>
#include <adoint.h>
#include "WinPrivDetoursFork.h"

#include "WinPrivShared.h"

// helper function used for simple search and replace
LPWSTR SearchReplace(LPCWSTR sInputString, LPCWSTR sSearchString, LPCWSTR sReplaceString);

//   __   __            __   ___ ___  __        __   __
//  /  ` /  \  |\/|    |  \ |__   |  /  \ |  | |__) /__`
//  \__, \__/  |  |    |__/ |___  |  \__/ \__/ |  \ .__/
//

static HRESULT(STDMETHODCALLTYPE* TrueComOpen)(__RPC__in Connection15* This,
	__RPC__in BSTR ConnectionString, __RPC__in BSTR UserID, __RPC__in BSTR Password, long Options);
static BOOL ComOpenAttached = FALSE;
static PVOID ComOpenTarget = NULL;

static HRESULT STDMETHODCALLTYPE DetourComOpen(__RPC__in Connection15* This,
	__RPC__in BSTR ConnectionString, __RPC__in BSTR UserID, __RPC__in BSTR Password, long Options)
{
	// handle search and replace
	BSTR sRevisedString = NULL;
	if (VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		// do search replace and create a new string from the result
		LPCWSTR sReplace = _wgetenv(WINPRIV_EV_SQL_CONNECT_REPLACE);
		if (sReplace == NULL) sReplace = L"";
		const LPWSTR sNewString = SearchReplace(ConnectionString,
			_wgetenv(WINPRIV_EV_SQL_CONNECT_SEARCH), sReplace);
		sRevisedString = SysAllocString(sNewString);
		if (sRevisedString != NULL) ConnectionString = sRevisedString;
		free(sNewString);
	}

	// handle show or complete overwrite
	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1))
	{
		PrintMessage(L"SQL Connection String: %s", ConnectionString);
	}

	const HRESULT iResult = TrueComOpen(This, ConnectionString, UserID, Password, Options);
	if (sRevisedString != NULL) SysFreeString(sRevisedString);
	return iResult;
}

VOID WINAPI DllExtraAttachCom(VOID)
{
	if (!ComOpenAttached &&
		(VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH)))
	{
		const IID CLSID_CADOConnection = { 0x00000514, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };
		const IID IID_Connection15 = { 0x00000515, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };
		Connection15* tConnection = NULL;
		HMODULE hTargetModule = NULL;

		(void)CoCreateInstance(&CLSID_CADOConnection, NULL, CLSCTX_INPROC_SERVER, &IID_Connection15, &tConnection);
		if (tConnection == NULL) return;

		ComOpenTarget = tConnection->lpVtbl->Open;
		TrueComOpen = tConnection->lpVtbl->Open;
		if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
			(LPCWSTR)ComOpenTarget, &hTargetModule) && DetourTransactionBegin() == NO_ERROR)
		{
			const LONG attachResult = DetourAttach((PVOID*)(&TrueComOpen), (PVOID)DetourComOpen);
			const LONG commitResult = DetourTransactionCommit();
			ComOpenAttached = attachResult == NO_ERROR && commitResult == NO_ERROR;
		}

		tConnection->lpVtbl->Release(tConnection);
	}
}

VOID WINAPI DllExtraDetachCom(VOID)
{
	if (!ComOpenAttached) return;

	MEMORY_BASIC_INFORMATION memory;
	if (VirtualQuery(ComOpenTarget, &memory, sizeof(memory)) != sizeof(memory) ||
		memory.State != MEM_COMMIT)
	{
		ComOpenAttached = FALSE;
		ComOpenTarget = NULL;
		return;
	}

	if (DetourDetach((PVOID*)(&TrueComOpen), (PVOID)DetourComOpen) == NO_ERROR)
	{
		ComOpenAttached = FALSE;
		ComOpenTarget = NULL;
	}
}
