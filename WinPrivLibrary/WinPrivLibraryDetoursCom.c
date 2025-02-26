#define CINTERFACE

#include <Windows.h>
#include <CDOSys.h>
#include <Ole2.h>
#include <adoint.h>
#include <detours.h>

#include "WinPrivShared.h"

// helper function used for simple search and replace
LPWSTR SearchReplace(LPWSTR sInputString, LPWSTR sSearchString, LPWSTR sReplaceString);

//   __   __            __   ___ ___  __        __   __  
//  /  ` /  \  |\/|    |  \ |__   |  /  \ |  | |__) /__` 
//  \__, \__/  |  |    |__/ |___  |  \__/ \__/ |  \ .__/ 
//  

HRESULT(STDMETHODCALLTYPE* TrueComOpen)(__RPC__in Connection15* This,
	__RPC__in BSTR ConnectionString, __RPC__in BSTR UserID, __RPC__in BSTR Password, long Options);

HRESULT STDMETHODCALLTYPE DetourComOpen(__RPC__in Connection15* This,
	__RPC__in BSTR ConnectionString, __RPC__in BSTR UserID, __RPC__in BSTR Password, long Options)
{
	// handle search and replace
	BSTR sRevisedString = NULL;
	if (VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		// do search replace and create a new string from the result
		const LPWSTR sNewString = SearchReplace(ConnectionString,
			_wgetenv(WINPRIV_EV_SQL_CONNECT_SEARCH), _wgetenv(WINPRIV_EV_SQL_CONNECT_REPLACE));
		sRevisedString = SysAllocString(sNewString);
		ConnectionString = sRevisedString;
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

VOID WINAPI DllExtraAttachDetachCom(BOOL bAttach)
{
	if (VariableIsSet(WINPRIV_EV_SQL_CONNECT_SHOW, 1) || VariableNotEmpty(WINPRIV_EV_SQL_CONNECT_SEARCH))
	{
		if (bAttach)
		{
			const IID CLSID_CADOConnection = { 0x00000514, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };
			const IID IID_Connection15 = { 0x00000515, 0x0000, 0x0010, { 0x80, 0x00, 0x00, 0xAA, 0x00, 0x6D, 0x2E, 0xA4 } };
			Connection15* tConnection;

			// create an object in order to get the virtual table pointer
			CoCreateInstance(&CLSID_CADOConnection, NULL, CLSCTX_INPROC_SERVER, &IID_Connection15, &tConnection);
			if (tConnection == NULL) return;

			// apply the detour to the vtable function
			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			TrueComOpen = tConnection->lpVtbl->Open;
			DetourAttach((PVOID*)(&TrueComOpen), (PVOID)DetourComOpen);
			DetourTransactionCommit();

			// cleanup
			tConnection->lpVtbl->Release(tConnection);
		}
		else
		{
			DetourDetach((PVOID*)(&TrueComOpen), (PVOID)DetourComOpen);
		}
	}
}