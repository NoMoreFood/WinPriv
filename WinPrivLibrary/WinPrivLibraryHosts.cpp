//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define _WINSOCKAPI_
#include "WinPrivLibrary.h"
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <ShlObj.h>
#include <windns.h>
#include <intrin.h>

#pragma comment(lib, "dnsapi.lib")

struct HostOverride
{
	std::wstring Name;
	std::wstring Replacement;
	std::string NarrowReplacement;
};

static std::vector<HostOverride> vHostOverrides;

static const HostOverride* FindHostOverride(_In_opt_ LPCWSTR sName, const void* pCaller) noexcept
{
	if (sName == nullptr) return nullptr;
	DWORD iError = GetLastError();
	SmartPointer<DWORD*> tErrorCleanup([](DWORD* pError) { SetLastError(*pError); }, &iError);

	// Native resolvers can dispatch work across threads; only application requests select an override.
	HMODULE hCaller = nullptr;
	if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		reinterpret_cast<LPCWSTR>(pCaller), &hCaller) && (hCaller == GetModuleHandleW(L"ws2_32.dll") ||
		hCaller == GetModuleHandleW(L"mswsock.dll") || hCaller == GetModuleHandleW(L"dnsapi.dll"))) return nullptr;
	try
	{
		const std::wstring sNormalized = NormalizeHostName(sName);
		for (const HostOverride& tOverride : vHostOverrides)
			if (tOverride.Name == sNormalized) return &tOverride;
	}
	catch (...)
	{
		// Failed matching must leave the native resolver's behavior intact.
	}
	return nullptr;
}

static const HostOverride* FindHostOverride(_In_opt_ LPCSTR sName, UINT iCodePage, const void* pCaller) noexcept
{
	if (sName == nullptr) return nullptr;
	DWORD iError = GetLastError();
	SmartPointer<DWORD*> tErrorCleanup([](DWORD* pError) { SetLastError(*pError); }, &iError);
	try
	{
		const int iLength = MultiByteToWideChar(iCodePage, 0, sName, -1, nullptr, 0);
		if (iLength == 0) return nullptr;
		std::wstring sWideName(iLength, L'\0');
		if (MultiByteToWideChar(iCodePage, 0, sName, -1, sWideName.data(), iLength) == 0) return nullptr;
		return FindHostOverride(sWideName.c_str(), pCaller);
	}
	catch (...)
	{
		return nullptr;
	}
}

static decltype(&WSALookupServiceBeginW) TrueWSALookupServiceBeginW = WSALookupServiceBeginW;
static decltype(&WSALookupServiceBeginA) TrueWSALookupServiceBeginA = WSALookupServiceBeginA;
static decltype(&GetAddrInfoW) TrueGetAddrInfoW = GetAddrInfoW;
static decltype(&getaddrinfo) TrueGetAddrInfoA = getaddrinfo;
static decltype(&gethostbyname) TrueGetHostByName = gethostbyname;
static decltype(&GetAddrInfoExW) TrueGetAddrInfoExW = GetAddrInfoExW;
static decltype(&GetAddrInfoExA) TrueGetAddrInfoExA = GetAddrInfoExA;
static decltype(&DnsQuery_W) TrueDnsQueryW = DnsQuery_W;
static decltype(&DnsQuery_A) TrueDnsQueryA = DnsQuery_A;
static decltype(&DnsQuery_UTF8) TrueDnsQueryUtf8 = DnsQuery_UTF8;
static decltype(&DnsQueryEx) TrueDnsQueryEx = DnsQueryEx;

static INT WSAAPI DetourWSALookupServiceBeginW(_In_ LPWSAQUERYSETW pRestrictions,
	_In_ DWORD iFlags, _Out_ LPHANDLE pLookup)
{
	const HostOverride* pOverride = pRestrictions != nullptr && pRestrictions->dwSize == sizeof(*pRestrictions) &&
		(pRestrictions->dwNameSpace == NS_DNS || pRestrictions->dwNameSpace == NS_ALL)
		? FindHostOverride(pRestrictions->lpszServiceInstanceName, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr) return TrueWSALookupServiceBeginW(pRestrictions, iFlags, pLookup);

	// Let Windows return the replacement's addresses, family, names, and provider data.
	WSAQUERYSETW tRestrictions = *pRestrictions;
	tRestrictions.lpszServiceInstanceName = const_cast<LPWSTR>(pOverride->Replacement.c_str());
	return TrueWSALookupServiceBeginW(&tRestrictions, iFlags, pLookup);
}

static INT WSAAPI DetourWSALookupServiceBeginA(_In_ LPWSAQUERYSETA pRestrictions,
	_In_ DWORD iFlags, _Out_ LPHANDLE pLookup)
{
	const HostOverride* pOverride = pRestrictions != nullptr && pRestrictions->dwSize == sizeof(*pRestrictions) &&
		(pRestrictions->dwNameSpace == NS_DNS || pRestrictions->dwNameSpace == NS_ALL)
		? FindHostOverride(pRestrictions->lpszServiceInstanceName, CP_ACP, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr) return TrueWSALookupServiceBeginA(pRestrictions, iFlags, pLookup);

	WSAQUERYSETA tRestrictions = *pRestrictions;
	tRestrictions.lpszServiceInstanceName = const_cast<LPSTR>(pOverride->NarrowReplacement.c_str());
	return TrueWSALookupServiceBeginA(&tRestrictions, iFlags, pLookup);
}

static INT WSAAPI DetourGetAddrInfoW(_In_opt_ PCWSTR sName, _In_opt_ PCWSTR sService,
	_In_opt_ const ADDRINFOW* pHints, _Outptr_ PADDRINFOW* pResults)
{
	const HostOverride* pOverride = FindHostOverride(sName, _ReturnAddress());
	return TrueGetAddrInfoW(pOverride == nullptr ? sName : pOverride->Replacement.c_str(), sService, pHints, pResults);
}

static INT WSAAPI DetourGetAddrInfoA(_In_opt_ PCSTR sName, _In_opt_ PCSTR sService,
	_In_opt_ const ADDRINFOA* pHints, _Outptr_ PADDRINFOA* pResults)
{
	const HostOverride* pOverride = FindHostOverride(sName, CP_ACP, _ReturnAddress());
	return TrueGetAddrInfoA(pOverride == nullptr ? sName : pOverride->NarrowReplacement.c_str(),
		sService, pHints, pResults);
}

static hostent* WSAAPI DetourGetHostByName(_In_ PCSTR sName)
{
	const HostOverride* pOverride = FindHostOverride(sName, CP_ACP, _ReturnAddress());
	return TrueGetHostByName(pOverride == nullptr ? sName : pOverride->NarrowReplacement.c_str());
}

static bool IsHostAddressQuery(WORD iType)
{
	return iType == DNS_TYPE_A || iType == DNS_TYPE_AAAA || iType == DNS_TYPE_ANY;
}

static INT WSAAPI DetourGetAddrInfoExW(_In_opt_ PCWSTR sName, _In_opt_ PCWSTR sService,
	_In_ DWORD iNamespace, _In_opt_ LPGUID pProvider, _In_opt_ const ADDRINFOEXW* pHints,
	_Outptr_ PADDRINFOEXW* pResults, _In_opt_ timeval* pTimeout, _In_opt_ LPOVERLAPPED pOverlapped,
	_In_opt_ LPLOOKUPSERVICE_COMPLETION_ROUTINE pCompletion, _Out_opt_ LPHANDLE pCancel)
{
	const HostOverride* pOverride = iNamespace == NS_DNS || iNamespace == NS_ALL
		? FindHostOverride(sName, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr)
		return TrueGetAddrInfoExW(sName, sService, iNamespace, pProvider, pHints,
			pResults, pTimeout, pOverlapped, pCompletion, pCancel);

	// Select the destination before extended lookups invoke additional resolver entry points.
	return TrueGetAddrInfoExW(pOverride->Replacement.c_str(), sService, iNamespace,
		pProvider, pHints, pResults, pTimeout, pOverlapped, pCompletion, pCancel);
}

static INT WSAAPI DetourGetAddrInfoExA(_In_opt_ PCSTR sName, _In_opt_ PCSTR sService,
	_In_ DWORD iNamespace, _In_opt_ LPGUID pProvider, _In_opt_ const ADDRINFOEXA* pHints,
	_Outptr_ PADDRINFOEXA* pResults, _In_opt_ timeval* pTimeout, _In_opt_ LPOVERLAPPED pOverlapped,
	_In_opt_ LPLOOKUPSERVICE_COMPLETION_ROUTINE pCompletion, _Out_opt_ LPHANDLE pCancel)
{
	const HostOverride* pOverride = iNamespace == NS_DNS || iNamespace == NS_ALL
		? FindHostOverride(sName, CP_ACP, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr)
		return TrueGetAddrInfoExA(sName, sService, iNamespace, pProvider, pHints,
			pResults, pTimeout, pOverlapped, pCompletion, pCancel);
	return TrueGetAddrInfoExA(pOverride->NarrowReplacement.c_str(), sService, iNamespace,
		pProvider, pHints, pResults, pTimeout, pOverlapped, pCompletion, pCancel);
}

static DNS_STATUS WINAPI DetourDnsQueryW(_In_ PCWSTR sName, _In_ WORD iType, _In_ DWORD iOptions,
	_Inout_opt_ PVOID pExtra, _Out_opt_ PDNS_RECORD* pResults, _Out_opt_ PVOID* pReserved)
{
	const HostOverride* pOverride = IsHostAddressQuery(iType) ? FindHostOverride(sName, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr) return TrueDnsQueryW(sName, iType, iOptions, pExtra, pResults, pReserved);
	return TrueDnsQueryW(pOverride->Replacement.c_str(),
		iType, iOptions, pExtra, pResults, pReserved);
}

static DNS_STATUS WINAPI DetourDnsQueryA(_In_ PCSTR sName, _In_ WORD iType, _In_ DWORD iOptions,
	_Inout_opt_ PVOID pExtra, _Out_opt_ PDNS_RECORD* pResults, _Out_opt_ PVOID* pReserved)
{
	const HostOverride* pOverride = IsHostAddressQuery(iType)
		? FindHostOverride(sName, CP_ACP, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr) return TrueDnsQueryA(sName, iType, iOptions, pExtra, pResults, pReserved);
	return TrueDnsQueryA(pOverride->NarrowReplacement.c_str(),
		iType, iOptions, pExtra, pResults, pReserved);
}

static DNS_STATUS WINAPI DetourDnsQueryUtf8(_In_ PCSTR sName, _In_ WORD iType, _In_ DWORD iOptions,
	_Inout_opt_ PVOID pExtra, _Out_opt_ PDNS_RECORD* pResults, _Out_opt_ PVOID* pReserved)
{
	const HostOverride* pOverride = IsHostAddressQuery(iType)
		? FindHostOverride(sName, CP_UTF8, _ReturnAddress()) : nullptr;
	if (pOverride == nullptr) return TrueDnsQueryUtf8(sName, iType, iOptions, pExtra, pResults, pReserved);
	return TrueDnsQueryUtf8(pOverride->NarrowReplacement.c_str(),
		iType, iOptions, pExtra, pResults, pReserved);
}

static DNS_STATUS WINAPI DetourDnsQueryEx(_In_ PDNS_QUERY_REQUEST pRequest,
	_Inout_ PDNS_QUERY_RESULT pResults, _Inout_opt_ PDNS_QUERY_CANCEL pCancel)
{
	if (pRequest == nullptr || (pRequest->Version != DNS_QUERY_REQUEST_VERSION1 &&
		pRequest->Version != DNS_QUERY_REQUEST_VERSION3) || !IsHostAddressQuery(pRequest->QueryType))
		return TrueDnsQueryEx(pRequest, pResults, pCancel);
	const HostOverride* pOverride = FindHostOverride(pRequest->QueryName, _ReturnAddress());
	if (pOverride == nullptr) return TrueDnsQueryEx(pRequest, pResults, pCancel);

	// Names remain owned by the immutable rules until asynchronous queries finish.
	if (pRequest->Version == DNS_QUERY_REQUEST_VERSION3)
	{
		DNS_QUERY_REQUEST3 tRequest = *reinterpret_cast<PDNS_QUERY_REQUEST3>(pRequest);
		tRequest.QueryName = pOverride->Replacement.c_str();
		return TrueDnsQueryEx(reinterpret_cast<PDNS_QUERY_REQUEST>(&tRequest), pResults, pCancel);
	}
	DNS_QUERY_REQUEST tRequest = *pRequest;
	tRequest.QueryName = pOverride->Replacement.c_str();
	return TrueDnsQueryEx(&tRequest, pResults, pCancel);
}

bool DllHostAttachDetach(winpriv::detours::action requestedAction)
{
	if (!VariableNotEmpty(WINPRIV_EV_HOST_OVERRIDE)) return true;
	if (requestedAction == winpriv::detours::action::attach)
	{
		// Read ordered rules before publishing hooks; replacement names stay stable for pending queries.
		try
		{
			INT iCount = 0;
			LPWSTR* pArguments = CommandLineToArgvW(_wgetenv(WINPRIV_EV_HOST_OVERRIDE), &iCount);
			SmartPointer<LPWSTR*> tArgumentsCleanup(LocalFree, pArguments);
			if (pArguments == nullptr) return false;
			for (int i = 0; i + 1 < iCount; i += 2)
			{
				HostOverride tOverride{ NormalizeHostName(pArguments[i]), pArguments[i + 1], {} };
				for (wchar_t character : tOverride.Replacement)
					tOverride.NarrowReplacement += static_cast<char>(character);
				vHostOverrides.push_back(std::move(tOverride));
			}
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}

	ApplyDetour(requestedAction, TrueWSALookupServiceBeginW, DetourWSALookupServiceBeginW);
	ApplyDetour(requestedAction, TrueWSALookupServiceBeginA, DetourWSALookupServiceBeginA);
	ApplyDetour(requestedAction, TrueGetAddrInfoW, DetourGetAddrInfoW);
	ApplyDetour(requestedAction, TrueGetAddrInfoA, DetourGetAddrInfoA);
	ApplyDetour(requestedAction, TrueGetHostByName, DetourGetHostByName);
	ApplyDetour(requestedAction, TrueGetAddrInfoExW, DetourGetAddrInfoExW);
	ApplyDetour(requestedAction, TrueGetAddrInfoExA, DetourGetAddrInfoExA);
	ApplyDetour(requestedAction, TrueDnsQueryW, DetourDnsQueryW);
	ApplyDetour(requestedAction, TrueDnsQueryA, DetourDnsQueryA);
	ApplyDetour(requestedAction, TrueDnsQueryUtf8, DetourDnsQueryUtf8);
	ApplyDetour(requestedAction, TrueDnsQueryEx, DetourDnsQueryEx);
	return true;
}
