//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <Windows.h>
#include <bcrypt.h>
#include <sddl.h>
#include <array>
#include <cwchar>
#include <vector>

#include "WinPrivDetoursFork.h"
#include "WinPrivShared.h"

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"advapi32.lib")

void DllExtraAttachDetach(winpriv::detours::action requestedAction);

namespace
{
	std::array<CHAR, MAX_PATH + 1> detourLibrary{};
	std::array<HANDLE, 4> detourBundleLocks{};

	using WidePath = std::array<WCHAR, MAX_PATH + 16>;
	using BundlePaths = std::array<WidePath, 3>;
	constexpr std::array<LPCWSTR, 3> bundleSuffixes{
		L"-32.dll", L"-64.dll", L"-arm64.dll" };
	constexpr std::array<LPCWSTR, 3> cachedBundleNames{
		L"WinPrivLibrary-32.dll", L"WinPrivLibrary-64.dll",
		L"WinPrivLibrary-arm64.dll" };
	constexpr size_t cacheNonceCharacterCount = 32;

	auto trueCreateProcessA = &CreateProcessA;
	auto trueCreateProcessW = &CreateProcessW;

	constexpr GUID winPrivPayloadGuid{
		0xa4b01a2d, 0xb07f, 0x47f8,
		{ 0xb0, 0x30, 0x5a, 0x49, 0x25, 0x74, 0x47, 0x83 } };
	// The GUID versions this schema. Its data is one NUL-terminated UTF-16
	// value per name below, in the same fixed order.
	constexpr std::array<LPCWSTR, 16> winPrivSettingNames{
		WINPRIV_EV_RELAUNCH_MODE,
		WINPRIV_EV_REG_OVERRIDE,
		WINPRIV_EV_MAC_OVERRIDE,
		WINPRIV_EV_BACKUP_RESTORE,
		WINPRIV_EV_DISABLE_AMSI,
		WINPRIV_EV_BREAK_LOCKS,
		WINPRIV_EV_PRIVLIST,
		WINPRIV_EV_PARENT_PID,
		WINPRIV_EV_HOST_OVERRIDE,
		WINPRIV_EV_ADMIN_IMPERSONATE,
		WINPRIV_EV_SERVER_EDITION,
		WINPRIV_EV_RECORD_CRYPTO,
		WINPRIV_EV_SQL_CONNECT_SHOW,
		WINPRIV_EV_SQL_CONNECT_SEARCH,
		WINPRIV_EV_SQL_CONNECT_REPLACE,
		WINPRIV_EV_MEDIUM_PLUS,
	};

	bool CaptureWinPrivPayload(std::vector<WCHAR>& payload) noexcept
	{
		try
		{
			constexpr size_t maximumCharacters = MAXDWORD / sizeof(WCHAR);
			for (LPCWSTR name : winPrivSettingNames)
			{
				SetLastError(NO_ERROR);
				const DWORD required =
					GetEnvironmentVariableW(name, nullptr, 0);
				if (required == 0)
				{
					const DWORD error = GetLastError();
					if (error != NO_ERROR && error != ERROR_ENVVAR_NOT_FOUND)
					{
						return false;
					}
					if (payload.size() == maximumCharacters)
					{
						SetLastError(ERROR_BAD_ENVIRONMENT);
						return false;
					}
					payload.push_back(L'\0');
					continue;
				}

				if (required > maximumCharacters - payload.size())
				{
					SetLastError(ERROR_BAD_ENVIRONMENT);
					return false;
				}
				const size_t offset = payload.size();
				payload.resize(offset + required);
				SetLastError(NO_ERROR);
				const DWORD copied = GetEnvironmentVariableW(
					name, payload.data() + offset, required);
				if (copied >= required ||
					(copied == 0 && GetLastError() != NO_ERROR))
				{
					SetLastError(ERROR_BAD_ENVIRONMENT);
					return false;
				}
				payload.resize(offset + copied + 1);
			}
			return true;
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}

	bool ApplyWinPrivPayload(LPCVOID payload, DWORD payloadSize)
	{
		if (payload == nullptr || payloadSize % sizeof(WCHAR) != 0)
		{
			SetLastError(ERROR_INVALID_DATA);
			return false;
		}

		std::array<LPCWSTR, winPrivSettingNames.size()> values{};
		LPCWSTR cursor = static_cast<LPCWSTR>(payload);
		size_t remaining = payloadSize / sizeof(WCHAR);
		for (LPCWSTR& value : values)
		{
			const WCHAR* terminator = wmemchr(cursor, L'\0', remaining);
			if (terminator == nullptr)
			{
				SetLastError(ERROR_INVALID_DATA);
				return false;
			}
			value = cursor;
			const size_t consumed = terminator - cursor + 1;
			cursor += consumed;
			remaining -= consumed;
		}
		if (remaining != 0)
		{
			SetLastError(ERROR_INVALID_DATA);
			return false;
		}

		for (size_t index = 0; index < winPrivSettingNames.size(); ++index)
		{
			if (_wputenv_s(winPrivSettingNames[index], values[index]) != 0)
			{
				SetLastError(ERROR_BAD_ENVIRONMENT);
				return false;
			}
			if (*values[index] == L'\0' &&
				!SetEnvironmentVariableW(winPrivSettingNames[index], L""))
			{
				return false;
			}
		}
		return true;
	}

	bool ApplyInjectedWinPrivPayload() noexcept
	{
		DWORD payloadSize = 0;
		PVOID payload = DetourFindPayload(
			&winPrivPayloadGuid, &payloadSize);
		if (payload == nullptr)
		{
			if (GetLastError() != ERROR_MOD_NOT_FOUND)
			{
				return false;
			}
			SetLastError(NO_ERROR);
			return true;
		}

		const bool applied = ApplyWinPrivPayload(payload, payloadSize);
		const DWORD applyError = GetLastError();
		if (!DetourFreePayload(payload))
		{
			return false;
		}
		SetLastError(applied ? NO_ERROR : applyError);
		return applied;
	}

	bool CopyAsciiPath(LPCWSTR source)
	{
		size_t index = 0;
		for (; source[index] != L'\0'; ++index)
		{
			if (index + 1 >= detourLibrary.size() || source[index] > 0x7f)
			{
				return false;
			}
			detourLibrary[index] = static_cast<CHAR>(source[index]);
		}
		detourLibrary[index] = '\0';
		return true;
	}

	bool SameFile(LPCWSTR firstPath, LPCWSTR secondPath)
	{
		constexpr DWORD sharing =
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
		const HANDLE first = CreateFileW(firstPath, 0, sharing, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (first == INVALID_HANDLE_VALUE)
		{
			return false;
		}
		const HANDLE second = CreateFileW(secondPath, 0, sharing, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (second == INVALID_HANDLE_VALUE)
		{
			CloseHandle(first);
			return false;
		}

		BY_HANDLE_FILE_INFORMATION firstInformation{};
		BY_HANDLE_FILE_INFORMATION secondInformation{};
		const bool result =
			GetFileInformationByHandle(first, &firstInformation) &&
			GetFileInformationByHandle(second, &secondInformation) &&
			firstInformation.dwVolumeSerialNumber ==
				secondInformation.dwVolumeSerialNumber &&
			firstInformation.nFileIndexHigh == secondInformation.nFileIndexHigh &&
			firstInformation.nFileIndexLow == secondInformation.nFileIndexLow;
		CloseHandle(second);
		CloseHandle(first);
		return result;
	}

	void CloseHandles(std::array<HANDLE, 3>& handles)
	{
		for (HANDLE& handle : handles)
		{
			if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(handle);
				handle = nullptr;
			}
		}
	}

	void CloseDetourBundleLocks()
	{
		for (HANDLE& handle : detourBundleLocks)
		{
			if (handle != nullptr && handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(handle);
				handle = nullptr;
			}
		}
	}

	bool BuildBundlePaths(
		LPCWSTR modulePath, BundlePaths& paths, size_t& currentIndex)
	{
		const size_t moduleLength = wcslen(modulePath);
		currentIndex = bundleSuffixes.size();
		size_t prefixLength = 0;
		for (size_t index = 0; index < bundleSuffixes.size(); ++index)
		{
			const size_t suffixLength = wcslen(bundleSuffixes[index]);
			if (moduleLength >= suffixLength &&
				_wcsicmp(modulePath + moduleLength - suffixLength,
					bundleSuffixes[index]) == 0)
			{
				currentIndex = index;
				prefixLength = moduleLength - suffixLength;
				break;
			}
		}
		if (currentIndex == bundleSuffixes.size())
		{
			SetLastError(ERROR_BAD_PATHNAME);
			return false;
		}

		for (size_t index = 0; index < paths.size(); ++index)
		{
			const size_t suffixLength = wcslen(bundleSuffixes[index]);
			if (prefixLength + suffixLength >= paths[index].size())
			{
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return false;
			}
			wmemcpy(paths[index].data(), modulePath, prefixLength);
			wcscpy_s(paths[index].data() + prefixLength,
				paths[index].size() - prefixLength, bundleSuffixes[index]);
		}
		return true;
	}

	bool OpenBundle(
		const BundlePaths& paths, DWORD sharing,
		std::array<HANDLE, 3>& handles, bool rejectReparsePoints = false)
	{
		handles.fill(nullptr);
		for (size_t index = 0; index < handles.size(); ++index)
		{
			handles[index] = CreateFileW(
				paths[index].data(), GENERIC_READ, sharing, nullptr,
				OPEN_EXISTING,
				rejectReparsePoints
					? FILE_FLAG_OPEN_REPARSE_POINT
					: FILE_ATTRIBUTE_NORMAL,
				nullptr);
			if (handles[index] == INVALID_HANDLE_VALUE)
			{
				const DWORD error = GetLastError();
				CloseHandles(handles);
				SetLastError(error);
				return false;
			}
			if (rejectReparsePoints)
			{
				FILE_ATTRIBUTE_TAG_INFO tagInformation{};
				if (!GetFileInformationByHandleEx(
						handles[index], FileAttributeTagInfo,
						&tagInformation, sizeof(tagInformation)) ||
					(tagInformation.FileAttributes &
						FILE_ATTRIBUTE_REPARSE_POINT) != 0)
				{
					CloseHandles(handles);
					SetLastError(ERROR_INVALID_DATA);
					return false;
				}
			}
		}
		return true;
	}

	bool BuildCacheFilePaths(
		LPCWSTR directory, BundlePaths& paths)
	{
		for (size_t index = 0; index < paths.size(); ++index)
		{
			if (swprintf_s(paths[index].data(), paths[index].size(),
				L"%ls\\%ls", directory, cachedBundleNames[index]) < 0)
			{
				SetLastError(ERROR_INSUFFICIENT_BUFFER);
				return false;
			}
		}
		return true;
	}

	bool CreateUniqueCacheDirectory(WidePath& directory, BundlePaths& paths)
	{
		const DWORD windowsLength = GetSystemWindowsDirectoryW(
			directory.data(), static_cast<UINT>(directory.size()));
		if (windowsLength == 0 || windowsLength >= directory.size() ||
			wcscat_s(directory.data(), directory.size(),
				L"\\Temp\\WinPriv-") != 0)
		{
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return false;
		}
		const size_t prefixLength = wcslen(directory.data());
		if (prefixLength + cacheNonceCharacterCount + 1 > directory.size())
		{
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return false;
		}

		PSECURITY_DESCRIPTOR descriptor = nullptr;
		constexpr LPCWSTR sddl =
			L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
			L"(A;OICI;FA;;;OW)(A;OICI;GRGX;;;BU)";
		if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
				sddl, SDDL_REVISION_1, &descriptor, nullptr))
		{
			return false;
		}

		SECURITY_ATTRIBUTES attributes{
			.nLength = sizeof(attributes),
			.lpSecurityDescriptor = descriptor,
			.bInheritHandle = FALSE,
		};
		constexpr WCHAR hex[] = L"0123456789abcdef";
		std::array<BYTE, 16> nonce{};
		for (DWORD attempt = 0; attempt < 64; ++attempt)
		{
			if (!BCRYPT_SUCCESS(BCryptGenRandom(
					nullptr, nonce.data(), static_cast<ULONG>(nonce.size()),
					BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
			{
				LocalFree(descriptor);
				SetLastError(ERROR_GEN_FAILURE);
				return false;
			}
			size_t length = prefixLength;
			for (BYTE byte : nonce)
			{
				directory[length++] = hex[byte >> 4];
				directory[length++] = hex[byte & 0xf];
			}
			directory[length] = L'\0';

			if (CreateDirectoryW(directory.data(), &attributes))
			{
				LocalFree(descriptor);
				if (!BuildCacheFilePaths(directory.data(), paths))
				{
					RemoveDirectoryW(directory.data());
					return false;
				}
				return true;
			}
			const DWORD error = GetLastError();
			if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS)
			{
				LocalFree(descriptor);
				SetLastError(error);
				return false;
			}
		}
		LocalFree(descriptor);
		SetLastError(ERROR_ALREADY_EXISTS);
		return false;
	}

	bool LockCache(LPCWSTR directory, const BundlePaths& paths)
	{
		HANDLE directoryHandle = CreateFileW(
			directory, FILE_READ_ATTRIBUTES,
			FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
			FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
		if (directoryHandle == INVALID_HANDLE_VALUE)
		{
			return false;
		}

		FILE_ATTRIBUTE_TAG_INFO tagInformation{};
		if (!GetFileInformationByHandleEx(
				directoryHandle, FileAttributeTagInfo,
				&tagInformation, sizeof(tagInformation)) ||
			(tagInformation.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
		{
			CloseHandle(directoryHandle);
			SetLastError(ERROR_INVALID_DATA);
			return false;
		}

		std::array<HANDLE, 3> handles{};
		if (!OpenBundle(paths, FILE_SHARE_READ, handles, true))
		{
			CloseHandle(directoryHandle);
			return false;
		}

		detourBundleLocks[0] = directoryHandle;
		for (size_t index = 0; index < handles.size(); ++index)
		{
			detourBundleLocks[index + 1] = handles[index];
		}
		return true;
	}

	void DeleteCache(LPCWSTR directory, const BundlePaths& paths)
	{
		for (const auto& path : paths)
		{
			DeleteFileW(path.data());
		}
		RemoveDirectoryW(directory);
	}

	bool CacheDetourBundle(LPCWSTR modulePath)
	{
		BundlePaths sourcePaths{};
		size_t currentIndex = 0;
		if (!BuildBundlePaths(modulePath, sourcePaths, currentIndex))
		{
			return false;
		}

		std::array<HANDLE, 3> sourceHandles{};
		if (!OpenBundle(sourcePaths, FILE_SHARE_READ, sourceHandles))
		{
			return false;
		}

		WidePath cacheDirectory{};
		BundlePaths cachePaths{};
		if (!CreateUniqueCacheDirectory(cacheDirectory, cachePaths))
		{
			CloseHandles(sourceHandles);
			return false;
		}

		bool copied = true;
		for (size_t index = 0; index < cachePaths.size(); ++index)
		{
			if (!CopyFileW(
					sourcePaths[index].data(), cachePaths[index].data(), TRUE))
			{
				copied = false;
				break;
			}
		}
		CloseHandles(sourceHandles);
		if (!copied || !LockCache(cacheDirectory.data(), cachePaths))
		{
			const DWORD error = GetLastError();
			DeleteCache(cacheDirectory.data(), cachePaths);
			SetLastError(error);
			return false;
		}

		if (!CopyAsciiPath(cachePaths[currentIndex].data()))
		{
			CloseDetourBundleLocks();
			SetLastError(ERROR_NO_UNICODE_TRANSLATION);
			return false;
		}
		return true;
	}

	bool IsHexCharacter(WCHAR value)
	{
		return (value >= L'0' && value <= L'9') ||
			(value >= L'a' && value <= L'f') ||
			(value >= L'A' && value <= L'F');
	}

	bool ParseCachePath(
		LPCWSTR modulePath, WidePath& directory,
		BundlePaths& paths, size_t& currentIndex)
	{
		const DWORD windowsLength = GetSystemWindowsDirectoryW(
			directory.data(), static_cast<UINT>(directory.size()));
		if (windowsLength == 0 || windowsLength >= directory.size() ||
			wcscat_s(directory.data(), directory.size(),
				L"\\Temp\\WinPriv-") != 0)
		{
			return false;
		}
		const size_t prefixLength = wcslen(directory.data());
		if (prefixLength + cacheNonceCharacterCount + 1 > directory.size())
		{
			return false;
		}
		const size_t directoryLength = prefixLength + cacheNonceCharacterCount;
		if (wcslen(modulePath) <= directoryLength + 1)
		{
			return false;
		}
		if (_wcsnicmp(modulePath, directory.data(), prefixLength) != 0)
		{
			return false;
		}
		for (size_t index = 0; index < cacheNonceCharacterCount; ++index)
		{
			if (!IsHexCharacter(modulePath[prefixLength + index]))
			{
				return false;
			}
			directory[prefixLength + index] =
				modulePath[prefixLength + index];
		}
		if (modulePath[directoryLength] != L'\\')
		{
			return false;
		}
		directory[directoryLength] = L'\0';

		currentIndex = cachedBundleNames.size();
		for (size_t index = 0; index < cachedBundleNames.size(); ++index)
		{
			if (_wcsicmp(
					modulePath + directoryLength + 1,
					cachedBundleNames[index]) == 0)
			{
				currentIndex = index;
				break;
			}
		}
		return currentIndex != cachedBundleNames.size() &&
			BuildCacheFilePaths(directory.data(), paths);
	}

	bool LockExistingCache(LPCWSTR modulePath)
	{
		WidePath directory{};
		BundlePaths paths{};
		size_t currentIndex = 0;
		if (!ParseCachePath(modulePath, directory, paths, currentIndex))
		{
			return true;
		}
		if (!SameFile(modulePath, paths[currentIndex].data()) ||
			!LockCache(directory.data(), paths))
		{
			SetLastError(ERROR_INVALID_DATA);
			return false;
		}
		return true;
	}

	bool SetDetourLibraryPath(HINSTANCE instance)
	{
		std::array<WCHAR, MAX_PATH + 1> path{};
		const DWORD pathLength = GetModuleFileNameW(
			instance, path.data(), static_cast<DWORD>(path.size()));
		if (pathLength == 0 || pathLength >= path.size())
		{
			return false;
		}

		if (CopyAsciiPath(path.data()))
		{
			return LockExistingCache(path.data());
		}

		WCHAR* separator = wcsrchr(path.data(), L'\\');
		if (separator == nullptr || separator == path.data() ||
			!CopyAsciiPath(separator + 1))
		{
			SetLastError(ERROR_NO_UNICODE_TRANSLATION);
			return false;
		}
		LPCWSTR fileName = separator + 1;

		// Keep the architecture suffix in the long ASCII filename. The helper
		// replaces that suffix when it must inject another architecture.
		*separator = L'\0';
		std::array<WCHAR, MAX_PATH + 1> shortDirectory{};
		const DWORD shortLength = GetShortPathNameW(
			path.data(), shortDirectory.data(),
			static_cast<DWORD>(shortDirectory.size()));
		if (shortLength != 0 && shortLength < shortDirectory.size())
		{
			const size_t directoryLength = wcslen(shortDirectory.data());
			const size_t fileNameLength = wcslen(fileName);
			if (directoryLength + fileNameLength + 1 < shortDirectory.size())
			{
				shortDirectory[directoryLength] = L'\\';
				wcscpy_s(shortDirectory.data() + directoryLength + 1,
					shortDirectory.size() - directoryLength - 1, fileName);
				*separator = L'\\';
				if (CopyAsciiPath(shortDirectory.data()) &&
					SameFile(path.data(), shortDirectory.data()))
				{
					return true;
				}
				*separator = L'\0';
			}
		}

		*separator = L'\\';
		return CacheDetourBundle(path.data());
	}

	BOOL WINAPI HookCreateProcessA(_In_opt_ LPCSTR lpApplicationName, _Inout_opt_ LPSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCSTR lpCurrentDirectory, _In_ LPSTARTUPINFOA lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		std::vector<WCHAR> payload;
		if (!CaptureWinPrivPayload(payload))
		{
			return FALSE;
		}
		return DetourCreateProcessWithDllExA(lpApplicationName, lpCommandLine, lpProcessAttributes,
			lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
			lpStartupInfo, lpProcessInformation, detourLibrary.data(), &winPrivPayloadGuid,
			payload.data(), static_cast<DWORD>(payload.size() * sizeof(WCHAR)), trueCreateProcessA);
	}

	BOOL WINAPI HookCreateProcessW(_In_opt_ LPCWSTR lpApplicationName, _Inout_opt_ LPWSTR lpCommandLine,
		_In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes, _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
		_In_ BOOL bInheritHandles, _In_ DWORD dwCreationFlags, _In_opt_ LPVOID lpEnvironment,
		_In_opt_ LPCWSTR lpCurrentDirectory, _In_ LPSTARTUPINFOW lpStartupInfo,
		_Out_ LPPROCESS_INFORMATION lpProcessInformation)
	{
		std::vector<WCHAR> payload;
		if (!CaptureWinPrivPayload(payload))
		{
			return FALSE;
		}
		return DetourCreateProcessWithDllExW(lpApplicationName, lpCommandLine, lpProcessAttributes,
			lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
			lpStartupInfo, lpProcessInformation, detourLibrary.data(), &winPrivPayloadGuid,
			payload.data(), static_cast<DWORD>(payload.size() * sizeof(WCHAR)), trueCreateProcessW);
	}
}

EXTERN_C BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		if (DetourIsHelperProcess())
		{
			return TRUE;
		}

		(void)DetourRestoreAfterWith();
		if (!ApplyInjectedWinPrivPayload())
		{
			return FALSE;
		}
		if (!SetDetourLibraryPath(hinst))
		{
			return FALSE;
		}

		winpriv::detours::transaction transaction;
		if (!transaction)
		{
			CloseDetourBundleLocks();
			return FALSE;
		}

		DllExtraAttachDetach(winpriv::detours::action::attach);
		(void)transaction.apply(winpriv::detours::action::attach, trueCreateProcessA, HookCreateProcessA);
		(void)transaction.apply(winpriv::detours::action::attach, trueCreateProcessW, HookCreateProcessW);
		const LONG result = transaction.commit();
		if (result != NO_ERROR)
		{
			CloseDetourBundleLocks();
		}
		return result == NO_ERROR;
	}
	else if (dwReason == DLL_PROCESS_DETACH)
	{
		if (reserved != nullptr)
		{
			return TRUE;
		}

		winpriv::detours::transaction transaction;
		if (!transaction)
		{
			CloseDetourBundleLocks();
			return FALSE;
		}

		DllExtraAttachDetach(winpriv::detours::action::detach);
		(void)transaction.apply(winpriv::detours::action::detach, trueCreateProcessA, HookCreateProcessA);
		(void)transaction.apply(winpriv::detours::action::detach, trueCreateProcessW, HookCreateProcessW);
		const LONG result = transaction.commit();
		CloseDetourBundleLocks();
		return result == NO_ERROR;
	}

	return TRUE;
}


