//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivLibrary.h"
#include "WinPrivDllLoader.h"
#include <array>
#include <fcntl.h>
#include <io.h>
#include <vector>

namespace winpriv::library
{
	loader::LibraryBundle libraryBundle;
	bool hooksInstalled = false;
	const auto queryObject = LoadNtFunction<NTSTATUS(NTAPI*)(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG)>(
		"NtQueryObject");

	auto trueCreateProcessA = &CreateProcessA;
	auto trueCreateProcessW = &CreateProcessW;

	bool CaptureWinPrivPayload(std::vector<WCHAR>& payload) noexcept
	{
		try
		{
			// Only the launcher's direct target pauses its console at exit; later descendants exit normally.
			constexpr size_t maximumCharacters = MAXDWORD / sizeof(WCHAR);
			const bool launcher = VariableIsSet(WINPRIV_EV_PARENT_PID, GetCurrentProcessId());
			for (LPCWSTR name : WinPrivSettingNames)
			{
				SetLastError(NO_ERROR);
				const DWORD required = !launcher && wcscmp(name, WINPRIV_EV_RELAUNCH_MODE) == 0 ? 0 :
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

				if (required > _MAX_ENV || required > maximumCharacters - payload.size())
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

		std::array<LPCWSTR, WinPrivSettingNames.size()> values{};
		LPCWSTR cursor = static_cast<LPCWSTR>(payload);
		size_t remaining = payloadSize / sizeof(WCHAR);
		for (LPCWSTR& value : values)
		{
			const WCHAR* terminator = wmemchr(cursor, L'\0', remaining);
			if (terminator == nullptr || terminator - cursor >= _MAX_ENV)
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

		for (size_t index = 0; index < WinPrivSettingNames.size(); ++index)
		{
			if (_wputenv_s(WinPrivSettingNames[index], values[index]) != 0)
			{
				SetLastError(ERROR_BAD_ENVIRONMENT);
				return false;
			}
			if (*values[index] == L'\0' &&
				!SetEnvironmentVariableW(WinPrivSettingNames[index], L""))
			{
				return false;
			}
		}
		return true;
	}

	BOOL CompleteChildInjection(BOOL created, DWORD creationFlags, LPPROCESS_INFORMATION process,
		const std::vector<WCHAR>& payload)
	{
		if (!created) return FALSE;

		// Children that cannot hook, load non-Microsoft DLLs, or read ordinary files run without hooks.
		DWORD error = NO_ERROR;
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamic{};
		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signature{};
		SmartPointer<HANDLE> token(CloseHandle, nullptr);
		DWORD appContainer = FALSE;
		DWORD length = 0;
		if (!GetProcessMitigationPolicy(process->hProcess, ProcessDynamicCodePolicy, &dynamic, sizeof(dynamic)) ||
			!GetProcessMitigationPolicy(process->hProcess, ProcessSignaturePolicy, &signature, sizeof(signature)) ||
			!OpenProcessToken(process->hProcess, TOKEN_QUERY, &token) ||
			!GetTokenInformation(token, TokenIsAppContainer, &appContainer, sizeof(appContainer), &length))
			error = GetLastError();
		else if ((!dynamic.ProhibitDynamicCode || dynamic.AllowThreadOptOut) &&
			!signature.MicrosoftSignedOnly && !signature.StoreSignedOnly && !appContainer)
		{
			try
			{
				std::vector<BYTE> data(sizeof(libraryBundle) + payload.size() * sizeof(WCHAR));
				loader::LibraryBundle childBundle = libraryBundle;
				for (ULONGLONG& file : childBundle.handles)
				{
					if (file == 0) continue;
					HANDLE childFile = nullptr;
					if (!DuplicateHandle(GetCurrentProcess(), reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(file)),
						process->hProcess, &childFile, 0, FALSE, DUPLICATE_SAME_ACCESS))
					{
						error = GetLastError();
						break;
					}
					file = reinterpret_cast<ULONG_PTR>(childFile);
				}
				memcpy(data.data(), &childBundle, sizeof(childBundle));
				memcpy(data.data() + sizeof(childBundle), payload.data(), payload.size() * sizeof(WCHAR));
				if (error == NO_ERROR && !loader::InjectLibrary(process->hProcess, data.data(),
					static_cast<DWORD>(data.size()), trueCreateProcessW))
				{
					error = GetLastError();
					if (error == NO_ERROR) error = ERROR_DLL_INIT_FAILED;
				}
			}
			catch (...)
			{
				error = ERROR_NOT_ENOUGH_MEMORY;
			}
		}
		if (error == NO_ERROR && !(creationFlags & CREATE_SUSPENDED) && ResumeThread(process->hThread) == MAXDWORD)
			error = GetLastError();
		if (error == NO_ERROR) return TRUE;

		TerminateProcess(process->hProcess, error);
		CloseHandle(process->hThread);
		CloseHandle(process->hProcess);
		*process = {};
		SetLastError(error);
		return FALSE;
	}

	BOOL WINAPI HookCreateProcessA(LPCSTR applicationName, LPSTR commandLine,
		LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles,
		DWORD creationFlags, LPVOID environment, LPCSTR currentDirectory, LPSTARTUPINFOA startupInfo,
		LPPROCESS_INFORMATION processInformation)
	{
		std::vector<WCHAR> payload;
		if (!CaptureWinPrivPayload(payload)) return FALSE;
		return CompleteChildInjection(trueCreateProcessA(applicationName, commandLine, processAttributes,
			threadAttributes, inheritHandles, creationFlags | CREATE_SUSPENDED, environment, currentDirectory,
			startupInfo, processInformation), creationFlags, processInformation, payload);
	}

	BOOL WINAPI HookCreateProcessW(LPCWSTR applicationName, LPWSTR commandLine,
		LPSECURITY_ATTRIBUTES processAttributes, LPSECURITY_ATTRIBUTES threadAttributes, BOOL inheritHandles,
		DWORD creationFlags, LPVOID environment, LPCWSTR currentDirectory, LPSTARTUPINFOW startupInfo,
		LPPROCESS_INFORMATION processInformation)
	{
		std::vector<WCHAR> payload;
		if (!CaptureWinPrivPayload(payload)) return FALSE;
		return CompleteChildInjection(trueCreateProcessW(applicationName, commandLine, processAttributes,
			threadAttributes, inheritHandles, creationFlags | CREATE_SUSPENDED, environment, currentDirectory,
			startupInfo, processInformation), creationFlags, processInformation, payload);
	}
}

#if defined(_M_IX86)
#pragma comment(linker, "/export:WinPrivInitialize=_WinPrivInitialize@4")
#else
#pragma comment(linker, "/export:WinPrivInitialize")
#endif

extern "C" BOOL WINAPI _DllMainCRTStartup(HINSTANCE instance, DWORD reason, LPVOID reserved);

extern "C" BOOL WINAPI WinPrivDllEntry(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	// System DLLs can still call WinPriv's hooks during process shutdown.
	if (reason == DLL_PROCESS_DETACH && reserved != nullptr && winpriv::library::hooksInstalled)
	{
		// Serialize final-owner cleanup without removing files that surviving descendants still need.
		using namespace winpriv::library;
		const HANDLE mutex = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(libraryBundle.handles[3]));
		const DWORD wait = mutex != nullptr ? WaitForSingleObject(mutex, 5000) : WAIT_FAILED;
		const bool locked = wait == WAIT_OBJECT_0 || wait == WAIT_ABANDONED;
		for (size_t index = 0; index < std::size(libraryBundle.paths); ++index)
		{
			const HANDLE file = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(libraryBundle.handles[index]));
			if (file == nullptr) continue;
			PUBLIC_OBJECT_BASIC_INFORMATION information{};
			if (locked && queryObject(file, ObjectBasicInformation, &information, sizeof(information), nullptr) >= 0 &&
				information.HandleCount == 1)
			{
				FILE_DISPOSITION_INFO_EX disposition{ FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS };
				SetFileInformationByHandle(file, FileDispositionInfoEx, &disposition, sizeof(disposition));
			}
			CloseHandle(file);
		}
		if (locked) ReleaseMutex(mutex);
		if (mutex != nullptr) CloseHandle(mutex);
		// shortcut: forced termination skips DLL cleanup; add an external owner if crash cleanup becomes required.
		return TRUE;
	}
	return _DllMainCRTStartup(instance, reason, reserved);
}

extern "C" DWORD WINAPI WinPrivInitialize(const winpriv::loader::LibraryBundle* bundle)
{
	using namespace winpriv::library;
	try
	{
		if (hooksInstalled) return ERROR_ALREADY_INITIALIZED;
		if (bundle == nullptr) return ERROR_INVALID_PARAMETER;
		for (size_t index = 0; index < std::size(bundle->paths); ++index)
		{
			if (bundle->paths[index][0] == '\0' ||
				memchr(bundle->paths[index], '\0', sizeof(bundle->paths[index])) == nullptr) return ERROR_INVALID_DATA;
		}
		libraryBundle = *bundle;

		// Flush diagnostic output as it is written by the library's CRT.
		if (const int output = _fileno(stdout); output >= 0) (void)_setmode(output, _O_U8TEXT);
		setvbuf(stdout, nullptr, _IONBF, 0);

		// Install feature and child-process hooks in one transaction; the image remains loaded until process exit.
		winpriv::detours::transaction transaction;
		if (transaction.error() != NO_ERROR) return transaction.error();
		SetLastError(NO_ERROR);
		if (!AttachExtraHooks(transaction))
		{
			const DWORD error = GetLastError();
			return error == NO_ERROR ? ERROR_DLL_INIT_FAILED : error;
		}
		transaction.attach(trueCreateProcessA, HookCreateProcessA);
		transaction.attach(trueCreateProcessW, HookCreateProcessW);
		const DWORD error = transaction.commit();
		hooksInstalled = error == NO_ERROR;
		return error;
	}
	catch (...)
	{
		return ERROR_NOT_ENOUGH_MEMORY;
	}
}

extern "C" BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID)
{
	if (reason != DLL_PROCESS_ATTACH || DetourIsHelperProcess()) return TRUE;

	// Restore the executable's import table and settings before its TLS callbacks and entry point run.
	DWORD size = 0;
	const auto payload = static_cast<const BYTE*>(DetourFindPayload(winpriv::loader::payloadGuid, size));
	if (payload == nullptr) return GetLastError() == ERROR_MOD_NOT_FOUND;
	DWORD error = ERROR_INVALID_DATA;
	if (size >= sizeof(winpriv::loader::LibraryBundle) && DetourRestoreAfterWith() &&
		winpriv::library::ApplyWinPrivPayload(payload + sizeof(winpriv::loader::LibraryBundle),
			size - sizeof(winpriv::loader::LibraryBundle)))
		error = WinPrivInitialize(reinterpret_cast<const winpriv::loader::LibraryBundle*>(payload));
	DetourFreePayload(const_cast<BYTE*>(payload));
	SetLastError(error);
	return error == NO_ERROR;
}
