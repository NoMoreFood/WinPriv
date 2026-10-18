//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivLibrary.h"
#include "WinPrivMemoryLoader.h"
#include <array>
#include <vector>

namespace winpriv::library
{
	const memory::LibraryBundle* libraryBundle = nullptr;

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

		// Initialize the child's hooks before allowing its primary thread to execute.
		DWORD error = NO_ERROR;
		if (!memory::InjectLibrary(process->hProcess, libraryBundle, payload.data(),
			static_cast<DWORD>(payload.size() * sizeof(WCHAR)))) error = GetLastError();
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

EXTERN_C BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	using namespace winpriv::library;
	if (reason != DLL_PROCESS_ATTACH) return TRUE;

	// Keep an immutable copy of every architecture's raw image for subsequent child launches.
	const auto context = static_cast<winpriv::memory::Initialization*>(reserved);
	if (context == nullptr || context->image != reinterpret_cast<ULONG_PTR>(instance)) return FALSE;
	try
	{
		libraryBundle = reinterpret_cast<const winpriv::memory::LibraryBundle*>(static_cast<ULONG_PTR>(context->bundle));
		if (context->settingsSize != 0 && !ApplyWinPrivPayload(
			reinterpret_cast<LPCVOID>(static_cast<ULONG_PTR>(context->settings)), context->settingsSize))
		{
			context->error = GetLastError();
			return FALSE;
		}

		// The private CRT has no loader shutdown callback to flush buffered diagnostic output.
		setvbuf(stdout, nullptr, _IONBF, 0);

		// Install feature and child-process hooks in one transaction; the image remains loaded until process exit.
		winpriv::detours::transaction transaction;
		if (!transaction)
		{
			context->error = transaction.commit();
			return FALSE;
		}
		SetLastError(NO_ERROR);
		if (!AttachExtraHooks())
		{
			const DWORD error = GetLastError();
			context->error = error == NO_ERROR ? ERROR_DLL_INIT_FAILED : error;
			return FALSE;
		}
		(void)transaction.attach(trueCreateProcessA, HookCreateProcessA);
		(void)transaction.attach(trueCreateProcessW, HookCreateProcessW);
		context->error = transaction.commit();
		return context->error == NO_ERROR;
	}
	catch (...)
	{
		context->error = ERROR_NOT_ENOUGH_MEMORY;
		return FALSE;
	}
}
