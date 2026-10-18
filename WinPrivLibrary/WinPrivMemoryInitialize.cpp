//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivMemoryLoader.h"
#include "WinPrivDynamicCode.h"
#include <winternl.h>

extern "C" IMAGE_DOS_HEADER __ImageBase;

namespace winpriv::memory
{
#if defined(_M_IX86)
	decltype(&RtlUnwind) nativeUnwind = nullptr;
	using MemoryExceptionHandler = EXCEPTION_DISPOSITION(__cdecl*)(PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID);

	EXCEPTION_DISPOSITION __cdecl MemoryExceptionMarker(PEXCEPTION_RECORD, PVOID, PCONTEXT, PVOID)
	{
		return ExceptionContinueSearch;
	}

	bool IsMemoryExceptionHandler(PEXCEPTION_ROUTINE handler)
	{
		if (handler == reinterpret_cast<PEXCEPTION_ROUTINE>(MemoryExceptionMarker)) return true;
		const auto base = reinterpret_cast<PBYTE>(&__ImageBase);
		const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + __ImageBase.e_lfanew);
		const ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(handler) - reinterpret_cast<ULONG_PTR>(base);
		if (offset >= nt->OptionalHeader.SizeOfImage) return false;
		const auto config = reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY*>(base +
			nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress);
		const auto handlers = reinterpret_cast<const DWORD*>(config->SEHandlerTable);
		DWORD first = 0;
		DWORD last = config->SEHandlerCount;
		while (first < last)
		{
			const DWORD middle = first + (last - first) / 2;
			if (handlers[middle] < offset) first = middle + 1;
			else last = middle;
		}
		return first != config->SEHandlerCount && handlers[first] == offset;
	}

	__declspec(naked) void __stdcall UnwindNativeFrames(PVOID frame, PEXCEPTION_RECORD record)
	{
		// RtlUnwind resumes at the supplied address and does not preserve callee-saved registers.
		__asm
		{
			push ebp
			mov ebp, esp
			push ebx
			push esi
			push edi
			push 0
			push dword ptr [ebp + 12]
			push offset resumed
			push dword ptr [ebp + 8]
			call dword ptr [nativeUnwind]
		resumed:
			pop edi
			pop esi
			pop ebx
			pop ebp
			ret 8
		}
	}

	void __stdcall UnwindMemoryFrames(PVOID target, PEXCEPTION_RECORD record)
	{
		// Let Windows unwind registered modules, and validate private frames against our own SafeSEH table.
		if (target == nullptr || record == nullptr) return;
		const auto stack = reinterpret_cast<PNT_TIB>(NtCurrentTeb());
		ULONG_PTR minimum = reinterpret_cast<ULONG_PTR>(stack->StackLimit);
		const ULONG_PTR maximum = reinterpret_cast<ULONG_PTR>(stack->StackBase) - sizeof(EXCEPTION_REGISTRATION_RECORD);
		for (auto frame = stack->ExceptionList; ; frame = frame->Next)
		{
			const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(frame);
			if (address < minimum || address > maximum || (address & 3) != 0) return;
			if (frame == target) break;
			minimum = address + sizeof(*frame);
		}
		CONTEXT context;
		RtlCaptureContext(&context);
		for (auto frame = stack->ExceptionList; frame != target; frame = stack->ExceptionList)
		{
			while (frame != target && !IsMemoryExceptionHandler(frame->Handler)) frame = frame->Next;
			if (stack->ExceptionList != frame) UnwindNativeFrames(frame, record);
			if (frame == target) break;
			record->ExceptionFlags |= EXCEPTION_UNWINDING;
			PVOID dispatcher = nullptr;
			EXCEPTION_REGISTRATION_RECORD marker{ frame, reinterpret_cast<PEXCEPTION_ROUTINE>(MemoryExceptionMarker) };
			stack->ExceptionList = &marker;
			if (reinterpret_cast<MemoryExceptionHandler>(frame->Handler)(record, frame, &context, &dispatcher) !=
				ExceptionContinueSearch)
				RaiseFailFastException(nullptr, nullptr, 0);
			stack->ExceptionList = frame->Next;
		}
	}

	__declspec(naked) void WINAPI UnwindMemoryImage(PVOID target, PVOID instruction,
		PEXCEPTION_RECORD record, PVOID result)
	{
		// Preserve the caller's frame before tail-calling the operating system's final continuation.
		__asm
		{
			push ebp
			mov ebp, esp
			pushad
			push dword ptr [ebp + 16]
			push dword ptr [ebp + 8]
			call UnwindMemoryFrames
			popad
			pop ebp
			jmp dword ptr [nativeUnwind]
		}
	}

	LONG CALLBACK DispatchMemoryException(PEXCEPTION_POINTERS exception)
	{
		// Dispatch only this image's C++ exceptions through its compiler-listed SafeSEH handlers.
		const auto record = exception->ExceptionRecord;
		if (record->ExceptionCode != 0xe06d7363 || record->NumberParameters != 3 ||
			record->ExceptionInformation[0] != 0x19930520 || (record->ExceptionFlags & ~EXCEPTION_NONCONTINUABLE) != 0)
			return EXCEPTION_CONTINUE_SEARCH;
		const auto base = reinterpret_cast<PBYTE>(&__ImageBase);
		const ULONG_PTR imageBase = reinterpret_cast<ULONG_PTR>(base);
		const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + __ImageBase.e_lfanew);
		const ULONG_PTR throwInfo = record->ExceptionInformation[2];
		if (throwInfo != 0 && throwInfo - imageBase >= nt->OptionalHeader.SizeOfImage)
			return EXCEPTION_CONTINUE_SEARCH;
		const auto stack = reinterpret_cast<PNT_TIB>(NtCurrentTeb());
		ULONG_PTR minimum = reinterpret_cast<ULONG_PTR>(stack->StackLimit);
		const ULONG_PTR maximum = reinterpret_cast<ULONG_PTR>(stack->StackBase) - sizeof(EXCEPTION_REGISTRATION_RECORD);
		for (auto frame = stack->ExceptionList; ; frame = frame->Next)
		{
			const ULONG_PTR address = reinterpret_cast<ULONG_PTR>(frame);
			if (address < minimum || address > maximum || (address & 3) != 0) break;
			minimum = address + sizeof(*frame);
			if (address < exception->ContextRecord->Esp) continue;
			if (!IsMemoryExceptionHandler(frame->Handler)) break;
			PVOID dispatcher = nullptr;
			// The C++ runtime expects a dispatcher marker above the frame it is examining.
			EXCEPTION_REGISTRATION_RECORD marker{
				stack->ExceptionList, reinterpret_cast<PEXCEPTION_ROUTINE>(MemoryExceptionMarker) };
			stack->ExceptionList = &marker;
			const auto result = reinterpret_cast<MemoryExceptionHandler>(frame->Handler)(
				record, frame, exception->ContextRecord, &dispatcher);
			stack->ExceptionList = marker.Next;
			if (result == ExceptionContinueExecution) return EXCEPTION_CONTINUE_EXECUTION;
			if (result != ExceptionContinueSearch) break;
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}
#else
	decltype(&RtlPcToFileHeader) nativeImageBase = nullptr;

	PVOID NTAPI FindMemoryImageBase(PVOID address, PVOID* imageBase)
	{
		// C++ exception metadata uses image-relative addresses even for privately mapped code.
		const auto base = reinterpret_cast<PBYTE>(&__ImageBase);
		const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + __ImageBase.e_lfanew);
		if (reinterpret_cast<ULONG_PTR>(address) - reinterpret_cast<ULONG_PTR>(base) < nt->OptionalHeader.SizeOfImage)
		{
			*imageBase = base;
			return base;
		}
		return nativeImageBase(address, imageBase);
	}
#endif

	__declspec(noinline) bool SameExportName(const char* left, const char* right)
	{
		while (*left != '\0' && *left == *right)
		{
			++left;
			++right;
		}
		return *left == *right;
	}

	PBYTE FindNativeModule()
	{
		PBYTE nativeModule = nullptr;
		const auto list = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
		for (auto link = list->Flink; link != list; link = link->Flink)
		{
			const auto module = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
			const auto candidate = static_cast<PBYTE>(module->DllBase);
			if (candidate == nullptr) continue;
			const auto candidateDos = reinterpret_cast<IMAGE_DOS_HEADER*>(candidate);
			const auto candidateNt = reinterpret_cast<IMAGE_NT_HEADERS*>(candidate + candidateDos->e_lfanew);
			const auto& exports = candidateNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			if (exports.Size == 0) continue;
			const auto directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(candidate + exports.VirtualAddress);
			if (SameExportName(reinterpret_cast<LPCSTR>(candidate + directory->Name), "ntdll.dll"))
			{
				nativeModule = candidate;
				break;
			}
		}
		return nativeModule;
	}

	PVOID FindNativeExport(PBYTE module, LPCSTR name)
	{
		const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
		const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(module + dos->e_lfanew);
		const auto& exports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (exports.Size == 0) return nullptr;
		const auto directory = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(module + exports.VirtualAddress);
		const auto names = reinterpret_cast<DWORD*>(module + directory->AddressOfNames);
		const auto ordinals = reinterpret_cast<WORD*>(module + directory->AddressOfNameOrdinals);
		const auto functions = reinterpret_cast<DWORD*>(module + directory->AddressOfFunctions);
		for (DWORD index = 0; index < directory->NumberOfNames; ++index)
		{
			if (SameExportName(reinterpret_cast<LPCSTR>(module + names[index]), name))
				return module + functions[ordinals[index]];
		}
		return nullptr;
	}
}

#if defined(_M_IX86)
#pragma comment(linker, "/export:WinPrivInitializeMemory=_WinPrivInitializeMemory@4")
#else
#pragma comment(linker, "/export:WinPrivInitializeMemory")
#endif

extern "C" DWORD WINAPI WinPrivInitializeMemory(winpriv::memory::Initialization* context)
{
	using namespace winpriv::memory;
	const auto base = reinterpret_cast<PBYTE>(static_cast<ULONG_PTR>(context->image));
	const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
	const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);

	// Resolve the native loader functions without depending on this image's uninitialized import table.
	PBYTE nativeModule = FindNativeModule();
	if (nativeModule == nullptr) return context->error = ERROR_MOD_NOT_FOUND;
	const auto loadDll = reinterpret_cast<NTSTATUS(NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE)>(
		FindNativeExport(nativeModule, "LdrLoadDll"));
	const auto getProcedure = reinterpret_cast<NTSTATUS(NTAPI*)(PVOID, PANSI_STRING, ULONG, PVOID*)>(
		FindNativeExport(nativeModule, "LdrGetProcedureAddress"));
	const auto statusToError = reinterpret_cast<ULONG(NTAPI*)(NTSTATUS)>(
		FindNativeExport(nativeModule, "RtlNtStatusToDosError"));
	if (loadDll == nullptr || getProcedure == nullptr || statusToError == nullptr)
		return context->error = ERROR_PROC_NOT_FOUND;

	// Resolve dependencies in the target process, including forwarded exports and API-set contracts.
	const auto& importDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDirectory.Size != 0)
	{
		const auto imports = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + importDirectory.VirtualAddress);
		const size_t count = importDirectory.Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
		for (size_t index = 0; index < count && imports[index].Name != 0; ++index)
		{
			const auto& import = imports[index];
			WCHAR nameBuffer[256];
			USHORT length = 0;
			const auto name = reinterpret_cast<LPCSTR>(base + import.Name);
			while (name[length] != '\0' && length < 255)
			{
				nameBuffer[length] = static_cast<BYTE>(name[length]);
				++length;
			}
			if (length == 255) return context->error = ERROR_BAD_EXE_FORMAT;
			nameBuffer[length] = L'\0';
			UNICODE_STRING libraryName;
			libraryName.Length = length * sizeof(WCHAR);
			libraryName.MaximumLength = libraryName.Length + sizeof(WCHAR);
			libraryName.Buffer = nameBuffer;
			HANDLE dependency = nullptr;
			NTSTATUS status = loadDll(nullptr, nullptr, &libraryName, &dependency);
			if (status < 0) return context->error = statusToError(status);
			const auto source = reinterpret_cast<IMAGE_THUNK_DATA*>(base +
				(import.OriginalFirstThunk != 0 ? import.OriginalFirstThunk : import.FirstThunk));
			const auto destination = reinterpret_cast<IMAGE_THUNK_DATA*>(base + import.FirstThunk);
			for (size_t thunk = 0; source[thunk].u1.AddressOfData != 0; ++thunk)
			{
				PVOID procedure = nullptr;
				const auto address = source[thunk].u1.AddressOfData;
				if (IMAGE_SNAP_BY_ORDINAL(address))
					status = getProcedure(dependency, nullptr, IMAGE_ORDINAL(address), &procedure);
				else
				{
					const auto named = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + address);
					ANSI_STRING procedureName;
					procedureName.Length = 0;
					while (named->Name[procedureName.Length] != '\0') ++procedureName.Length;
					procedureName.MaximumLength = procedureName.Length + 1;
					procedureName.Buffer = named->Name;
					status = getProcedure(dependency, &procedureName, 0, &procedure);
#if defined(_WIN64)
					if (status >= 0 && SameExportName(named->Name, "RtlPcToFileHeader"))
					{
						nativeImageBase = reinterpret_cast<decltype(nativeImageBase)>(procedure);
						procedure = reinterpret_cast<PVOID>(FindMemoryImageBase);
					}
#else
					if (status >= 0 && SameExportName(named->Name, "RtlUnwind"))
					{
						nativeUnwind = reinterpret_cast<decltype(nativeUnwind)>(procedure);
						procedure = reinterpret_cast<PVOID>(UnwindMemoryImage);
					}
#endif
				}
				if (status < 0) return context->error = statusToError(status);
				destination[thunk].u1.Function = reinterpret_cast<ULONG_PTR>(procedure);
			}
		}
	}

	// Use the operating system's CFG dispatch functions for indirect calls from this image.
	const auto& configuration = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	const auto config = configuration.Size >= sizeof(DWORD) ?
		reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY*>(base + configuration.VirtualAddress) : nullptr;
	if (config != nullptr && config->Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) + sizeof(DWORD))
	{
		const auto nativeDos = reinterpret_cast<IMAGE_DOS_HEADER*>(nativeModule);
		const auto nativeNt = reinterpret_cast<IMAGE_NT_HEADERS*>(nativeModule + nativeDos->e_lfanew);
		const auto& nativeConfiguration = nativeNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
		const auto nativeConfig = nativeConfiguration.Size >= sizeof(DWORD) ?
			reinterpret_cast<IMAGE_LOAD_CONFIG_DIRECTORY*>(nativeModule + nativeConfiguration.VirtualAddress) : nullptr;
		if (nativeConfig != nullptr &&
			nativeConfig->Size >= offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) + sizeof(DWORD))
		{
			if (config->GuardCFCheckFunctionPointer && nativeConfig->GuardCFCheckFunctionPointer)
				*reinterpret_cast<ULONG_PTR*>(config->GuardCFCheckFunctionPointer) =
					*reinterpret_cast<ULONG_PTR*>(nativeConfig->GuardCFCheckFunctionPointer);
			if (config->GuardCFDispatchFunctionPointer && nativeConfig->GuardCFDispatchFunctionPointer)
				*reinterpret_cast<ULONG_PTR*>(config->GuardCFDispatchFunctionPointer) =
					*reinterpret_cast<ULONG_PTR*>(nativeConfig->GuardCFDispatchFunctionPointer);
		}
	}

	// Static TLS requires Windows loader registration; the memory-loaded library uses dynamic TLS instead.
	const auto& tlsDirectory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	if (tlsDirectory.Size != 0)
	{
		const auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tlsDirectory.VirtualAddress);
		if (tls->EndAddressOfRawData != tls->StartAddressOfRawData || tls->SizeOfZeroFill != 0)
			return context->error = ERROR_NOT_SUPPORTED;
	}

	// Finalize page permissions and register unwind information before running any C++ initialization.
	winpriv::DynamicCodeScope codeScope;
	if (codeScope.Result() != NO_ERROR) return context->error = codeScope.Result();
	const auto sections = IMAGE_FIRST_SECTION(nt);
	for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index)
	{
		const auto& section = sections[index];
		const bool execute = (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
		const bool write = (section.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
		const bool read = (section.Characteristics & IMAGE_SCN_MEM_READ) != 0;
		DWORD protection = execute ? (write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) :
			(write ? PAGE_READWRITE : (read ? PAGE_READONLY : PAGE_NOACCESS));
		DWORD previous = 0;
		const SIZE_T size = section.Misc.VirtualSize > section.SizeOfRawData ?
			section.Misc.VirtualSize : section.SizeOfRawData;
		if (size != 0 && !VirtualProtect(base + section.VirtualAddress, size, protection, &previous))
			return context->error = GetLastError();
	}
	DWORD previous = 0;
	if (!VirtualProtect(base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &previous) ||
		!FlushInstructionCache(GetCurrentProcess(), base, nt->OptionalHeader.SizeOfImage))
		return context->error = GetLastError();
#if defined(_WIN64)
	const auto& exceptions = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	const auto functions = reinterpret_cast<PRUNTIME_FUNCTION>(base + exceptions.VirtualAddress);
	if (exceptions.Size != 0 && !RtlAddFunctionTable(functions,
		exceptions.Size / sizeof(RUNTIME_FUNCTION), reinterpret_cast<DWORD64>(base)))
		return context->error = ERROR_DLL_INIT_FAILED;
#else
	if (nativeUnwind == nullptr || config == nullptr ||
		config->Size < offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, SEHandlerCount) + sizeof(DWORD))
		return context->error = ERROR_BAD_EXE_FORMAT;
	if (config->SEHandlerTable == 0 || config->SEHandlerCount == 0)
		return context->error = ERROR_BAD_EXE_FORMAT;
	PVOID exceptionHandler = AddVectoredExceptionHandler(1, DispatchMemoryException);
	if (exceptionHandler == nullptr) return context->error = ERROR_NOT_ENOUGH_MEMORY;
#endif
	if (tlsDirectory.Size != 0)
	{
		const auto tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(base + tlsDirectory.VirtualAddress);
		if (tls->AddressOfCallBacks != 0)
		{
			for (auto callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks); *callback; ++callback)
				(*callback)(base, DLL_PROCESS_ATTACH, context);
		}
	}
	using Entry = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
	const auto entry = reinterpret_cast<Entry>(base + nt->OptionalHeader.AddressOfEntryPoint);
	if (!entry(reinterpret_cast<HINSTANCE>(base), DLL_PROCESS_ATTACH, context))
	{
#if defined(_WIN64)
		if (exceptions.Size != 0) RtlDeleteFunctionTable(functions);
#else
		RemoveVectoredExceptionHandler(exceptionHandler);
#endif
		return context->error = context->error == NO_ERROR ? ERROR_DLL_INIT_FAILED : context->error;
	}
	return context->error = NO_ERROR;
}
