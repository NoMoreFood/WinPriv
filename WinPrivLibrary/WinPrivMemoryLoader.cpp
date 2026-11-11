//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#if defined(_M_IX86)
#include "WinPrivWow64Call.h"
#endif
#include "WinPrivMemoryLoader.h"
#include "WinPrivDynamicCode.h"
#include "WinPrivShared.h"
#include <compressapi.h>
#include <wincrypt.h>
#include <mscat.h>
#include <algorithm>
#include <cstring>
#include <memory>

#pragma comment(lib, "cabinet.lib")
#pragma comment(lib, "wintrust.lib")

namespace winpriv::memory
{
	constexpr std::array<WORD, 3> machines{
		IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM64 };
	constexpr DWORD digestSize = 32;
	constexpr DWORD maxLibrarySize = 64 * 1024 * 1024;

	struct MappedImage
	{
		std::vector<BYTE> bytes;
		std::vector<IMAGE_SECTION_HEADER> sections;
		IMAGE_DATA_DIRECTORY relocations{};
		IMAGE_DATA_DIRECTORY unwind{};
		ULONGLONG preferredBase = 0;
		DWORD initialize = 0;
		WORD machine = 0;
	};

	bool ImageRange(size_t offset, size_t size, size_t limit)
	{
		return offset <= limit && size <= limit - offset;
	}

	bool PrepareImage(LibraryImage source, WORD machine, MappedImage& image)
	{
		// Validate the PE before interpreting any offsets or copying its sections.
		if (source.data == nullptr || source.size < sizeof(IMAGE_DOS_HEADER)) return false;
		const auto data = static_cast<const BYTE*>(source.data);
		const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(data);
		if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(*dos) ||
			!ImageRange(dos->e_lfanew, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER), source.size)) return false;
		const auto signature = reinterpret_cast<const DWORD*>(data + dos->e_lfanew);
		const auto header = reinterpret_cast<const IMAGE_FILE_HEADER*>(signature + 1);
		if (*signature != IMAGE_NT_SIGNATURE || header->Machine != machine ||
			(header->Characteristics & IMAGE_FILE_DLL) == 0 || header->NumberOfSections == 0) return false;
		const size_t optionalOffset = reinterpret_cast<const BYTE*>(header + 1) - data;
		if (!ImageRange(optionalOffset, header->SizeOfOptionalHeader, source.size)) return false;
		DWORD imageSize = 0;
		DWORD headerSize = 0;
		IMAGE_DATA_DIRECTORY exports{};
		const auto readOptional = [&]<typename Header>(const Header* optional)
		{
			if (header->SizeOfOptionalHeader < sizeof(Header) || optional->SectionAlignment < 0x1000 ||
				optional->NumberOfRvaAndSizes != IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return false;
			imageSize = optional->SizeOfImage;
			headerSize = optional->SizeOfHeaders;
			image.preferredBase = optional->ImageBase;
			image.relocations = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			image.unwind = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
			exports = optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			for (const auto& directory : optional->DataDirectory)
			{
				if (&directory == &optional->DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]) continue;
				if (!ImageRange(directory.VirtualAddress, directory.Size, imageSize)) return false;
			}
			return true;
		};
		if (machine == IMAGE_FILE_MACHINE_I386)
		{
			const auto optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(data + optionalOffset);
			if (!readOptional(optional) || optional->Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) return false;
		}
		else
		{
			const auto optional = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(data + optionalOffset);
			if (!readOptional(optional) || optional->Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
		}
		const size_t sectionsOffset = optionalOffset + header->SizeOfOptionalHeader;
		if (imageSize == 0 || imageSize > 256 * 1024 * 1024 || headerSize > imageSize ||
			headerSize > source.size ||
			!ImageRange(sectionsOffset, header->NumberOfSections * sizeof(IMAGE_SECTION_HEADER), headerSize)) return false;
		image.bytes.resize(imageSize);
		image.machine = machine;
		memcpy(image.bytes.data(), data, headerSize);
		const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(data + sectionsOffset);
		image.sections.assign(sections, sections + header->NumberOfSections);
		DWORD previousEnd = headerSize;
		for (const auto& section : image.sections)
		{
			const DWORD size = (std::max)(section.Misc.VirtualSize, section.SizeOfRawData);
			if (section.VirtualAddress < previousEnd || (section.VirtualAddress & 0xfff) != 0 ||
				!ImageRange(section.VirtualAddress, size, imageSize) ||
				!ImageRange(section.PointerToRawData, section.SizeOfRawData, source.size)) return false;
			memcpy(image.bytes.data() + section.VirtualAddress, data + section.PointerToRawData,
				section.SizeOfRawData);
			previousEnd = section.VirtualAddress + size;
		}

		// Locate the architecture-native initializer exported by the library.
		if (exports.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return false;
		const auto directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
			image.bytes.data() + exports.VirtualAddress);
		if (directory->NumberOfNames > imageSize / sizeof(DWORD) ||
			directory->NumberOfFunctions > imageSize / sizeof(DWORD) ||
			!ImageRange(directory->AddressOfNames, size_t(directory->NumberOfNames) * sizeof(DWORD), imageSize) ||
			!ImageRange(directory->AddressOfNameOrdinals, size_t(directory->NumberOfNames) * sizeof(WORD), imageSize) ||
			!ImageRange(directory->AddressOfFunctions, size_t(directory->NumberOfFunctions) * sizeof(DWORD), imageSize))
			return false;
		const auto names = reinterpret_cast<const DWORD*>(image.bytes.data() + directory->AddressOfNames);
		const auto ordinals = reinterpret_cast<const WORD*>(image.bytes.data() + directory->AddressOfNameOrdinals);
		const auto functions = reinterpret_cast<const DWORD*>(image.bytes.data() + directory->AddressOfFunctions);
		constexpr char initializer[] = "WinPrivInitializeMemory";
		constexpr size_t initializerSize = sizeof(initializer);
		for (DWORD index = 0; index < directory->NumberOfNames; ++index)
		{
			if (!ImageRange(names[index], initializerSize, imageSize) ||
				memcmp(image.bytes.data() + names[index], initializer, initializerSize) != 0) continue;
			if (ordinals[index] >= directory->NumberOfFunctions) return false;
			image.initialize = functions[ordinals[index]];
			return image.initialize < imageSize && std::ranges::any_of(image.sections, [&](const auto& section)
			{
				return (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
					image.initialize >= section.VirtualAddress &&
					image.initialize - section.VirtualAddress < section.Misc.VirtualSize;
			});
		}
		return false;
	}

	bool RelocateImage(MappedImage& image, ULONGLONG address)
	{
		// Relocate virtual addresses in the mapped image, never in the raw file layout.
		const ULONGLONG delta = address - image.preferredBase;
		if (delta == 0) return true;
		if (image.relocations.Size == 0) return false;
		size_t offset = image.relocations.VirtualAddress;
		const size_t end = offset + image.relocations.Size;
		while (offset < end)
		{
			if (!ImageRange(offset, sizeof(IMAGE_BASE_RELOCATION), end)) return false;
			const auto block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(image.bytes.data() + offset);
			if (block->VirtualAddress > image.bytes.size() || block->SizeOfBlock < sizeof(*block) ||
				block->SizeOfBlock % sizeof(WORD) != 0 ||
				!ImageRange(offset, block->SizeOfBlock, end)) return false;
			const auto entries = reinterpret_cast<const WORD*>(block + 1);
			const size_t count = (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD);
			for (size_t index = 0; index < count; ++index)
			{
				const WORD type = entries[index] >> 12;
				const size_t target = size_t(block->VirtualAddress) + (entries[index] & 0xfff);
				if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
				if (type == IMAGE_REL_BASED_HIGHLOW && image.machine == IMAGE_FILE_MACHINE_I386 &&
					ImageRange(target, sizeof(DWORD), image.bytes.size()))
					*reinterpret_cast<DWORD*>(image.bytes.data() + target) += static_cast<DWORD>(delta);
				else if (type == IMAGE_REL_BASED_DIR64 && image.machine != IMAGE_FILE_MACHINE_I386 &&
					ImageRange(target, sizeof(ULONGLONG), image.bytes.size()))
					*reinterpret_cast<ULONGLONG*>(image.bytes.data() + target) += delta;
				else return false;
			}
			offset += block->SizeOfBlock;
		}
		return true;
	}

	bool DecompressLibrary(LibraryImage resource, std::vector<BYTE>& bytes)
	{
		if (resource.data == nullptr || resource.size <= digestSize)
		{
			SetLastError(ERROR_BAD_COMPRESSION_BUFFER);
			return false;
		}
		const auto compressed = static_cast<const BYTE*>(resource.data) + digestSize;
		const DWORD compressedSize = resource.size - digestSize;
		SmartPointer<DECOMPRESSOR_HANDLE> decompressor(CloseDecompressor, nullptr);
		if (!CreateDecompressor(COMPRESS_ALGORITHM_LZMS, nullptr, &decompressor)) return false;
		SIZE_T size = 0;
		if (Decompress(decompressor, compressed, compressedSize, nullptr, 0, &size) ||
			GetLastError() != ERROR_INSUFFICIENT_BUFFER) return false;
		if (size == 0 || size > maxLibrarySize)
		{
			SetLastError(ERROR_BAD_COMPRESSION_BUFFER);
			return false;
		}
		try
		{
			bytes.resize(size);
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
		return Decompress(decompressor, compressed, compressedSize, bytes.data(), bytes.size(), &size) != FALSE;
	}

	bool CreateBundle(const std::array<LibraryImage, 3>& resources, std::wstring_view directory,
		std::vector<BYTE>& bytes) noexcept
	{
		try
		{
			LibraryBundle bundle{ (sizeof(LibraryBundle) + 7) & ~DWORD(7) };
			if (directory.empty() || directory.size() >= std::size(bundle.directory))
			{
				SetLastError(ERROR_BAD_PATHNAME);
				return false;
			}
			directory.copy(bundle.directory, directory.size());
			for (size_t index = 0; index < resources.size(); ++index)
			{
				if (resources[index].data == nullptr || resources[index].size <= digestSize ||
					resources[index].size > MAXDWORD - bundle.size - 7)
				{
					SetLastError(ERROR_BAD_EXE_FORMAT);
					return false;
				}
				bundle.offsets[index] = bundle.size;
				bundle.sizes[index] = resources[index].size;
				bundle.size = (bundle.size + resources[index].size + 7) & ~DWORD(7);
			}
			bytes.resize(bundle.size);
			memcpy(bytes.data(), &bundle, sizeof(bundle));
			for (size_t index = 0; index < resources.size(); ++index)
				memcpy(bytes.data() + bundle.offsets[index], resources[index].data, resources[index].size);
			return true;
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}

	PVOID AllocateImageMemory(HANDLE process, SIZE_T size)
	{
#if defined(_M_IX86)
		// A 32-bit caller must keep every remote allocation address representable in its own pointer type.
		for (ULONG_PTR address = 0x10000000; address < 0x70000000; address += 0x01000000)
		{
			if (PVOID allocation = VirtualAllocEx(process, reinterpret_cast<PVOID>(address), size,
				MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) return allocation;
		}
		return nullptr;
#else
		return VirtualAllocEx(process, nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
#endif
	}

	HANDLE CreateInitializationThread(HANDLE process, LPTHREAD_START_ROUTINE initialize, PVOID context, WORD machine)
	{
#if defined(_M_IX86)
		// Call the native system library in-process when WOW64 cannot start a 64-bit child thread directly.
		if (machine != IMAGE_FILE_MACHINE_I386)
		{
			std::error_code error;
			const auto nativeModule = winpriv::wow64::module_handle("ntdll.dll", error);
			const auto createThread = error ? 0 : winpriv::wow64::import(nativeModule, "NtCreateThreadEx", error);
			std::uint64_t thread = 0;
			const LONG status = error ? 0 : static_cast<LONG>(winpriv::wow64::call_function(error, createThread,
				winpriv::wow64::ptr_to_uint64(&thread), THREAD_ALL_ACCESS, 0, winpriv::wow64::handle_to_uint64(process),
				winpriv::wow64::ptr_to_uint64(initialize), winpriv::wow64::ptr_to_uint64(context), 0, 0, 0, 0, 0));
			if (error || status < 0)
			{
				const LONG result = error ? error.value() : status;
				const auto statusToError = LoadNtFunction<ULONG(NTAPI*)(LONG)>("RtlNtStatusToDosError");
				SetLastError(result < 0 && statusToError ? statusToError(result) : static_cast<DWORD>(result));
				return nullptr;
			}
			return reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(thread));
		}
#else
		(void)machine;
#endif
		return CreateRemoteThread(process, nullptr, 0, initialize, context, 0, nullptr);
	}

	DWORD InitializeDiskLibrary(const Initialization* context)
	{
		const auto path = reinterpret_cast<LPCWSTR>(static_cast<ULONG_PTR>(context->libraryPath));
		const HMODULE module = LoadLibraryExW(path, nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
		if (module == nullptr) return GetLastError();
		const auto initialize = reinterpret_cast<decltype(&WinPrivInitialize)>(GetProcAddress(module, "WinPrivInitialize"));
		const DWORD error = initialize == nullptr ? GetLastError() : initialize(context);
		if (error != NO_ERROR) FreeLibrary(module);
		return error;
	}

	bool InitializeLibrary(HANDLE process, const LibraryBundle* bundle,
		LPCVOID settings, DWORD settingsSize, bool local)
	{
		DynamicCodeScope codeScope;
		if (codeScope.Result() != NO_ERROR)
		{
			SetLastError(codeScope.Result());
			return false;
		}
		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy{};
		if (!GetProcessMitigationPolicy(process, ProcessDynamicCodePolicy,
			&dynamicCodePolicy, sizeof(dynamicCodePolicy))) return false;
		if (dynamicCodePolicy.ProhibitDynamicCode && !dynamicCodePolicy.AllowThreadOptOut)
		{
			SetLastError(ERROR_DYNAMIC_CODE_BLOCKED);
			return false;
		}
		// Choose the target machine independently of the launcher's architecture.
		USHORT machine = 0;
		USHORT nativeMachine = 0;
		if (!IsWow64Process2(process, &machine, &nativeMachine)) return false;
		if (machine == IMAGE_FILE_MACHINE_UNKNOWN && nativeMachine == IMAGE_FILE_MACHINE_ARM64)
		{
			// Distinguish native ARM64 from x64 emulation, which is not reported as WOW64.
			struct MachineInformation { USHORT machine; USHORT reserved; DWORD attributes; } information{};
			if (GetProcessInformation(process, static_cast<PROCESS_INFORMATION_CLASS>(9),
				&information, sizeof(information))) machine = information.machine;
			else if (GetLastError() != ERROR_INVALID_PARAMETER && GetLastError() != ERROR_NOT_SUPPORTED) return false;
		}
		if (machine == IMAGE_FILE_MACHINE_UNKNOWN) machine = nativeMachine;
		constexpr WORD arm64EcMachine = 0xa641;
		if (machine == arm64EcMachine) machine = IMAGE_FILE_MACHINE_AMD64;
		const auto found = std::ranges::find(machines, machine);
		if (found == machines.end() || bundle == nullptr || bundle->size < sizeof(*bundle))
		{
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return false;
		}
		const size_t index = found - machines.begin();
		if (bundle->sizes[index] <= digestSize || !ImageRange(bundle->offsets[index], bundle->sizes[index], bundle->size) ||
			(settingsSize != 0 && settings == nullptr))
		{
			SetLastError(ERROR_INVALID_DATA);
			return false;
		}
		const LibraryImage resource{ reinterpret_cast<const BYTE*>(bundle) + bundle->offsets[index], bundle->sizes[index] };

		// Keep the verified file open until the native loader has finished opening it.
		std::wstring path(bundle->directory);
		if (!path.ends_with(L'\\')) path += L'\\';
		path += libraryNames[index];
		SmartPointer<HANDLE> file(CloseHandle,
			CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
		if (file == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND)
			return false;
		if (file != INVALID_HANDLE_VALUE)
		{
			const DWORD capacity = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED);
			if (capacity == 0) return false;
			path.resize(capacity);
			const DWORD length = GetFinalPathNameByHandleW(file, path.data(), capacity, FILE_NAME_NORMALIZED);
			if (length == 0 || length >= capacity) return false;
			path.resize(length);
		}
		// A nested launcher needs its own hook state when this DLL is already loaded by its parent.
		const bool fromDisk = file != INVALID_HANDLE_VALUE && (!local || GetModuleHandleW(path.c_str()) == nullptr);
		std::vector<BYTE> bytes;
		if (fromDisk)
		{
			// Match the DLL's Authenticode digest to the build before letting the native loader open it.
			LARGE_INTEGER size{};
			if (!GetFileSizeEx(file, &size)) return false;
			if (size.QuadPart <= 0 || size.QuadPart > maxLibrarySize)
			{
				SetLastError(ERROR_BAD_EXE_FORMAT);
				return false;
			}
			SmartPointer<HCATADMIN> catalog([](HCATADMIN handle) { CryptCATAdminReleaseContext(handle, 0); }, nullptr);
			if (!CryptCATAdminAcquireContext2(&catalog, nullptr, L"SHA256", nullptr, 0)) return false;
			BYTE digest[digestSize];
			DWORD length = digestSize;
			if (!CryptCATAdminCalcHashFromFileHandle2(catalog, file, &length, digest, 0) || length != digestSize ||
				memcmp(digest, resource.data, digestSize) != 0)
			{
				SetLastError(ERROR_INVALID_IMAGE_HASH);
				return false;
			}
			if (!local)
			{
				bytes.resize(static_cast<size_t>(size.QuadPart));
				DWORD read = 0;
				if (!SetFilePointerEx(file, {}, nullptr, FILE_BEGIN) ||
					!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr)) return false;
				if (read != bytes.size())
				{
					SetLastError(ERROR_HANDLE_EOF);
					return false;
				}
			}
		}
		else if (!DecompressLibrary(resource, bytes)) return false;

		// Retain initialized hook state, but release the temporary bootstrap used for file-backed child loads.
		bool started = false;
		bool releaseBootstrap = false;
		DWORD error = NO_ERROR;
		const DWORD pathSize = fromDisk ? static_cast<DWORD>((path.size() + 1) * sizeof(WCHAR)) : 0;
		const ULONGLONG dataSize = sizeof(Initialization) + ULONGLONG(bundle->size) + settingsSize + pathSize;
		if (dataSize > MAXDWORD)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
		const PVOID remoteData = AllocateImageMemory(process, static_cast<SIZE_T>(dataSize));
		if (remoteData == nullptr) return false;
		const auto releaseData = [&](PVOID data)
		{
			if (!started) VirtualFreeEx(process, data, 0, MEM_RELEASE);
			SetLastError(error);
		};
		std::unique_ptr<void, decltype(releaseData)> dataCleanup(remoteData, releaseData);
		const auto releaseImage = [&](PVOID image)
		{
			if (!started || releaseBootstrap) VirtualFreeEx(process, image, 0, MEM_RELEASE);
		};
		std::unique_ptr<void, decltype(releaseImage)> remoteImage(nullptr, releaseImage);
		LPTHREAD_START_ROUTINE initialize = nullptr;
#if defined(_WIN64)
		IMAGE_DATA_DIRECTORY localUnwind{};
#endif
		if (!local || !fromDisk)
		{
			MappedImage image;
			if (!PrepareImage({ bytes.data(), static_cast<DWORD>(bytes.size()) }, machine, image))
			{
				error = ERROR_BAD_EXE_FORMAT;
				return false;
			}
			remoteImage.reset(AllocateImageMemory(process, image.bytes.size()));
			if (!remoteImage)
			{
				error = GetLastError();
				return false;
			}
			if (!RelocateImage(image, reinterpret_cast<ULONG_PTR>(remoteImage.get())))
			{
				error = ERROR_BAD_EXE_FORMAT;
				return false;
			}
			if (!WriteProcessMemory(process, remoteImage.get(), image.bytes.data(), image.bytes.size(), nullptr))
			{
				error = GetLastError();
				return false;
			}

			// Only code sections are executable while the bootstrap resolves imports.
			for (const auto& section : image.sections)
			{
				if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) continue;
				DWORD previous = 0;
				if (!VirtualProtectEx(process, static_cast<PBYTE>(remoteImage.get()) + section.VirtualAddress,
					(std::max)(section.Misc.VirtualSize, section.SizeOfRawData), PAGE_EXECUTE_READ, &previous))
				{
					error = GetLastError();
					return false;
				}
			}
			if (!FlushInstructionCache(process, remoteImage.get(), image.bytes.size()))
			{
				error = GetLastError();
				return false;
			}
			initialize = reinterpret_cast<LPTHREAD_START_ROUTINE>(
				static_cast<PBYTE>(remoteImage.get()) + image.initialize);
#if defined(_WIN64)
			if (local) localUnwind = image.unwind;
#endif
		}

		// Pass settings and the selected DLL path alongside the retained fallback resources.
		Initialization context{
			reinterpret_cast<ULONG_PTR>(remoteImage.get()),
			reinterpret_cast<ULONG_PTR>(remoteData) + sizeof(Initialization),
			reinterpret_cast<ULONG_PTR>(remoteData) + sizeof(Initialization) + bundle->size,
			0, settingsSize, ERROR_DLL_INIT_FAILED };
		if (fromDisk) context.libraryPath = context.settings + settingsSize;
		if (!WriteProcessMemory(process, remoteData, &context, sizeof(context), nullptr) ||
			!WriteProcessMemory(process, reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(context.bundle)),
				bundle, bundle->size, nullptr) ||
			(settingsSize != 0 && !WriteProcessMemory(process,
				reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(context.settings)), settings, settingsSize, nullptr)) ||
			(fromDisk && !WriteProcessMemory(process,
				reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(context.libraryPath)), path.c_str(), pathSize, nullptr)))
		{
			error = GetLastError();
			return false;
		}
		if (local)
		{
			const auto localContext = static_cast<Initialization*>(remoteData);
#if defined(_WIN64)
			// Publish unwind metadata from the launcher before entering any private x64 or ARM64 code.
			if (!fromDisk)
			{
				const auto base = static_cast<PBYTE>(remoteImage.get());
				const auto table = reinterpret_cast<PRUNTIME_FUNCTION>(base + localUnwind.VirtualAddress);
				if (localUnwind.Size == 0 || localUnwind.Size % sizeof(RUNTIME_FUNCTION) != 0 ||
					!RtlAddFunctionTable(table, localUnwind.Size / sizeof(RUNTIME_FUNCTION),
						reinterpret_cast<DWORD64>(base)))
				{
					error = ERROR_DLL_INIT_FAILED;
					return false;
				}
				localContext->unwindRegistered = TRUE;
			}
#endif
			started = true;
			if (fromDisk) localContext->error = InitializeDiskLibrary(localContext);
			else initialize(remoteData);
		}
		else
		{
			SmartPointer<HANDLE> thread(CloseHandle,
				CreateInitializationThread(process, initialize, remoteData, machine));
			if (!thread)
			{
				error = GetLastError();
				return false;
			}
			started = true;
			const DWORD wait = WaitForSingleObject(thread, 30000);
			if (wait != WAIT_OBJECT_0)
			{
				error = wait == WAIT_TIMEOUT ? ERROR_TIMEOUT : GetLastError();
				// Stop the owned child without unmapping code that its initializer could still use.
				TerminateProcess(process, error);
				WaitForSingleObject(process, 5000);
				return false;
			}
		}
		if (!ReadProcessMemory(process, remoteData, &context, sizeof(context), nullptr))
		{
			error = GetLastError();
			return false;
		}
		releaseBootstrap = fromDisk && !context.unwindRegistered;
		error = context.error;
		if (error != NO_ERROR) return false;

		// Descendants read the retained bundle; no caller should modify its images or initialization record.
		DWORD previous = 0;
		if (!VirtualProtectEx(process, remoteData, static_cast<SIZE_T>(dataSize), PAGE_READONLY, &previous))
		{
			error = GetLastError();
			return false;
		}
		return true;
	}

	bool LoadBundle(const LibraryBundle* bundle) noexcept
	{
		try
		{
			return InitializeLibrary(GetCurrentProcess(), bundle, nullptr, 0, true);
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}

	bool InjectLibrary(HANDLE process, const LibraryBundle* bundle,
		LPCVOID settings, DWORD settingsSize) noexcept
	{
		try
		{
			return InitializeLibrary(process, bundle, settings, settingsSize, false);
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}
}
