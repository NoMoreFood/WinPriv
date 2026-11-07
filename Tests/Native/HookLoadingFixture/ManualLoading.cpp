#include "LoadingProbe.h"
#include <winternl.h>
#include <delayimp.h>
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

struct ManualTlsScope
{
    // shortcut: TLS bindings serialize fixture calls; arbitrary DLL-created threads need a loader notification bridge.
    using Lock = NTSTATUS(NTAPI*)(ULONG, ULONG*, ULONG_PTR*);
    using Unlock = NTSTATUS(NTAPI*)(ULONG, ULONG_PTR);
    Unlock unlock = nullptr;
    ULONG_PTR cookie = 0;
    void*** pointer = nullptr;
    void** original = nullptr;
    std::vector<void*> slots;
    DWORD error = ERROR_SUCCESS;

    ManualTlsScope(const IMAGE_TLS_DIRECTORY* tls, void* data)
    {
        if (tls == nullptr) return;
        const auto ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto lock = reinterpret_cast<Lock>(GetProcAddress(ntdll, "LdrLockLoaderLock"));
        unlock = reinterpret_cast<Unlock>(GetProcAddress(ntdll, "LdrUnlockLoaderLock"));
        ULONG disposition = 0;
        if (lock == nullptr || unlock == nullptr || lock(0, &disposition, &cookie) < 0)
        {
            cookie = 0;
            error = ERROR_LOCK_FAILED;
            return;
        }

        // The delayed dependency has no TLS; keep the native loader serialized while installing a private TLS vector.
        DWORD count = 0;
        const auto list = &NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
        for (auto item = list->Flink; item != list; item = item->Flink)
        {
            const auto entry = CONTAINING_RECORD(item, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            const auto base = static_cast<const BYTE*>(entry->DllBase);
            const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
            if (directory.Size == 0) continue;
            const auto native = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(base + directory.VirtualAddress);
            const DWORD index = *reinterpret_cast<const DWORD*>(native->AddressOfIndex);
            if (index >= 4096)
            {
                error = ERROR_NOT_SUPPORTED;
                return;
            }
            count = (std::max)(count, index + 1);
        }
        auto location = reinterpret_cast<void***>(reinterpret_cast<BYTE*>(NtCurrentTeb()) + 11 * sizeof(void*));
        if (count != 0 && *location == nullptr)
        {
            error = ERROR_INVALID_DATA;
            return;
        }
        slots.resize(size_t(count) + 1);
        if (count != 0) memcpy(slots.data(), *location, size_t(count) * sizeof(void*));
        slots[count] = data;
        *reinterpret_cast<DWORD*>(tls->AddressOfIndex) = count;
        original = *location;
        pointer = location;
        *pointer = slots.data();
    }

    ~ManualTlsScope()
    {
        if (pointer != nullptr) *pointer = original;
        if (cookie != 0) unlock(0, cookie);
    }
};

struct ManualImage
{
    BYTE* base = nullptr;
    bool section = false;
    bool attached = false;
    std::vector<HMODULE> dependencies;
    const IMAGE_TLS_DIRECTORY* tls = nullptr;
    std::vector<PIMAGE_TLS_CALLBACK> callbacks;
    std::unique_ptr<void, decltype(&_aligned_free)> threadData{ nullptr, _aligned_free };
#if defined(_WIN64)
    PRUNTIME_FUNCTION functions = nullptr;
#endif

    DWORD CreateThreadData(std::unique_ptr<void, decltype(&_aligned_free)>& data) const
    {
        if (tls == nullptr) return ERROR_SUCCESS;
        const size_t rawSize = tls->EndAddressOfRawData - tls->StartAddressOfRawData;
        const size_t size = rawSize + tls->SizeOfZeroFill;
        const DWORD alignment = (tls->Characteristics >> 20) & 15;
        data.reset(_aligned_malloc((std::max)(size, size_t(1)),
            (std::max)(sizeof(void*), size_t(1) << (alignment == 0 ? 0 : alignment - 1))));
        if (!data) return ERROR_NOT_ENOUGH_MEMORY;
        memset(data.get(), 0, size);
        if (rawSize != 0) memcpy(data.get(), reinterpret_cast<const void*>(tls->StartAddressOfRawData), rawSize);
        return ERROR_SUCCESS;
    }

    BOOL Notify(DWORD reason) const
    {
        const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        const auto entry = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(
            base + nt->OptionalHeader.AddressOfEntryPoint);
        const auto module = reinterpret_cast<HMODULE>(base);
        for (const auto callback : callbacks) callback(module, reason, nullptr);
        return entry(module, reason, nullptr);
    }

    ~ManualImage()
    {
        if (attached)
        {
            ManualTlsScope scope(tls, threadData.get());
            if (scope.error != ERROR_SUCCESS) RaiseFailFastException(nullptr, nullptr, 0);
            Notify(DLL_PROCESS_DETACH);
        }
#if defined(_WIN64)
        if (functions != nullptr) RtlDeleteFunctionTable(functions);
#endif
        if (base != nullptr)
        {
            if (section) UnmapViewOfFile(base);
            else VirtualFree(base, 0, MEM_RELEASE);
        }
        for (auto dependency = dependencies.rbegin(); dependency != dependencies.rend(); ++dependency)
            FreeLibrary(*dependency);
    }
};

static DWORD MapProbe(LPCWSTR path, const std::vector<BYTE>& bytes, bool section, bool native, ManualImage& image)
{
    // Only map a validated native DLL built by this test suite.
    const auto range = [](size_t offset, size_t count, size_t size)
    {
        return offset <= size && count <= size - offset;
    };
    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) return ERROR_BAD_EXE_FORMAT;
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew < sizeof(*dos) ||
        !range(dos->e_lfanew, sizeof(IMAGE_NT_HEADERS), bytes.size())) return ERROR_BAD_EXE_FORMAT;
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(bytes.data() + dos->e_lfanew);
#if defined(_M_IX86)
    constexpr WORD machine = IMAGE_FILE_MACHINE_I386;
#elif defined(_M_ARM64)
    constexpr WORD machine = IMAGE_FILE_MACHINE_ARM64;
#else
    constexpr WORD machine = IMAGE_FILE_MACHINE_AMD64;
#endif
    const size_t size = nt->OptionalHeader.SizeOfImage;
    const auto sections = IMAGE_FIRST_SECTION(nt);
    const size_t sectionOffset = reinterpret_cast<const BYTE*>(sections) - bytes.data();
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != machine ||
        (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) == 0 ||
        nt->FileHeader.NumberOfSections == 0 || nt->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER) ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC || size == 0 || size > 16 * 1024 * 1024 ||
        nt->OptionalHeader.SizeOfHeaders > size || nt->OptionalHeader.SizeOfHeaders > bytes.size() ||
        nt->OptionalHeader.AddressOfEntryPoint == 0 || nt->OptionalHeader.AddressOfEntryPoint >= size ||
        nt->OptionalHeader.NumberOfRvaAndSizes != 16 ||
        !range(sectionOffset, size_t(nt->FileHeader.NumberOfSections) * sizeof(*sections),
            nt->OptionalHeader.SizeOfHeaders)) return ERROR_BAD_EXE_FORMAT;
    for (const auto& directory : nt->OptionalHeader.DataDirectory)
    {
        if (&directory == &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY]) continue;
        if (!range(directory.VirtualAddress, directory.Size, size)) return ERROR_BAD_EXE_FORMAT;
    }
    DWORD previousEnd = nt->OptionalHeader.SizeOfHeaders;
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index)
    {
        const auto& current = sections[index];
        const DWORD extent = (std::max)(current.SizeOfRawData, current.Misc.VirtualSize);
        if (current.VirtualAddress < previousEnd || (current.VirtualAddress & 0xfff) != 0 ||
            !range(current.VirtualAddress, extent, size) ||
            !range(current.PointerToRawData, current.SizeOfRawData, bytes.size())) return ERROR_BAD_EXE_FORMAT;
        previousEnd = current.VirtualAddress + extent;
    }

    // Both backing types use the raw image's relocations, so copy-on-write image pages start from the same bytes.
    image.section = section;
    if (section)
    {
        const HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return GetLastError();
        const HANDLE mapping = CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
        const DWORD error = GetLastError();
        CloseHandle(file);
        if (mapping == nullptr) return error;
        image.base = static_cast<BYTE*>(MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0));
        const DWORD mapped = GetLastError();
        CloseHandle(mapping);
        if (image.base == nullptr) return mapped;
    }
    else
    {
        image.base = static_cast<BYTE*>(VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
        if (image.base == nullptr) return GetLastError();
        memcpy(image.base, bytes.data(), nt->OptionalHeader.SizeOfHeaders);
    }
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index)
    {
        const auto& current = sections[index];
        DWORD previous = 0;
        const DWORD extent = (std::max)(current.SizeOfRawData, current.Misc.VirtualSize);
        if (extent != 0 && !VirtualProtect(image.base + current.VirtualAddress, extent, PAGE_READWRITE, &previous))
            return GetLastError();
        memcpy(image.base + current.VirtualAddress, bytes.data() + current.PointerToRawData, current.SizeOfRawData);
    }
    const ULONG_PTR delta = reinterpret_cast<ULONG_PTR>(image.base) - nt->OptionalHeader.ImageBase;
    const auto& relocations = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta != 0 && relocations.Size == 0) return ERROR_BAD_EXE_FORMAT;
    size_t offset = relocations.VirtualAddress;
    const size_t end = offset + relocations.Size;
    while (offset < end)
    {
        if (!range(offset, sizeof(IMAGE_BASE_RELOCATION), end)) return ERROR_BAD_EXE_FORMAT;
        const auto block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(image.base + offset);
        if (block->SizeOfBlock < sizeof(*block) || block->SizeOfBlock % sizeof(WORD) != 0 ||
            !range(offset, block->SizeOfBlock, end)) return ERROR_BAD_EXE_FORMAT;
        const auto entries = reinterpret_cast<const WORD*>(block + 1);
        for (size_t index = 0; index < (block->SizeOfBlock - sizeof(*block)) / sizeof(WORD); ++index)
        {
            const WORD type = entries[index] >> 12;
            const size_t target = size_t(block->VirtualAddress) + (entries[index] & 0xfff);
            if (type == IMAGE_REL_BASED_ABSOLUTE) continue;
#if defined(_WIN64)
            if (type != IMAGE_REL_BASED_DIR64 || !range(target, sizeof(ULONGLONG), size)) return ERROR_BAD_EXE_FORMAT;
#else
            if (type != IMAGE_REL_BASED_HIGHLOW || !range(target, sizeof(DWORD), size)) return ERROR_BAD_EXE_FORMAT;
#endif
            *reinterpret_cast<ULONG_PTR*>(image.base + target) += delta;
        }
        offset += block->SizeOfBlock;
    }

    // TLS fields are relocated virtual addresses, including the callback array and static-data template.
    const auto& tls = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls.Size != 0)
    {
        if (tls.Size < sizeof(IMAGE_TLS_DIRECTORY)) return ERROR_BAD_EXE_FORMAT;
        image.tls = reinterpret_cast<const IMAGE_TLS_DIRECTORY*>(image.base + tls.VirtualAddress);
        const ULONG_PTR base = reinterpret_cast<ULONG_PTR>(image.base);
        const auto addressRange = [&](ULONG_PTR address, size_t length)
        {
            return address >= base && range(address - base, length, size);
        };
        const auto& directory = *image.tls;
        if (directory.EndAddressOfRawData < directory.StartAddressOfRawData ||
            !addressRange(directory.StartAddressOfRawData,
                directory.EndAddressOfRawData - directory.StartAddressOfRawData) ||
            !range(directory.EndAddressOfRawData - directory.StartAddressOfRawData, directory.SizeOfZeroFill, size) ||
            !addressRange(directory.AddressOfIndex, sizeof(DWORD))) return ERROR_BAD_EXE_FORMAT;
        if (directory.AddressOfCallBacks != 0)
        {
            for (ULONG_PTR position = directory.AddressOfCallBacks; ; position += sizeof(PIMAGE_TLS_CALLBACK))
            {
                if (!addressRange(position, sizeof(PIMAGE_TLS_CALLBACK))) return ERROR_BAD_EXE_FORMAT;
                const auto callback = *reinterpret_cast<const PIMAGE_TLS_CALLBACK*>(position);
                if (callback == nullptr) break;
                if (!addressRange(reinterpret_cast<ULONG_PTR>(callback), 1)) return ERROR_BAD_EXE_FORMAT;
                image.callbacks.push_back(callback);
            }
        }
        const DWORD error = image.CreateThreadData(image.threadData);
        if (error != ERROR_SUCCESS) return error;
    }

    // Resolve the same import table through either public Win32 APIs or the native loader APIs.
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto load = reinterpret_cast<NTSTATUS(NTAPI*)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE)>(
        GetProcAddress(ntdll, "LdrLoadDll"));
    const auto procedure = reinterpret_cast<NTSTATUS(NTAPI*)(PVOID, PANSI_STRING, ULONG, PVOID*)>(
        GetProcAddress(ntdll, "LdrGetProcedureAddress"));
    const auto statusToError = reinterpret_cast<ULONG(NTAPI*)(NTSTATUS)>(
        GetProcAddress(ntdll, "RtlNtStatusToDosError"));
    if (load == nullptr || procedure == nullptr || statusToError == nullptr) return ERROR_PROC_NOT_FOUND;
    const auto& imports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const auto descriptors = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(image.base + imports.VirtualAddress);
    for (size_t index = 0; index < imports.Size / sizeof(*descriptors) && descriptors[index].Name != 0; ++index)
    {
        const auto& import = descriptors[index];
        if (!range(import.Name, 1, size) || memchr(image.base + import.Name, 0, size - import.Name) == nullptr)
            return ERROR_BAD_EXE_FORMAT;
        const auto name = reinterpret_cast<LPCSTR>(image.base + import.Name);
        HMODULE dependency = nullptr;
        if (native)
        {
            std::wstring wide(name, name + strlen(name));
            if (wide.size() >= 32767) return ERROR_BAD_EXE_FORMAT;
            UNICODE_STRING text{ static_cast<USHORT>(wide.size() * sizeof(WCHAR)),
                static_cast<USHORT>((wide.size() + 1) * sizeof(WCHAR)), wide.data() };
            HANDLE loaded = nullptr;
            const NTSTATUS status = load(nullptr, nullptr, &text, &loaded);
            if (status < 0) return statusToError(status);
            dependency = static_cast<HMODULE>(loaded);
        }
        else dependency = LoadLibraryA(name);
        if (dependency == nullptr) return GetLastError();
        image.dependencies.push_back(dependency);
        const DWORD source = import.OriginalFirstThunk != 0 ? import.OriginalFirstThunk : import.FirstThunk;
        for (size_t thunk = 0; ; ++thunk)
        {
            const size_t position = thunk * sizeof(IMAGE_THUNK_DATA);
            if (!range(size_t(source) + position, sizeof(IMAGE_THUNK_DATA), size) ||
                !range(size_t(import.FirstThunk) + position, sizeof(IMAGE_THUNK_DATA), size))
                return ERROR_BAD_EXE_FORMAT;
            const auto imported = reinterpret_cast<const IMAGE_THUNK_DATA*>(image.base + source + position);
            const auto address = imported->u1.AddressOfData;
            if (address == 0) break;
            const bool ordinal = IMAGE_SNAP_BY_ORDINAL(address) != 0;
            LPCSTR function = MAKEINTRESOURCEA(IMAGE_ORDINAL(address));
            if (!ordinal)
            {
                if (!range(address, sizeof(IMAGE_IMPORT_BY_NAME), size)) return ERROR_BAD_EXE_FORMAT;
                function = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(image.base + address)->Name;
                if (memchr(function, 0, size - address - sizeof(WORD)) == nullptr) return ERROR_BAD_EXE_FORMAT;
            }
            PVOID resolved = nullptr;
            if (native)
            {
                const size_t length = ordinal ? 0 : strlen(function);
                if (length >= 65535) return ERROR_BAD_EXE_FORMAT;
                ANSI_STRING text{ static_cast<USHORT>(length), static_cast<USHORT>(length + 1), const_cast<PSTR>(function) };
                const NTSTATUS status = procedure(dependency, ordinal ? nullptr : &text,
                    ordinal ? IMAGE_ORDINAL(address) : 0, &resolved);
                if (status < 0) return statusToError(status);
            }
            else resolved = reinterpret_cast<PVOID>(GetProcAddress(dependency, function));
            if (resolved == nullptr) return GetLastError();
            reinterpret_cast<IMAGE_THUNK_DATA*>(image.base + import.FirstThunk + position)->u1.Function =
                reinterpret_cast<ULONG_PTR>(resolved);
        }
    }

    // Publish executable pages and unwind metadata before invoking the DLL's CRT entry point.
    for (WORD index = 0; index < nt->FileHeader.NumberOfSections; ++index)
    {
        const auto& current = sections[index];
        const bool execute = (current.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        const bool write = (current.Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        const DWORD protection = execute ? (write ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ) :
            (write ? PAGE_READWRITE : PAGE_READONLY);
        DWORD previous = 0;
        const DWORD extent = (std::max)(current.SizeOfRawData, current.Misc.VirtualSize);
        if (extent != 0 && !VirtualProtect(image.base + current.VirtualAddress, extent, protection, &previous))
            return GetLastError();
    }
    DWORD previous = 0;
    if (!VirtualProtect(image.base, nt->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &previous) ||
        !FlushInstructionCache(GetCurrentProcess(), image.base, size)) return GetLastError();
#if defined(_WIN64)
    const auto& exceptions = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exceptions.Size != 0)
    {
        const auto functions = reinterpret_cast<PRUNTIME_FUNCTION>(image.base + exceptions.VirtualAddress);
        if (!RtlAddFunctionTable(functions, exceptions.Size / sizeof(RUNTIME_FUNCTION),
            reinterpret_cast<DWORD64>(image.base))) return ERROR_DLL_INIT_FAILED;
        image.functions = functions;
    }
#endif
    ManualTlsScope scope(image.tls, image.threadData.get());
    if (scope.error != ERROR_SUCCESS) return scope.error;
    if (!image.Notify(DLL_PROCESS_ATTACH)) return ERROR_DLL_INIT_FAILED;
    image.attached = true;
    return ERROR_SUCCESS;
}

static FARPROC WINAPI MappedExport(HMODULE module, LPCSTR name)
{
    // This resolver reads the fixture's own exports; forwarded system exports retain the OS implementation.
    const auto base = reinterpret_cast<const BYTE*>(module);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto& exports = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    const auto directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + exports.VirtualAddress);
    const auto names = reinterpret_cast<const DWORD*>(base + directory->AddressOfNames);
    const auto ordinals = reinterpret_cast<const WORD*>(base + directory->AddressOfNameOrdinals);
    const auto functions = reinterpret_cast<const DWORD*>(base + directory->AddressOfFunctions);
    DWORD ordinal = MAXDWORD;
    if (reinterpret_cast<ULONG_PTR>(name) <= MAXWORD)
        ordinal = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(name)) - directory->Base;
    else
    {
        for (DWORD index = 0; index < directory->NumberOfNames; ++index)
            if (strcmp(name, reinterpret_cast<LPCSTR>(base + names[index])) == 0) ordinal = ordinals[index];
    }
    if (ordinal >= directory->NumberOfFunctions || functions[ordinal] == 0)
    {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return nullptr;
    }
    const DWORD rva = functions[ordinal];
    if (rva >= exports.VirtualAddress && rva - exports.VirtualAddress < exports.Size)
    {
        const std::string forward(reinterpret_cast<LPCSTR>(base + rva));
        const auto separator = forward.find_last_of('.');
        if (separator == std::string::npos) return nullptr;
        const auto library = forward.substr(0, separator) + ".dll";
        return GetProcAddress(GetModuleHandleA(library.c_str()), forward.c_str() + separator + 1);
    }
    return reinterpret_cast<FARPROC>(const_cast<BYTE*>(base + rva));
}

static DWORD CheckLifecycle(ManualImage* image, HMODULE module, LPCWSTR key, LPCWSTR valueName, LPCWSTR file,
    DWORD expectedValue, DWORD expectedSize, LoadingLifecycleState& detached)
{
    const auto find = [&](LPCSTR name)
    {
        return image == nullptr ? GetProcAddress(module, name) : MappedExport(module, name);
    };
    const auto query = reinterpret_cast<LoadingLifecycleQuery>(find("WinPrivLifecycleQuery"));
    const auto state = reinterpret_cast<const LoadingLifecycleState*>(find("WinPrivLifecycleState"));
    if (query == nullptr || state == nullptr || state->callbacks[DLL_PROCESS_ATTACH] != 1 ||
        state->entries[DLL_PROCESS_ATTACH] != 1 || state->failures != 0 || state->delayLoads != 0 ||
        state->registryValue != expectedValue || state->fileSize != expectedSize)
    {
        if (state != nullptr)
            std::fprintf(stderr, "Lifecycle attach: callbacks=%lu entries=%lu failures=%lu value=%lu size=%lu\n",
                state->callbacks[DLL_PROCESS_ATTACH], state->entries[DLL_PROCESS_ATTACH], state->failures,
                state->registryValue, state->fileSize);
        return ERROR_INVALID_DATA;
    }
    const auto base = reinterpret_cast<const BYTE*>(module);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    const auto& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
    if (directory.Size != 2 * sizeof(ImgDelayDescr)) return ERROR_BAD_EXE_FORMAT;
    const auto delay = reinterpret_cast<const ImgDelayDescr*>(base + directory.VirtualAddress);
    const auto range = [&](DWORD rva, size_t size)
    {
        return rva < nt->OptionalHeader.SizeOfImage && size <= nt->OptionalHeader.SizeOfImage - rva;
    };
    if (delay->grAttrs != dlattrRva || !range(delay->rvaHmod, sizeof(HMODULE)) ||
        !range(delay->rvaIAT, 2 * sizeof(ULONG_PTR)) || !range(delay->rvaUnloadIAT, 2 * sizeof(ULONG_PTR)) ||
        !range(delay->rvaDLLName, sizeof("WinPrivLoadingProbe.dll")) ||
        strcmp(reinterpret_cast<LPCSTR>(base + delay->rvaDLLName), "WinPrivLoadingProbe.dll") != 0)
        return ERROR_BAD_EXE_FORMAT;
    const auto handle = reinterpret_cast<const HMODULE*>(base + delay->rvaHmod);
    const auto iat = reinterpret_cast<const ULONG_PTR*>(base + delay->rvaIAT);
    const auto original = reinterpret_cast<const ULONG_PTR*>(base + delay->rvaUnloadIAT);
    if (*handle != nullptr || iat[0] != original[0] || iat[1] != 0 ||
        GetModuleHandleW(L"WinPrivLoadingProbe.dll") != nullptr) return ERROR_INVALID_DATA;
    const auto call = [&](DWORD expectedCall, BOOL unload)
    {
        LoadingProbeResult result{};
        const DWORD error = query(key, valueName, file, expectedCall, unload, &detached, &result);
        if (error != ERROR_SUCCESS) return error;
        if (!unload && (result.registryValue != expectedValue || result.fileSize != expectedSize ||
            result.attachCount != 1 || *handle == nullptr || iat[0] == original[0])) return DWORD(ERROR_INVALID_DATA);
        return DWORD(ERROR_SUCCESS);
    };

    // Keep the main thread's TLS data alive while two other threads get independent initialized copies.
    {
        ManualTlsScope scope(image == nullptr ? nullptr : image->tls,
            image == nullptr ? nullptr : image->threadData.get());
        if (scope.error != ERROR_SUCCESS) return scope.error;
        DWORD error = call(1, FALSE);
        if (error == ERROR_SUCCESS) error = call(2, FALSE);
        if (error != ERROR_SUCCESS) return error;
    }
    for (unsigned index = 0; index < 2; ++index)
    {
        DWORD error = ERROR_SUCCESS;
        std::thread worker([&]
        {
            std::unique_ptr<void, decltype(&_aligned_free)> data(nullptr, _aligned_free);
            if (image != nullptr) error = image->CreateThreadData(data);
            if (error != ERROR_SUCCESS) return;
            ManualTlsScope scope(image == nullptr ? nullptr : image->tls, data.get());
            error = scope.error;
            if (error != ERROR_SUCCESS) return;
            if (image != nullptr) image->Notify(DLL_THREAD_ATTACH);
            error = call(1, FALSE);
            if (error == ERROR_SUCCESS) error = call(2, FALSE);
            if (image != nullptr) image->Notify(DLL_THREAD_DETACH);
        });
        worker.join();
        if (error != ERROR_SUCCESS) return error;
    }

    // Delay unload must restore the thunk and free its DLL before a forced-address-change reload.
    ManualTlsScope scope(image == nullptr ? nullptr : image->tls, image == nullptr ? nullptr : image->threadData.get());
    if (scope.error != ERROR_SUCCESS) return scope.error;
    DWORD error = call(3, FALSE);
    if (error != ERROR_SUCCESS) return error;
    if (state->delayLoads != 1) return ERROR_INVALID_DATA;
    const HMODULE dependency = *handle;
    const auto dependentBase = reinterpret_cast<const BYTE*>(dependency);
    const auto dependentDos = reinterpret_cast<const IMAGE_DOS_HEADER*>(dependentBase);
    const auto dependentNt = reinterpret_cast<const IMAGE_NT_HEADERS*>(dependentBase + dependentDos->e_lfanew);
    const DWORD dependencySize = dependentNt->OptionalHeader.SizeOfImage;
    if ((error = call(0, TRUE)) != ERROR_SUCCESS) return error;
    MEMORY_BASIC_INFORMATION memory{};
    if (*handle != nullptr || iat[0] != original[0] || GetModuleHandleW(L"WinPrivLoadingProbe.dll") != nullptr ||
        VirtualQuery(dependency, &memory, sizeof(memory)) != sizeof(memory) || memory.State != MEM_FREE)
        return ERROR_BUSY;
    const auto release = [](void* address) { VirtualFree(address, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(release)> reservation(
        VirtualAlloc(dependency, dependencySize, MEM_RESERVE, PAGE_NOACCESS), release);
    if (reservation.get() != dependency) return ERROR_NOT_ENOUGH_MEMORY;
    if ((error = call(4, FALSE)) != ERROR_SUCCESS) return error;
    if (*handle == dependency || state->delayLoads != 2) return ERROR_INVALID_DATA;
    const HMODULE reloaded = *handle;
    if ((error = call(0, TRUE)) != ERROR_SUCCESS) return error;
    if (*handle != nullptr || iat[0] != original[0] || GetModuleHandleW(L"WinPrivLoadingProbe.dll") != nullptr ||
        VirtualQuery(reloaded, &memory, sizeof(memory)) != sizeof(memory) || memory.State != MEM_FREE)
        return ERROR_BUSY;
    return ERROR_SUCCESS;
}

DWORD TestManualLoading(LPCWSTR path, LPCWSTR key, LPCWSTR valueName, LPCWSTR file,
    DWORD expectedValue, DWORD expectedSize, DWORD& completed, DWORD& lifecycleCases)
{
    const std::wstring library(path);
    const auto lifecyclePath = library.substr(0, library.find_last_of(L'\\') + 1) + L"WinPrivLifecycleProbe.dll";
    const LPCWSTR variables[]{ L"WINPRIV_LOADING_TLS_KEY", L"WINPRIV_LOADING_TLS_VALUE", L"WINPRIV_LOADING_TLS_FILE" };
    const LPCWSTR values[]{ key, valueName, file };
    std::wstring saved[3];
    for (unsigned index = 0; index < 3; ++index)
    {
        const DWORD length = GetEnvironmentVariableW(variables[index], nullptr, 0);
        if (length != 0)
        {
            saved[index].resize(length);
            GetEnvironmentVariableW(variables[index], saved[index].data(), length);
        }
    }
    const auto restore = [&](void*)
    {
        for (unsigned index = 0; index < 3; ++index)
            SetEnvironmentVariableW(variables[index], saved[index].empty() ? nullptr : saved[index].c_str());
    };
    std::unique_ptr<void, decltype(restore)> environment(reinterpret_cast<void*>(1), restore);
    for (unsigned index = 0; index < 3; ++index)
        if (!SetEnvironmentVariableW(variables[index], values[index])) return GetLastError();

    for (const bool lifecycle : { false, true })
    {
        const LPCWSTR fixture = lifecycle ? lifecyclePath.c_str() : path;
        FILE* opened = nullptr;
        if (_wfopen_s(&opened, fixture, L"rb") != 0) return ERROR_OPEN_FAILED;
        std::unique_ptr<FILE, decltype(&fclose)> stream(opened, fclose);
        if (fseek(opened, 0, SEEK_END) != 0) return ERROR_READ_FAULT;
        const long length = ftell(opened);
        if (length <= 0 || length > 16 * 1024 * 1024 || fseek(opened, 0, SEEK_SET) != 0) return ERROR_BAD_EXE_FORMAT;
        std::vector<BYTE> bytes(static_cast<size_t>(length));
        if (fread(bytes.data(), 1, bytes.size(), opened) != bytes.size()) return ERROR_READ_FAULT;
        stream.reset();
        for (const unsigned backing : { 0u, 1u, 2u })
        {
            if (!lifecycle && backing == 0) continue;
            for (const bool native : { false, true })
            {
                if (backing == 0 && native) continue;
                volatile LONG detached = 0;
                const auto release = [](void* address) { VirtualFree(address, 0, MEM_RELEASE); };
                std::unique_ptr<void, decltype(release)> reservation(nullptr, release);
                for (LONG iteration = 0; iteration < 2; ++iteration)
                {
                    BYTE* address = nullptr;
                    DWORD imageSize = 0;
                    LoadingLifecycleState finalState{};
                    {
                        ManualImage image;
                        std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> loaded(nullptr, FreeLibrary);
                        if (backing == 0)
                        {
                            loaded.reset(LoadLibraryW(fixture));
                            if (!loaded) return GetLastError();
                            address = reinterpret_cast<BYTE*>(loaded.get());
                        }
                        else
                        {
                            const DWORD error = MapProbe(fixture, bytes, backing == 2, native, image);
                            if (error != ERROR_SUCCESS) return error;
                            if (!lifecycle && image.tls != nullptr) return ERROR_NOT_SUPPORTED;
                            if (GetModuleHandleW(fixture) != nullptr) return ERROR_INVALID_DATA;
                            address = image.base;
                        }
                        if (address == reservation.get()) return ERROR_INVALID_ADDRESS;
                        MEMORY_BASIC_INFORMATION memory{};
                        if (VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory) ||
                            memory.Type != static_cast<DWORD>(backing == 1 ? MEM_PRIVATE : MEM_IMAGE))
                            return ERROR_INVALID_DATA;
                        if (lifecycle)
                        {
                            const DWORD error = CheckLifecycle(backing == 0 ? nullptr : &image,
                                reinterpret_cast<HMODULE>(address), key, valueName, file,
                                expectedValue, expectedSize, finalState);
                            if (error != ERROR_SUCCESS) return error;
                        }
                        else
                        {
                            LoadingProbeResult result{};
                            const DWORD error = CheckLoadingProbe(reinterpret_cast<HMODULE>(address),
                                key, valueName, file, &detached, result, MappedExport);
                            if (error != ERROR_SUCCESS) return error;
                            if (result.registryValue != expectedValue || result.fileSize != expectedSize)
                                return ERROR_INVALID_DATA;
                        }
                        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(address);
                        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(address + dos->e_lfanew);
                        imageSize = nt->OptionalHeader.SizeOfImage;
                    }
                    MEMORY_BASIC_INFORMATION memory{};
                    if (GetModuleHandleW(fixture) != nullptr ||
                        VirtualQuery(address, &memory, sizeof(memory)) != sizeof(memory) || memory.State != MEM_FREE)
                        return ERROR_BUSY;
                    if (lifecycle)
                    {
                        if (finalState.failures != 0 || finalState.queries != 8 || finalState.delayLoads != 2 ||
                            finalState.delayUnloads != 2)
                        {
                            std::fprintf(stderr, "Lifecycle detach: backing=%u native=%u failures=%lu "
                                "queries=%lu loads=%lu unloads=%lu\n",
                                backing, native, finalState.failures, finalState.queries,
                                finalState.delayLoads, finalState.delayUnloads);
                            for (DWORD reason = 0; reason < 4; ++reason)
                                std::fprintf(stderr, "Notification %lu: callbacks=%lu entries=%lu\n", reason,
                                    finalState.callbacks[reason], finalState.entries[reason]);
                            return ERROR_INVALID_DATA;
                        }
                        for (DWORD reason = 0; reason < 4; ++reason)
                        {
                            const DWORD expected = reason == DLL_PROCESS_ATTACH || reason == DLL_PROCESS_DETACH ? 1 : 2;
                            if (finalState.callbacks[reason] != expected || finalState.entries[reason] != expected)
                                return ERROR_INVALID_DATA;
                        }
                        ++lifecycleCases;
                    }
                    else
                    {
                        if (detached != iteration + 1) return ERROR_DLL_INIT_FAILED;
                        ++completed;
                    }
                    reservation.reset();
                    reservation.reset(VirtualAlloc(address, imageSize, MEM_RESERVE, PAGE_NOACCESS));
                    if (reservation.get() != address) return ERROR_NOT_ENOUGH_MEMORY;
                }
            }
        }
    }
    return ERROR_SUCCESS;
}
