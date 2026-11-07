#include "LoadingProbe.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <memory>
#include <string>
#include <vector>
#if defined(WINPRIV_LOADING_MODE_DELAY)
#include <delayimp.h>
#endif

static std::string LoadingAnsi(LPCWSTR text)
{
    const int length = WideCharToMultiByte(CP_ACP, 0, text, -1, nullptr, 0, nullptr, nullptr);
    std::string converted(length, '\0');
    WideCharToMultiByte(CP_ACP, 0, text, -1, converted.data(), length, nullptr, nullptr);
    return converted;
}

static HMODULE LoadProbe(LPCWSTR path, bool ansi, DWORD flags, bool plain = false)
{
    if (!ansi) return plain ? LoadLibraryW(path) : LoadLibraryExW(path, nullptr, flags);
    const auto converted = LoadingAnsi(path);
    return plain ? LoadLibraryA(converted.c_str()) : LoadLibraryExA(converted.c_str(), nullptr, flags);
}

DWORD CheckLoadingProbe(HMODULE module, LPCWSTR key, LPCWSTR valueName, LPCWSTR file,
    volatile LONG* detached, LoadingProbeResult& result, LoadingExportResolver resolve)
{
    // Keep GetProcAddress as an import call because Windows suppresses its export as a CFG callback target.
    const auto find = [&](LPCSTR name)
    {
        return resolve == nullptr ? GetProcAddress(module, name) : resolve(module, name);
    };
    const auto attached = reinterpret_cast<const DWORD*>(find("WinPrivLoadingAttachCount"));
    const auto processId = reinterpret_cast<decltype(&GetCurrentProcessId)>(
        find(MAKEINTRESOURCEA(3)));
    if (attached == nullptr || *attached != 1 || processId == nullptr || processId() != GetCurrentProcessId())
        return ERROR_INVALID_DATA;
    DWORD calls = 0;
    LoadingProbeResult first{};
    for (const bool ordinal : { false, true })
    {
        const auto query = reinterpret_cast<LoadingProbeQuery>(find(
            ordinal ? MAKEINTRESOURCEA(1) : "WinPrivLoadingQuery"));
        if (query == nullptr) return GetLastError();
        for (const BOOL ansi : { FALSE, TRUE })
        {
            const DWORD error = query(key, valueName, file, ansi, detached, &result);
            if (error != ERROR_SUCCESS) return error;
            if (result.attachCount != 1 || result.calls != ++calls) return ERROR_INVALID_DATA;
            if (calls == 1) first = result;
            if (result.registryValue != first.registryValue || result.fileSize != first.fileSize)
                return ERROR_INVALID_DATA;
        }
    }
    return ERROR_SUCCESS;
}

static DWORD CheckUnmapped(HMODULE module, LPCWSTR path)
{
    MEMORY_BASIC_INFORMATION memory{};
    if (GetModuleHandleW(path) != nullptr) return ERROR_BUSY;
    if (VirtualQuery(module, &memory, sizeof(memory)) != sizeof(memory)) return GetLastError();
    return memory.State == MEM_FREE ? ERROR_SUCCESS : ERROR_BUSY;
}

static DWORD ReloadProbe(LPCWSTR path, bool ansi, DWORD flags, LPCWSTR key, LPCWSTR valueName,
    LPCWSTR file, LoadingProbeResult& result, bool plain = false)
{
    // The fixture has no permanent import of this DLL; both loader and address-space state must prove removal.
    if (GetModuleHandleW(path) != nullptr) return ERROR_ALREADY_EXISTS;
    volatile LONG detached = 0;
    std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(LoadProbe(path, ansi, flags, plain), FreeLibrary);
    if (!module) return GetLastError();
    DWORD error = CheckLoadingProbe(module.get(), key, valueName, file, &detached, result);
    if (error != ERROR_SUCCESS) return error;
    const LoadingProbeResult first = result;
    const HMODULE original = module.get();
    const auto bytes = reinterpret_cast<const BYTE*>(original);
    const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
    const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(bytes + dos->e_lfanew);
    const DWORD imageSize = nt->OptionalHeader.SizeOfImage;
    module.reset();
    if (detached != 1) return ERROR_DLL_INIT_FAILED;
    if ((error = CheckUnmapped(original, path)) != ERROR_SUCCESS) return error;

    // Occupy the old image address so stale imports or cached pointers cannot pass a same-address reload.
    const auto release = [](void* address) { VirtualFree(address, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(release)> reservation(
        VirtualAlloc(original, imageSize, MEM_RESERVE, PAGE_NOACCESS), release);
    if (reservation.get() != original) return ERROR_NOT_ENOUGH_MEMORY;
    module.reset(LoadProbe(path, ansi, flags, plain));
    if (!module) return GetLastError();
    if (module.get() == original) return ERROR_INVALID_ADDRESS;
    error = CheckLoadingProbe(module.get(), key, valueName, file, &detached, result);
    if (error != ERROR_SUCCESS) return error;
    if (result.registryValue != first.registryValue || result.fileSize != first.fileSize) return ERROR_INVALID_DATA;
    const HMODULE relocated = module.get();
    module.reset();
    if (detached != 2) return ERROR_DLL_INIT_FAILED;
    return CheckUnmapped(relocated, path);
}

LSTATUS QueryReloadedLibrary(LPCWSTR key, LPCWSTR valueName, DWORD& value)
{
    std::array<WCHAR, 32768> path{};
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (length == 0 || length >= path.size()) return ERROR_INSUFFICIENT_BUFFER;
    std::wstring library(path.data());
    library.resize(library.find_last_of(L'\\') + 1);
    library += L"WinPrivLoadingProbe.dll";
    LoadingProbeResult result{};
    const DWORD error = ReloadProbe(library.c_str(), false, 0, key, valueName, nullptr, result);
    value = result.registryValue;
    return error;
}

static DWORD CheckResource(HMODULE module)
{
    const HRSRC resource = FindResourceW(module, MAKEINTRESOURCEW(1), RT_RCDATA);
    if (resource == nullptr) return GetLastError();
    const HGLOBAL loaded = LoadResource(module, resource);
    if (loaded == nullptr) return GetLastError();
    constexpr WORD expected[]{ 0x1234, 0x5678, 0x9abc, 0xdef0 };
    const void* data = LockResource(loaded);
    return SizeofResource(module, resource) == sizeof(expected) && data != nullptr &&
        memcmp(data, expected, sizeof(expected)) == 0 ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

static DWORD CheckSignedLoading(LPCWSTR reportPath, DWORD& accepted, DWORD& tampered)
{
    // A fresh copy avoids a cached module handle bypassing the loader's signature check.
    std::array<WCHAR, MAX_PATH> system{};
    const UINT length = GetSystemDirectoryW(system.data(), static_cast<UINT>(system.size()));
    if (length == 0 || length >= system.size()) return ERROR_BAD_PATHNAME;
    const auto source = std::wstring(system.data()) + L"\\bcryptprimitives.dll";
    std::wstring lastCopy;
    for (const bool ansi : { false, true })
    {
        for (const DWORD search : { DWORD(0), DWORD(LOAD_LIBRARY_SEARCH_SYSTEM32),
            DWORD(LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32),
            DWORD(LOAD_WITH_ALTERED_SEARCH_PATH) })
        {
            lastCopy = std::wstring(reportPath) + L".signed-" + std::to_wstring(accepted) + L".dll";
            if (!CopyFileW(source.c_str(), lastCopy.c_str(), TRUE)) return GetLastError();
            if (GetModuleHandleW(lastCopy.c_str()) != nullptr) return ERROR_ALREADY_EXISTS;
            std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(
                LoadProbe(lastCopy.c_str(), ansi, LOAD_LIBRARY_REQUIRE_SIGNED_TARGET | search), FreeLibrary);
            if (!module) return GetLastError();
            const auto base = reinterpret_cast<const BYTE*>(module.get());
            const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
            const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
            if ((nt->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) == 0)
                return ERROR_INVALID_DATA;
            const auto generate = reinterpret_cast<BOOL(WINAPI*)(PBYTE, SIZE_T)>(
                GetProcAddress(module.get(), "ProcessPrng"));
            std::array<BYTE, 32> bytes{};
            if (generate == nullptr || !generate(bytes.data(), bytes.size())) return ERROR_PROC_NOT_FOUND;
            ++accepted;
        }
    }

    // Changing the entry-point header tests signature rejection without introducing executable instructions.
    const auto damaged = std::wstring(reportPath) + L".tampered.dll";
    if (!CopyFileW(source.c_str(), damaged.c_str(), TRUE)) return GetLastError();
    FILE* opened = nullptr;
    if (_wfopen_s(&opened, damaged.c_str(), L"r+b") != 0) return ERROR_OPEN_FAILED;
    std::unique_ptr<FILE, decltype(&fclose)> stream(opened, fclose);
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS nt{};
    if (fread(&dos, sizeof(dos), 1, opened) != 1 || fseek(opened, dos.e_lfanew, SEEK_SET) != 0 ||
        fread(&nt, sizeof(nt), 1, opened) != 1) return ERROR_READ_FAULT;
    if (nt.OptionalHeader.AddressOfEntryPoint == 0) return ERROR_INVALID_DATA;
    const long entryOffset = dos.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
        offsetof(IMAGE_OPTIONAL_HEADER, AddressOfEntryPoint);
    const DWORD noEntry = 0;
    if (fseek(opened, entryOffset, SEEK_SET) != 0 || fwrite(&noEntry, sizeof(noEntry), 1, opened) != 1)
        return ERROR_WRITE_FAULT;
    stream.reset();
    for (const bool ansi : { false, true })
    {
        std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(
            LoadProbe(damaged.c_str(), ansi, LOAD_LIBRARY_REQUIRE_SIGNED_TARGET), FreeLibrary);
        const DWORD error = module ? ERROR_SUCCESS : GetLastError();
        if (module || error != ERROR_INVALID_IMAGE_HASH) return ERROR_INVALID_DATA;
        ++tampered;
    }
    return ERROR_SUCCESS;
}

int TestLibraryLoading(int argumentCount, wchar_t* arguments[])
{
    if (argumentCount != 9) return 2;
    const LPCWSTR library = arguments[2];
    const LPCWSTR key = arguments[3];
    const LPCWSTR valueName = arguments[4];
    const LPCWSTR file = arguments[5];
    const DWORD expectedValue = wcstoul(arguments[6], nullptr, 0);
    const DWORD expectedSize = wcstoul(arguments[7], nullptr, 0);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    FILE* output = nullptr;
    if (_wfopen_s(&output, arguments[8], L"w") != 0) return 2;
    std::unique_ptr<FILE, decltype(&fclose)> report(output, fclose);
    const auto fail = [&](LPCWSTR stage, DWORD error, DWORD flags = 0, bool ansi = false)
    {
        std::fprintf(output, "{\"success\":false,\"stage\":\"%ls\",\"error\":%lu,\"flags\":%lu,\"ansi\":%s}\n",
            stage, error, flags, ansi ? "true" : "false");
        return 1;
    };
    DWORD executableCases = 0, resourceCases = 0, searchCases = 0, signedCases = 0, unresolvedCases = 0, delayCases = 0;
    DWORD handleCases = 0, pinCases = 0;
    DWORD signedAccepted = 0, signedTampered = 0, manualCases = 0, lifecycleCases = 0;
    std::array<DWORD, 2> signatureResults{};
    std::vector<DWORD> validationResults;
    LoadingProbeResult result{};
    const auto verify = [&]() { return result.registryValue == expectedValue && result.fileSize == expectedSize; };

    // Cover every combination of documented search-directory flags, plus the other executable-load modes.
    constexpr DWORD searchBits[]{ LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
        LOAD_LIBRARY_SEARCH_USER_DIRS, LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS };
    std::vector<DWORD> searchFlags{ 0 };
    for (unsigned mask = 1; mask < (1U << std::size(searchBits)); ++mask)
    {
        DWORD flags = 0;
        for (size_t bit = 0; bit < std::size(searchBits); ++bit)
            if ((mask & (1U << bit)) != 0) flags |= searchBits[bit];
        searchFlags.push_back(flags);
    }
    auto executableFlags = searchFlags;
    executableFlags.insert(executableFlags.end(), { LOAD_WITH_ALTERED_SEARCH_PATH,
        LOAD_IGNORE_CODE_AUTHZ_LEVEL, LOAD_LIBRARY_SAFE_CURRENT_DIRS });
    for (const bool ansi : { false, true })
    {
        DWORD error = ReloadProbe(library, ansi, 0, key, valueName, file, result, true);
        if (error != ERROR_SUCCESS || !verify()) return fail(L"LoadLibrary", error, 0, ansi);
        ++executableCases;
        for (const DWORD flags : executableFlags)
        {
            error = ReloadProbe(library, ansi, flags, key, valueName, file, result);
            if (error != ERROR_SUCCESS || !verify()) return fail(L"LoadLibraryEx", error, flags, ansi);
            ++executableCases;
        }

        // Resource mappings must not initialize DLL code or enter the executable module list.
        for (const DWORD resourceFlags : { LOAD_LIBRARY_AS_DATAFILE, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE,
            LOAD_LIBRARY_AS_IMAGE_RESOURCE, LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE })
        {
            for (const DWORD search : searchFlags)
            {
                const DWORD flags = resourceFlags | search;
                std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(
                    LoadProbe(library, ansi, flags), FreeLibrary);
                if (!module) return fail(L"resource-load", GetLastError(), flags, ansi);
                const auto address = reinterpret_cast<ULONG_PTR>(module.get());
                if ((address & 3) == 0 || GetModuleHandleW(library) != nullptr)
                    return fail(L"resource-execution", ERROR_INVALID_DATA, flags, ansi);
                if ((error = CheckResource(module.get())) != ERROR_SUCCESS)
                    return fail(L"resource-data", error, flags, ansi);
                if ((resourceFlags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE) != 0)
                {
                    const HANDLE write = CreateFileW(library, GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
                    const DWORD denied = GetLastError();
                    if (write != INVALID_HANDLE_VALUE) CloseHandle(write);
                    if (write != INVALID_HANDLE_VALUE || denied != ERROR_SHARING_VIOLATION)
                        return fail(L"resource-exclusive", denied, flags, ansi);
                }
                const auto base = reinterpret_cast<HMODULE>(address & ~ULONG_PTR(3));
                module.reset();
                if ((error = CheckUnmapped(base, library)) != ERROR_SUCCESS)
                    return fail(L"resource-unload", error, flags, ansi);
                ++resourceCases;
            }

            // An already executable module remains initialized when acquired with a resource flag.
            std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> executable(LoadProbe(library, ansi, 0), FreeLibrary);
            if (!executable) return fail(L"resource-existing-setup", GetLastError(), resourceFlags, ansi);
            const HMODULE additional = LoadProbe(library, ansi, resourceFlags);
            if (additional != executable.get()) return fail(L"resource-existing-handle", ERROR_INVALID_HANDLE);
            if (!FreeLibrary(additional)) return fail(L"resource-existing-release", GetLastError());
            error = CheckLoadingProbe(executable.get(), key, valueName, file, nullptr, result);
            if (error != ERROR_SUCCESS || !verify())
                return fail(L"resource-existing-query", error, resourceFlags, ansi);
            const HMODULE address = executable.get();
            executable.reset();
            if ((error = CheckUnmapped(address, library)) != ERROR_SUCCESS)
                return fail(L"resource-existing-unload", error);
            ++resourceCases;
        }

        // DONT_RESOLVE_DLL_REFERENCES is inspected without ever calling an unresolved function.
        for (const DWORD search : searchFlags)
        {
            const DWORD flags = DONT_RESOLVE_DLL_REFERENCES | search;
            std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(LoadProbe(library, ansi, flags), FreeLibrary);
            if (!module) return fail(L"unresolved-load", GetLastError(), flags, ansi);
            const auto attached = reinterpret_cast<const DWORD*>(
                GetProcAddress(module.get(), "WinPrivLoadingAttachCount"));
            if (attached == nullptr || *attached != 0) return fail(L"unresolved-initialization", ERROR_INVALID_DATA);
            const HMODULE address = module.get();
            module.reset();
            if ((error = CheckUnmapped(address, library)) != ERROR_SUCCESS) return fail(L"unresolved-unload", error);
            error = ReloadProbe(library, ansi, search, key, valueName, file, result);
            if (error != ERROR_SUCCESS || !verify()) return fail(L"resolved-reload", error, search, ansi);
            ++unresolvedCases;
        }

        // Compare validation with the unhooked baseline: Windows can ignore unused flags for absolute paths.
        std::vector<DWORD> validationFlags;
        for (const DWORD search : searchFlags)
        {
            if (search != 0) validationFlags.push_back(LOAD_WITH_ALTERED_SEARCH_PATH | search);
        }
        validationFlags.insert(validationFlags.end(), { 0x80000000, LOAD_LIBRARY_REQUIRE_SIGNED_TARGET });
        for (const DWORD flags : validationFlags)
        {
            std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(LoadProbe(library, ansi, flags), FreeLibrary);
            const DWORD rejected = module ? ERROR_SUCCESS : GetLastError();
            validationResults.push_back(rejected);
            if (flags == LOAD_LIBRARY_REQUIRE_SIGNED_TARGET && rejected != ERROR_INVALID_IMAGE_HASH)
                return fail(L"unsigned-image", rejected, flags, ansi);
            if (!module) continue;
            error = CheckLoadingProbe(module.get(), key, valueName, file, nullptr, result);
            if (error != ERROR_SUCCESS || !verify())
                return fail(L"accepted-flags", error, flags, ansi);
            const HMODULE address = module.get();
            module.reset();
            if ((error = CheckUnmapped(address, library)) != ERROR_SUCCESS)
                return fail(L"accepted-flags-unload", error);
        }

        // Authenticode validity alone is insufficient when the image lacks FORCE_INTEGRITY.
        std::array<WCHAR, MAX_PATH> systemDirectory{};
        const UINT length = GetSystemDirectoryW(systemDirectory.data(), static_cast<UINT>(systemDirectory.size()));
        if (length == 0 || length >= systemDirectory.size()) return fail(L"system-directory", ERROR_BAD_PATHNAME);
        const auto signedPath = std::wstring(systemDirectory.data()) + L"\\version.dll";
        std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> signedModule(
            LoadProbe(signedPath.c_str(), ansi, LOAD_LIBRARY_REQUIRE_SIGNED_TARGET), FreeLibrary);
        signatureResults[ansi] = signedModule ? ERROR_SUCCESS : GetLastError();
        if (signedModule && GetProcAddress(signedModule.get(), "GetFileVersionInfoSizeW") == nullptr)
            return fail(L"signed-export", GetLastError(), LOAD_LIBRARY_REQUIRE_SIGNED_TARGET, ansi);
        ++signedCases;

        // Lookup flags determine whether releasing the original reference can unmap the DLL.
        for (const DWORD flags : { DWORD(0), DWORD(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT),
            DWORD(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS),
            DWORD(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) })
        {
            std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(LoadProbe(library, ansi, 0), FreeLibrary);
            if (!module) return fail(L"handle-load", GetLastError());
            const HMODULE address = module.get();
            const bool fromAddress = (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) != 0;
            const auto nameA = LoadingAnsi(library);
            HMODULE additional = nullptr;
            const BOOL found = ansi ? GetModuleHandleExA(flags,
                fromAddress ? reinterpret_cast<LPCSTR>(address) : nameA.c_str(), &additional) :
                GetModuleHandleExW(flags, fromAddress ? reinterpret_cast<LPCWSTR>(address) : library, &additional);
            if (!found || additional != address) return fail(L"handle-lookup", GetLastError(), flags, ansi);
            error = CheckLoadingProbe(address, key, valueName, file, nullptr, result);
            if (error != ERROR_SUCCESS || !verify())
                return fail(L"handle-query", error, flags, ansi);
            module.reset();
            if ((flags & GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT) == 0)
            {
                if (GetModuleHandleW(library) != additional || CheckResource(additional) != ERROR_SUCCESS)
                    return fail(L"handle-reference", ERROR_INVALID_HANDLE, flags, ansi);
                if (!FreeLibrary(additional)) return fail(L"handle-release", GetLastError(), flags, ansi);
            }
            if ((error = CheckUnmapped(address, library)) != ERROR_SUCCESS)
                return fail(L"handle-unload", error, flags, ansi);
            ++handleCases;
        }
    }

    // Basename loads must honor application, user, and default search directories, including expected failures.
    const std::wstring libraryPath(library);
    const auto separator = libraryPath.find_last_of(L'\\');
    if (separator == std::wstring::npos) return fail(L"library-path", ERROR_BAD_PATHNAME);
    const auto directory = libraryPath.substr(0, separator);
    const auto name = libraryPath.substr(separator + 1);
    const DLL_DIRECTORY_COOKIE cookie = AddDllDirectory(directory.c_str());
    if (cookie == nullptr) return fail(L"add-directory", GetLastError());
    for (const bool ansi : { false, true })
    {
        for (const DWORD flags : { LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_USER_DIRS })
        {
            const DWORD error = ReloadProbe(name.c_str(), ansi, flags, key, valueName, file, result);
            if (error != ERROR_SUCCESS || !verify()) return fail(L"search-directory", error, flags, ansi);
            ++searchCases;
        }
        for (const DWORD flags : { LOAD_LIBRARY_SEARCH_SYSTEM32, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR })
        {
            std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> module(
                LoadProbe(name.c_str(), ansi, flags), FreeLibrary);
            const DWORD error = module ? ERROR_SUCCESS : GetLastError();
            const DWORD expected = flags == LOAD_LIBRARY_SEARCH_SYSTEM32 ?
                ERROR_MOD_NOT_FOUND : ERROR_INVALID_PARAMETER;
            if (module || error != expected) return fail(L"search-rejection", error, flags, ansi);
            ++searchCases;
        }
        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)) return fail(L"default-system", GetLastError());
        std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> absent(
            LoadProbe(name.c_str(), ansi, 0, true), FreeLibrary);
        const DWORD error = absent ? ERROR_SUCCESS : GetLastError();
        if (absent || error != ERROR_MOD_NOT_FOUND) return fail(L"default-rejection", error, 0, ansi);
        ++searchCases;
        if (!SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_USER_DIRS | LOAD_LIBRARY_SEARCH_SYSTEM32))
            return fail(L"default-user", GetLastError());
        const DWORD loaded = ReloadProbe(name.c_str(), ansi, 0, key, valueName, file, result, true);
        if (loaded != ERROR_SUCCESS || !verify()) return fail(L"default-load", loaded, 0, ansi);
        ++searchCases;
    }
    if (!RemoveDllDirectory(cookie) || !SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_DEFAULT_DIRS))
        return fail(L"restore-directories", GetLastError());

#if defined(WINPRIV_LOADING_MODE_DELAY)
    // The MSVC helper must restore its import thunk and release the DLL before the next delayed call.
    volatile LONG detached = 0;
    HMODULE previous = nullptr;
    const auto release = [](void* address) { VirtualFree(address, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(release)> reservation(nullptr, release);
    for (unsigned iteration = 0; iteration < 3; ++iteration)
    {
        if (GetModuleHandleW(L"WinPrivLoadingProbe.dll") != nullptr)
            return fail(L"delay-not-unloaded", ERROR_BUSY);
        const DWORD error = WinPrivLoadingQuery(key, valueName, file, TRUE, &detached, &result);
        if (error != ERROR_SUCCESS || !verify() || result.attachCount != 1 || result.calls != 1)
            return fail(L"delay-query", error);
        const HMODULE module = GetModuleHandleW(L"WinPrivLoadingProbe.dll");
        if (module == nullptr || module == previous) return fail(L"delay-address", ERROR_INVALID_ADDRESS);
        const auto bytes = reinterpret_cast<const BYTE*>(module);
        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
        const auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(bytes + dos->e_lfanew);
        const DWORD size = nt->OptionalHeader.SizeOfImage;
        if (!__FUnloadDelayLoadedDLL2("WinPrivLoadingProbe.dll")) return fail(L"delay-unload", GetLastError());
        if (detached != static_cast<LONG>(iteration + 1)) return fail(L"delay-detach", ERROR_DLL_INIT_FAILED);
        const DWORD unmapped = CheckUnmapped(module, L"WinPrivLoadingProbe.dll");
        if (unmapped != ERROR_SUCCESS) return fail(L"delay-mapping", unmapped);
        reservation.reset();
        reservation.reset(VirtualAlloc(module, size, MEM_RESERVE, PAGE_NOACCESS));
        if (reservation.get() != module) return fail(L"delay-reserve", GetLastError());
        previous = module;
        ++delayCases;
    }
#endif

    const DWORD signedError = CheckSignedLoading(arguments[8], signedAccepted, signedTampered);
    if (signedError != ERROR_SUCCESS) return fail(L"signed-target", signedError);
    const DWORD manualError = TestManualLoading(library, key, valueName, file,
        expectedValue, expectedSize, manualCases, lifecycleCases);
    if (manualError != ERROR_SUCCESS) return fail(L"manual-loading", manualError);

    // Pinning deliberately retains the image until process exit, so this check must run after unload tests.
    std::unique_ptr<HINSTANCE__, decltype(&FreeLibrary)> pinned(LoadLibraryW(library), FreeLibrary);
    if (!pinned) return fail(L"pin-load", GetLastError());
    const HMODULE pinnedAddress = pinned.get();
    const DWORD query = CheckLoadingProbe(pinnedAddress, key, valueName, file, nullptr, result);
    if (query != ERROR_SUCCESS || !verify()) return fail(L"pin-query", query);
    for (const bool ansi : { false, true })
    {
        for (const DWORD flags : { GET_MODULE_HANDLE_EX_FLAG_PIN,
            GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS })
        {
            const bool fromAddress = (flags & GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS) != 0;
            const auto nameA = LoadingAnsi(library);
            HMODULE additional = nullptr;
            const BOOL found = ansi ? GetModuleHandleExA(flags,
                fromAddress ? reinterpret_cast<LPCSTR>(pinnedAddress) : nameA.c_str(), &additional) :
                GetModuleHandleExW(flags,
                    fromAddress ? reinterpret_cast<LPCWSTR>(pinnedAddress) : library, &additional);
            if (!found || additional != pinnedAddress) return fail(L"pin-lookup", GetLastError(), flags, ansi);
            pinned.reset();
            if (!FreeLibrary(additional) || GetModuleHandleW(library) != pinnedAddress ||
                CheckResource(pinnedAddress) != ERROR_SUCCESS)
                return fail(L"pin-retention", GetLastError(), flags, ansi);
            ++pinCases;
        }
    }

    std::fprintf(output, "{\"success\":true,\"executableCases\":%lu,\"resourceCases\":%lu,"
        "\"unresolvedCases\":%lu,\"searchCases\":%lu,\"signedCases\":%lu,\"delayCases\":%lu,"
        "\"handleCases\":%lu,\"pinCases\":%lu,\"signedAccepted\":%lu,\"signedTampered\":%lu,"
        "\"manualCases\":%lu,\"lifecycleCases\":%lu,\"signatureResults\":[%lu,%lu],\"validationResults\":[",
        executableCases, resourceCases, unresolvedCases, searchCases, signedCases, delayCases,
        handleCases, pinCases, signedAccepted, signedTampered, manualCases, lifecycleCases,
        signatureResults[0], signatureResults[1]);
    for (size_t index = 0; index < validationResults.size(); ++index)
        std::fprintf(output, "%s%lu", index == 0 ? "" : ",", validationResults[index]);
    std::fprintf(output, "]}\n");
    return 0;
}
