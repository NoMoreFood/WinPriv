//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include "WinPrivDllLoader.h"
#include "WinPrivShared.h"
#include <compressapi.h>
#include <wincrypt.h>
#include <mscat.h>
#include <rpc.h>
#include <algorithm>
#include <memory>
#include <string>

#pragma comment(lib, "cabinet.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "rpcrt4.lib")

namespace winpriv::loader
{
	constexpr DWORD digestSize = 32;
	constexpr DWORD maxLibrarySize = 64 * 1024 * 1024;

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

	bool AsciiDirectory(std::wstring& directory)
	{
		if (std::ranges::all_of(directory, [](WCHAR value) { return value <= 0x7f; })) return true;
		WCHAR shortPath[MAX_PATH + 1];
		const DWORD length = GetShortPathNameW(directory.c_str(), shortPath, static_cast<DWORD>(std::size(shortPath)));
		if (length == 0 || length >= std::size(shortPath) ||
			!std::all_of(shortPath, shortPath + length, [](WCHAR value) { return value <= 0x7f; })) return false;
		directory.assign(shortPath, length);
		return true;
	}

	bool VerifyLibraryPath(HANDLE file, LibraryImage resource, CHAR (&destination)[LibraryBundle::pathCapacity])
	{
		// Match the Authenticode digest to reject DLLs from a different build.
		if (resource.data == nullptr || resource.size <= digestSize)
		{
			SetLastError(ERROR_BAD_EXE_FORMAT);
			return false;
		}
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
		DWORD digestLength = digestSize;
		if (!CryptCATAdminCalcHashFromFileHandle2(catalog, file, &digestLength, digest, 0) ||
			digestLength != digestSize || memcmp(digest, resource.data, digestSize) != 0)
		{
			SetLastError(ERROR_INVALID_IMAGE_HASH);
			return false;
		}

		// Resolve junctions and symbolic links before publishing the locked file's name.
		const DWORD capacity = GetFinalPathNameByHandleW(file, nullptr, 0, FILE_NAME_NORMALIZED);
		if (capacity == 0) return false;
		std::wstring path(capacity, L'\0');
		const DWORD length = GetFinalPathNameByHandleW(file, path.data(), capacity, FILE_NAME_NORMALIZED);
		if (length == 0) return false;
		if (length >= capacity)
		{
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return false;
		}
		path.resize(length);
		const size_t separator = path.find_last_of(L'\\');
		std::wstring directory = path.substr(0, separator);
		if (!AsciiDirectory(directory) || !std::ranges::all_of(std::wstring_view(path).substr(separator),
			[](WCHAR value) { return value <= 0x7f; }))
		{
			SetLastError(ERROR_NO_UNICODE_TRANSLATION);
			return false;
		}
		path.replace(0, separator, directory);
		if (path.size() >= std::size(destination))
		{
			SetLastError(ERROR_FILENAME_EXCED_RANGE);
			return false;
		}
		std::transform(path.begin(), path.end(), destination, [](WCHAR value) { return CHAR(value); });
		destination[path.size()] = '\0';
		return true;
	}

	bool LoadLibraries(const std::array<LibraryImage, 3>& resources, std::wstring_view directory) noexcept
	{
		LibraryBundle bundle;
		std::wstring pendingFile;
		bool loaded = false;
		const auto closeHandles = [&]
		{
			for (ULONGLONG& handle : bundle.handles)
			{
				if (handle != 0) CloseHandle(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(handle)));
				handle = 0;
			}
		};
		const auto cleanup = [&](void*)
		{
			const DWORD error = GetLastError();
			if (!loaded)
			{
				closeHandles();
				if (!pendingFile.empty()) DeleteFileW(pendingFile.c_str());
			}
			SetLastError(error);
		};
		std::unique_ptr<void, decltype(cleanup)> lifetime(&bundle, cleanup);
		try
		{
			// Hold every adjacent file against replacement before deciding whether the bundle is complete.
			std::wstring base(directory);
			bool extract = !AsciiDirectory(base);
			if (!base.ends_with(L'\\')) base += L'\\';
			DWORD openError = NO_ERROR;
			for (size_t index = 0; !extract && index < resources.size(); ++index)
			{
				const std::wstring path = base + libraryNames[index];
				const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
					nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
				if (file != INVALID_HANDLE_VALUE) bundle.handles[index] = reinterpret_cast<ULONG_PTR>(file);
				else
				{
					const DWORD error = GetLastError();
					if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND) extract = true;
					else if (openError == NO_ERROR) openError = error;
				}
			}
			if (!extract)
			{
				if (openError != NO_ERROR)
				{
					SetLastError(openError);
					return false;
				}
				for (size_t index = 0; index < resources.size(); ++index)
				{
					const HANDLE file = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(bundle.handles[index]));
					if (!VerifyLibraryPath(file, resources[index], bundle.paths[index])) return false;
				}
				extract = GetModuleHandleA(bundle.paths[currentLibrary]) != nullptr;
			}

			// A separate copy gives nested launchers independent hook state and supports standalone executables.
			if (extract)
			{
				closeHandles();
				WCHAR temporary[MAX_PATH + 1];
				DWORD length = GetTempPathW(static_cast<DWORD>(std::size(temporary)), temporary);
				if (length == 0 || length >= std::size(temporary)) return false;
				base.assign(temporary, length);
				if (!AsciiDirectory(base))
				{
					length = GetSystemWindowsDirectoryW(temporary, static_cast<UINT>(std::size(temporary)));
					if (length == 0 || length >= std::size(temporary)) return false;
					base.assign(temporary, length);
					base += L"\\Temp";
					if (!AsciiDirectory(base))
					{
						SetLastError(ERROR_NO_UNICODE_TRANSLATION);
						return false;
					}
				}
				UUID uuid{};
				const RPC_STATUS status = UuidCreate(&uuid);
				RPC_WSTR text = nullptr;
				if ((status != RPC_S_OK && status != RPC_S_UUID_LOCAL_ONLY) || UuidToStringW(&uuid, &text) != RPC_S_OK)
				{
					SetLastError(ERROR_GEN_FAILURE);
					return false;
				}
				SmartPointer<RPC_WSTR> uuidText([](RPC_WSTR value) { RpcStringFreeW(&value); }, text);
				const std::wstring prefix = std::wstring(reinterpret_cast<LPCWSTR>(text)) + L'-';
				if (!base.ends_with(L'\\')) base += L'\\';

				// Write embedded copies before reopening them under their lifetime locks.
				for (size_t index = 0; index < resources.size(); ++index)
				{
					std::wstring path = base + L"WinPriv-" + prefix + (libraryNames[index] + 8);
					std::vector<BYTE> bytes;
					if (!DecompressLibrary(resources[index], bytes)) return false;
					SmartPointer<HANDLE> output(CloseHandle, CreateFileW(path.c_str(), GENERIC_WRITE,
						0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr));
					if (output == INVALID_HANDLE_VALUE) return false;
					pendingFile.swap(path);
					DWORD written = 0;
					if (!WriteFile(output, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr)) return false;
					if (written != bytes.size())
					{
						SetLastError(ERROR_WRITE_FAULT);
						return false;
					}
					output.Cleanup();
					const HANDLE file = CreateFileW(pendingFile.c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ,
						nullptr, OPEN_EXISTING, FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
					if (file == INVALID_HANDLE_VALUE) return false;
					bundle.handles[index] = reinterpret_cast<ULONG_PTR>(file);
					pendingFile.clear();
					if (!VerifyLibraryPath(file, resources[index], bundle.paths[index])) return false;
					FILE_DISPOSITION_INFO_EX disposition{
						FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS | FILE_DISPOSITION_FLAG_ON_CLOSE };
					if (!SetFileInformationByHandle(file, FileDispositionInfoEx, &disposition, sizeof(disposition)))
						return false;
				}

				const HANDLE mutex = CreateMutexW(nullptr, FALSE, nullptr);
				if (mutex == nullptr) return false;
				bundle.handles[3] = reinterpret_cast<ULONG_PTR>(mutex);
			}

			// The Windows loader owns image mapping, imports, TLS, and exception metadata.
			SmartPointer<HMODULE> module([&](HMODULE value)
			{
				const DWORD error = GetLastError();
				if (!loaded) FreeLibrary(value);
				SetLastError(error);
			},
				LoadLibraryExA(bundle.paths[currentLibrary], nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32));
			if (!module) return false;
			const auto initialize = reinterpret_cast<decltype(&WinPrivInitialize)>(GetProcAddress(module, "WinPrivInitialize"));
			const DWORD error = initialize == nullptr ? GetLastError() : initialize(&bundle);
			if (error != NO_ERROR)
			{
				SetLastError(error);
				return false;
			}
			loaded = true;
			return true;
		}
		catch (...)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			return false;
		}
	}
}
