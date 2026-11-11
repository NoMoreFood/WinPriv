//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <Windows.h>
#include <array>
#include <string_view>
#include <vector>

namespace winpriv::memory
{
	inline constexpr std::array<LPCWSTR, 3> libraryNames{
		L"WinPriv-x86.dll", L"WinPriv-x64.dll", L"WinPriv-ARM64.dll" };

	struct LibraryImage
	{
		LPCVOID data;
		DWORD size;
	};

	struct LibraryBundle
	{
		DWORD size;
		DWORD offsets[3];
		DWORD sizes[3];
		WCHAR directory[MAX_PATH + 1];
	};

	// Fixed-width addresses keep the initialization record identical across architectures.
	struct Initialization
	{
		ULONGLONG image;
		ULONGLONG bundle;
		ULONGLONG settings;
		ULONGLONG libraryPath;
		DWORD settingsSize;
		DWORD error;
		DWORD unwindRegistered = FALSE;
	};
	static_assert(sizeof(Initialization) == 48);

	bool DecompressLibrary(LibraryImage resource, std::vector<BYTE>& bytes);
	bool CreateBundle(const std::array<LibraryImage, 3>& resources, std::wstring_view directory,
		std::vector<BYTE>& bytes) noexcept;
	DWORD InitializeDiskLibrary(const Initialization* context);
	bool LoadBundle(const LibraryBundle* bundle) noexcept;
	bool InjectLibrary(HANDLE process, const LibraryBundle* bundle, LPCVOID settings, DWORD settingsSize) noexcept;
}

extern "C" DWORD WINAPI WinPrivInitialize(const winpriv::memory::Initialization* context);
