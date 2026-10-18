//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <Windows.h>
#include <array>
#include <vector>

namespace winpriv::memory
{
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
	};

	// Fixed-width addresses keep the initialization record identical across architectures.
	struct Initialization
	{
		ULONGLONG image;
		ULONGLONG bundle;
		ULONGLONG settings;
		DWORD settingsSize;
		DWORD error;
	};
	static_assert(sizeof(Initialization) == 32);

	bool CreateBundle(const std::array<LibraryImage, 3>& images, std::vector<BYTE>& bytes) noexcept;
	HMODULE LoadBundle(const LibraryBundle* bundle) noexcept;
	bool InjectLibrary(HANDLE process, const LibraryBundle* bundle, LPCVOID settings, DWORD settingsSize) noexcept;
}
