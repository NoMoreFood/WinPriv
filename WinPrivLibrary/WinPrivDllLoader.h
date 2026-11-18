//
// Copyright (c) Bryan Berns. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#pragma once

#include <Windows.h>
#include <array>
#include <string_view>
#include <vector>

namespace winpriv::loader
{
	inline constexpr std::array<LPCWSTR, 3> libraryNames{
		L"WinPriv-x86.dll", L"WinPriv-x64.dll", L"WinPriv-ARM64.dll" };
#if defined(_M_IX86)
	inline constexpr size_t currentLibrary = 0;
#elif defined(_M_X64)
	inline constexpr size_t currentLibrary = 1;
#else
	inline constexpr size_t currentLibrary = 2;
#endif
	inline constexpr GUID payloadGuid{
		0x3e72189e, 0xf3b2, 0x48a9, { 0x8b, 0xd1, 0xa2, 0xfa, 0x98, 0x4f, 0x74, 0x31 } };

	struct LibraryImage
	{
		LPCVOID data;
		DWORD size;
	};

	// Fixed-width handles keep the child payload identical across architectures.
	struct LibraryBundle
	{
		// The extended UNC prefix adds six characters to a conventional UNC path.
		static constexpr size_t pathCapacity = MAX_PATH + 1 + 6;
		CHAR paths[3][pathCapacity]{};
		ULONGLONG handles[4]{}; // Three locked DLL files and a cleanup mutex used only for temporary copies.
	};
	static_assert(sizeof(LibraryBundle) == 840);

	bool DecompressLibrary(LibraryImage resource, std::vector<BYTE>& bytes);
	bool LoadLibraries(const std::array<LibraryImage, 3>& resources, std::wstring_view directory) noexcept;
	bool InjectLibrary(HANDLE process, LPCVOID payload, DWORD size, decltype(&CreateProcessW) createProcess);
}

PVOID DetourFindPayload(REFGUID guid, DWORD& dataSize);
extern "C" BOOL WINAPI DetourFreePayload(PVOID data);
extern "C" BOOL WINAPI DetourRestoreAfterWith();
extern "C" BOOL WINAPI DetourIsHelperProcess();
extern "C" DWORD WINAPI WinPrivInitialize(const winpriv::loader::LibraryBundle* bundle);
