#pragma once

// Calls 64-bit native functions from a 32-bit WOW64 process via
// heaven's gate (x86-on-x64) or a syscall dispatch hook (x86-on-ARM64).

#if !(defined _M_IX86)
#error WinPrivWow64Call.h is for x86 builds only
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <mutex>
#include <string_view>
#include <system_error>
#include <type_traits>

namespace winpriv::wow64
{

// 64-bit PEB structures for walking the native module list from WOW64.

struct LIST_ENTRY_64 { std::uint64_t Flink, Blink; };

struct UNICODE_STRING_64
{
	std::uint16_t Length;
	std::uint16_t MaximumLength;
	std::uint64_t Buffer;
};

struct PROCESS_BASIC_INFORMATION_64
{
	std::uint64_t Reserved1;
	std::uint64_t PebBaseAddress;
	std::uint64_t Reserved2[4];
};

struct PEB_64
{
	std::uint8_t Pad[4];
	std::uint64_t Reserved[2];
	std::uint64_t Ldr;
};

struct PEB_LDR_DATA_64
{
	std::uint32_t Length;
	std::uint32_t Initialized;
	std::uint64_t SsHandle;
	LIST_ENTRY_64 InLoadOrderModuleList;
};

struct LDR_DATA_TABLE_ENTRY_64
{
	LIST_ENTRY_64 InLoadOrderLinks;
	LIST_ENTRY_64 InMemoryOrderLinks;
	LIST_ENTRY_64 InInitializationOrderLinks;
	std::uint64_t DllBase;
	std::uint64_t EntryPoint;
	union { std::uint32_t SizeOfImage; std::uint64_t Pad; };
	UNICODE_STRING_64 FullDllName;
	UNICODE_STRING_64 BaseDllName;
};

// Zero-extend a 32-bit pointer to 64 bits. Direct casts sign-extend, which
// produces invalid addresses with /LARGEADDRESSAWARE.

template <typename T>
inline std::uint64_t ptr_to_uint64(T* ptr) noexcept
{
	static_assert(sizeof(ptr) == sizeof(std::uint32_t));
	return static_cast<std::uint64_t>(reinterpret_cast<std::uint32_t>(ptr));
}

// Sign-extend a handle to 64 bits (required for pseudo-handles).

inline std::uint64_t handle_to_uint64(HANDLE handle) noexcept
{
	static_assert(sizeof(handle) == sizeof(std::int32_t));
	return static_cast<std::uint64_t>(reinterpret_cast<std::int32_t>(handle));
}

namespace detail
{

// All cached state uses trivially constructible types so statics are
// constant-initialized at load time. This avoids TLS, which MSVC uses
// for magic-static guards. std::call_once handles thread safety instead.

using QueryInfoProcess64T =
	LONG(__stdcall*)(HANDLE, std::uint32_t, void*, std::uint32_t, std::uint32_t*);
using ReadVirtualMemory64T =
	LONG(__stdcall*)(HANDLE, std::uint64_t, void*, std::uint64_t, std::uint64_t*);

// Bootstrap: resolve WOW64 ntdll functions and the 64-bit PEB address.

struct BootstrapState
{
	QueryInfoProcess64T queryProcess{};
	ReadVirtualMemory64T readMemory{};
	HANDLE selfHandle{};
	std::uint64_t pebAddress{};
	int error{};
};

inline const BootstrapState& Bootstrap() noexcept
{
	static BootstrapState state;
	static std::once_flag flag;
	std::call_once(flag, []()
	{
		const auto ntdll = GetModuleHandleW(L"ntdll.dll");
		if (!ntdll) { state.error = static_cast<int>(GetLastError()); return; }
		state.queryProcess = reinterpret_cast<QueryInfoProcess64T>(
			GetProcAddress(ntdll, "NtWow64QueryInformationProcess64"));
		state.readMemory = reinterpret_cast<ReadVirtualMemory64T>(
			GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64"));
		if (!state.queryProcess || !state.readMemory)
			{ state.error = static_cast<int>(GetLastError()); return; }
		if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(),
			GetCurrentProcess(), &state.selfHandle, 0, 0, DUPLICATE_SAME_ACCESS))
			{ state.error = static_cast<int>(GetLastError()); return; }
		PROCESS_BASIC_INFORMATION_64 pbi{};
		const LONG status = state.queryProcess(
			GetCurrentProcess(), 0, &pbi, sizeof(pbi), nullptr);
		if (status < 0) { state.error = status; return; }
		state.pebAddress = pbi.PebBaseAddress;
	});
	return state;
}

// Read 64-bit process memory. Low addresses are accessible directly.

inline void ReadMemory64(std::uint64_t address, void* buffer, std::size_t size,
	std::error_code& ec) noexcept
{
	if (size == 0) return;
	if (address + size - 1 <= std::numeric_limits<std::uint32_t>::max())
	{
		std::memcpy(buffer,
			reinterpret_cast<const void*>(static_cast<std::uint32_t>(address)), size);
		return;
	}
	const auto& boot = Bootstrap();
	if (boot.error) { ec = { boot.error, std::system_category() }; return; }
	const LONG status = boot.readMemory(
		boot.selfHandle, address, buffer, size, nullptr);
	if (status < 0) ec = { status, std::system_category() };
}

template <typename T>
inline T ReadMemory64(std::uint64_t address, std::error_code& ec) noexcept
{
	static_assert(std::is_trivially_copyable_v<T>);
	T value{};
	ReadMemory64(address, &value, sizeof(T), ec);
	return value;
}

template <typename T>
inline std::unique_ptr<T[]> AllocNothrow(std::size_t count) noexcept
{
	try { return std::make_unique<T[]>(count); }
	catch (...) { return nullptr; }
}

// Walk the 64-bit InLoadOrderModuleList. The callback returns true to stop.

template <typename Fn>
inline bool ForEachModule64(Fn&& fn, std::error_code& ec) noexcept
{
	const auto& boot = Bootstrap();
	if (boot.error)
		{ ec = { boot.error, std::system_category() }; return false; }
	const auto ldr = ReadMemory64<PEB_64>(boot.pebAddress, ec).Ldr;
	if (ec) return false;
	const auto sentinel =
		ldr + offsetof(PEB_LDR_DATA_64, InLoadOrderModuleList);
	auto entry = ReadMemory64<PEB_LDR_DATA_64>(ldr, ec)
		.InLoadOrderModuleList.Flink;
	if (ec) return false;
	while (entry != sentinel)
	{
		LDR_DATA_TABLE_ENTRY_64 module{};
		ReadMemory64(entry, &module, sizeof(module), ec);
		if (ec) return false;
		if (fn(module)) return true;
		entry = module.InLoadOrderLinks.Flink;
	}
	return false;
}

// Find LdrGetProcedureAddress in the native ntdll export table.

inline std::uint64_t FindLdrProcedureAddress(std::uint64_t ntdllBase,
	std::error_code& ec) noexcept
{
	const auto lfanew =
		ReadMemory64<IMAGE_DOS_HEADER>(ntdllBase, ec).e_lfanew;
	if (ec) return 0;
	const auto exportRva =
		ReadMemory64<IMAGE_NT_HEADERS64>(ntdllBase + lfanew, ec)
			.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
			.VirtualAddress;
	if (ec) return 0;
	if (exportRva == 0)
		{ ec = { ERROR_PROC_NOT_FOUND, std::system_category() }; return 0; }
	const auto ied =
		ReadMemory64<IMAGE_EXPORT_DIRECTORY>(ntdllBase + exportRva, ec);
	if (ec) return 0;

	auto rvaTable = AllocNothrow<std::uint32_t>(ied.NumberOfFunctions);
	auto ordTable = AllocNothrow<std::uint16_t>(ied.NumberOfNames);
	auto nameTable = AllocNothrow<std::uint32_t>(ied.NumberOfNames);
	if (!rvaTable || !ordTable || !nameTable)
		{ ec = { ERROR_NOT_ENOUGH_MEMORY, std::system_category() }; return 0; }
	ReadMemory64(ntdllBase + ied.AddressOfFunctions, rvaTable.get(),
		sizeof(std::uint32_t) * ied.NumberOfFunctions, ec);
	if (ec) return 0;
	ReadMemory64(ntdllBase + ied.AddressOfNameOrdinals, ordTable.get(),
		sizeof(std::uint16_t) * ied.NumberOfNames, ec);
	if (ec) return 0;
	ReadMemory64(ntdllBase + ied.AddressOfNames, nameTable.get(),
		sizeof(std::uint32_t) * ied.NumberOfNames, ec);
	if (ec) return 0;

	const char target[] = "LdrGetProcedureAddress";
	char buffer[sizeof(target)] = "";
	for (std::size_t i = 0; i < ied.NumberOfNames; ++i)
	{
		ReadMemory64(ntdllBase + nameTable[i], &buffer, sizeof(buffer), ec);
		if (ec) { ec.clear(); continue; }
		if (std::equal(std::begin(target), std::end(target), buffer))
			return ntdllBase + rvaTable[ordTable[i]];
	}
	ec = { ERROR_PROC_NOT_FOUND, std::system_category() };
	return 0;
}

// x86-to-x64 heaven's gate transition shellcode

#pragma code_seg(push, r1, ".text")
__declspec(allocate(".text"))
inline static const std::uint8_t x64CallShellcode[] = {
	// clang-format off

	0x55,             // push ebp
	0x89, 0xE5,       // mov ebp, esp
	0x83, 0xE4, 0xF0, // and esp, 0xFFFFFFF0

	// enter 64-bit mode
	0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB,

	0x67, 0x48, 0x8B, 0x4D, 16, // mov rcx, [ebp + 16]
	0x67, 0x48, 0x8B, 0x55, 24, // mov rdx, [ebp + 24]
	0x67, 0x4C, 0x8B, 0x45, 32, // mov r8,  [ebp + 32]
	0x67, 0x4C, 0x8B, 0x4D, 40, // mov r9,  [ebp + 40]
	0x67, 0x48, 0x8B, 0x45, 48, // mov rax, [ebp + 48] args count

	0xA8, 0x01,             // test al, 1
	0x75, 0x04,             // jne _no_adjust
	0x48, 0x83, 0xEC, 0x08, // sub rsp, 8

	0x57,                                     // push rdi
	0x67, 0x48, 0x8B, 0x7D, 0x38,             // mov rdi, [ebp + 56]
	0x48, 0x85, 0xC0,                         // test rax, rax
	0x74, 0x16, 0x48, 0x8D, 0x7C, 0xC7, 0xF8, // je _ls_e / lea rdi, [rdi+rax*8-8]

	0x48, 0x85, 0xC0,       // test rax, rax
	0x74, 0x0C,             // je _ls_e
	0xFF, 0x37,             // push [rdi]
	0x48, 0x83, 0xEF, 0x08, // sub rdi, 8
	0x48, 0x83, 0xE8, 0x01, // sub rax, 1
	0xEB, 0xEF,             // jmp _ls

	0x67, 0x8B, 0x7D, 0x40,       // mov edi, [ebp + 64]
	0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
	0x67, 0xFF, 0x55, 0x08,       // call [ebp + 0x8]
	0x67, 0x48, 0x89, 0x07,       // mov [edi], rax
	0x67, 0x48, 0x8B, 0x4D, 0x30, // mov rcx, [ebp+48]
	0x48, 0x8D, 0x64, 0xCC, 0x20, // lea rsp, [rsp+rcx*8+0x20]
	0x5F,                         // pop rdi

	// exit 64-bit mode
	0xE8, 0, 0, 0, 0, 0xC7, 0x44, 0x24, 4, 0x23, 0, 0, 0, 0x83, 4, 0x24, 0xD, 0xCB,

	0x66, 0x8C, 0xD8, // mov ax, ds
	0x8E, 0xD0,       // mov ss, eax
	0x89, 0xEC,       // mov esp, ebp
	0x5D,             // pop ebp
	0xC3              // ret

	// clang-format on
};
#pragma code_seg(pop, r1)

// CFG requires an indirect call through a real function entry point.

__declspec(naked) inline void x64CallThunk()
{
	__asm {
		mov eax, offset x64CallShellcode
		jmp eax
	}
}

template <class... Args>
inline std::uint64_t CallFunction_x64(std::uint64_t func,
	Args... args) noexcept
{
	std::uint64_t arr[sizeof...(args) > 4 ? sizeof...(args) : 4] = {
		static_cast<std::uint64_t>(args)... };
	using Sig = void(__cdecl*)(
		std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t,
		std::uint64_t, std::uint64_t, std::uint64_t, std::uint32_t);
	std::uint64_t ret;
	reinterpret_cast<Sig>(&x64CallThunk)(
		func, arr[0], arr[1], arr[2], arr[3],
		sizeof...(Args) > 4 ? (sizeof...(Args) - 4) : 0,
		ptr_to_uint64(arr + 4),
		reinterpret_cast<std::uint32_t>(&ret));
	return ret;
}

// ARM64 syscall dispatch hook: patches the CPU emulator's import of
// Wow64SystemServiceEx to route a synthetic syscall through our hook,
// which interprets a parameter structure to call arbitrary 64-bit functions.

#pragma code_seg(push, r1, ".text64")
#pragma warning(push)
#pragma warning(disable : 4200)
struct Wow64ServiceHook
{
	std::uint64_t original;
	std::uint8_t hook[];
};

// External linkage so every translation unit shares one instance.
__declspec(allocate(".text64"))
inline Wow64ServiceHook wow64ServiceHook = {
	0xD4200000D4200000,
	{
		// clang-format off

		// Native ARM64 hook, compiled from the native_64_shellcode project.
		0xff, 0x43, 0x00, 0xd1, 0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0xff, 0x83, 0x01, 0xd1,
		0x08, 0x00, 0x00, 0x90, 0x02, 0x21, 0x00, 0x91, 0x1f, 0xa8, 0x3f, 0x71, 0xe0, 0x00, 0x00, 0x54,
		0x48, 0x80, 0x5f, 0xf8, 0x00, 0x01, 0x3f, 0xd6, 0xff, 0x83, 0x01, 0x91, 0xfd, 0x7b, 0xc1, 0xa8,
		0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6, 0xf3, 0x3b, 0x00, 0xf9, 0x33, 0x00, 0x40, 0xb9,
		0x49, 0x20, 0x00, 0x58, 0x68, 0x02, 0x40, 0xf9, 0x1f, 0x01, 0x09, 0xeb, 0x20, 0x01, 0x00, 0x54,
		0x48, 0x80, 0x5f, 0xf8, 0x40, 0xfd, 0x81, 0x52, 0x00, 0x01, 0x3f, 0xd6, 0xf3, 0x3b, 0x40, 0xf9,
		0xff, 0x83, 0x01, 0x91, 0xfd, 0x7b, 0xc1, 0xa8, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
		0x69, 0xaa, 0x40, 0xa9, 0x00, 0x00, 0x80, 0x92, 0x68, 0x0e, 0x40, 0xf9, 0x6a, 0x00, 0x00, 0xb5,
		0x20, 0x01, 0x3f, 0xd6, 0xe8, 0x00, 0x00, 0x14, 0x5f, 0x05, 0x00, 0xf1, 0x81, 0x00, 0x00, 0x54,
		0x00, 0x01, 0x40, 0xf9, 0x20, 0x01, 0x3f, 0xd6, 0xe3, 0x00, 0x00, 0x14, 0x5f, 0x09, 0x00, 0xf1,
		0x81, 0x00, 0x00, 0x54, 0x00, 0x05, 0x40, 0xa9, 0x20, 0x01, 0x3f, 0xd6, 0xde, 0x00, 0x00, 0x14,
		0x5f, 0x0d, 0x00, 0xf1, 0xa1, 0x00, 0x00, 0x54, 0x02, 0x09, 0x40, 0xf9, 0x00, 0x05, 0x40, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0xd8, 0x00, 0x00, 0x14, 0x5f, 0x11, 0x00, 0xf1, 0xa1, 0x00, 0x00, 0x54,
		0x02, 0x0d, 0x41, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0x20, 0x01, 0x3f, 0xd6, 0xd2, 0x00, 0x00, 0x14,
		0x5f, 0x15, 0x00, 0xf1, 0xc1, 0x00, 0x00, 0x54, 0x04, 0x11, 0x40, 0xf9, 0x02, 0x0d, 0x41, 0xa9,
		0x00, 0x05, 0x40, 0xa9, 0x20, 0x01, 0x3f, 0xd6, 0xcb, 0x00, 0x00, 0x14, 0x5f, 0x19, 0x00, 0xf1,
		0xc1, 0x00, 0x00, 0x54, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9, 0x00, 0x05, 0x40, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0xc4, 0x00, 0x00, 0x14, 0x5f, 0x1d, 0x00, 0xf1, 0xe1, 0x00, 0x00, 0x54,
		0x06, 0x19, 0x40, 0xf9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9, 0x00, 0x05, 0x40, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0xbc, 0x00, 0x00, 0x14, 0x5f, 0x21, 0x00, 0xf1, 0xe1, 0x00, 0x00, 0x54,
		0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9, 0x00, 0x05, 0x40, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0xb4, 0x00, 0x00, 0x14, 0x5f, 0x25, 0x00, 0xf1, 0x21, 0x01, 0x00, 0x54,
		0x0a, 0x21, 0x40, 0xf9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0x00, 0x05, 0x40, 0xa9, 0xea, 0x03, 0x00, 0xf9, 0x20, 0x01, 0x3f, 0xd6, 0xaa, 0x00, 0x00, 0x14,
		0x5f, 0x29, 0x00, 0xf1, 0x21, 0x01, 0x00, 0x54, 0x0a, 0x2d, 0x44, 0xa9, 0x06, 0x1d, 0x43, 0xa9,
		0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0xa0, 0x00, 0x00, 0x14, 0x5f, 0x2d, 0x00, 0xf1, 0x61, 0x01, 0x00, 0x54,
		0x0a, 0x29, 0x40, 0xf9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x0b, 0x00, 0xf9, 0x0a, 0x2d, 0x44, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x94, 0x00, 0x00, 0x14, 0x5f, 0x31, 0x00, 0xf1, 0x61, 0x01, 0x00, 0x54,
		0x0a, 0x2d, 0x45, 0xa9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x88, 0x00, 0x00, 0x14, 0x5f, 0x35, 0x00, 0xf1, 0xa1, 0x01, 0x00, 0x54,
		0x0a, 0x31, 0x40, 0xf9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x13, 0x00, 0xf9, 0x0a, 0x2d, 0x45, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x01, 0xa9,
		0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9, 0x20, 0x01, 0x3f, 0xd6, 0x7a, 0x00, 0x00, 0x14,
		0x5f, 0x39, 0x00, 0xf1, 0xa1, 0x01, 0x00, 0x54, 0x0a, 0x2d, 0x46, 0xa9, 0x06, 0x1d, 0x43, 0xa9,
		0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9, 0xea, 0x2f, 0x02, 0xa9, 0x0a, 0x2d, 0x45, 0xa9,
		0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x6c, 0x00, 0x00, 0x14, 0x5f, 0x3d, 0x00, 0xf1, 0xe1, 0x01, 0x00, 0x54,
		0x0a, 0x39, 0x40, 0xf9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x1b, 0x00, 0xf9, 0x0a, 0x2d, 0x46, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x02, 0xa9,
		0x0a, 0x2d, 0x45, 0xa9, 0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x5c, 0x00, 0x00, 0x14, 0x5f, 0x41, 0x00, 0xf1, 0xe1, 0x01, 0x00, 0x54,
		0x0a, 0x2d, 0x47, 0xa9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x2f, 0x03, 0xa9, 0x0a, 0x2d, 0x46, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x02, 0xa9,
		0x0a, 0x2d, 0x45, 0xa9, 0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x4c, 0x00, 0x00, 0x14, 0x5f, 0x45, 0x00, 0xf1, 0x21, 0x02, 0x00, 0x54,
		0x0a, 0x41, 0x40, 0xf9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x23, 0x00, 0xf9, 0x0a, 0x2d, 0x47, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x03, 0xa9,
		0x0a, 0x2d, 0x46, 0xa9, 0xea, 0x2f, 0x02, 0xa9, 0x0a, 0x2d, 0x45, 0xa9, 0xea, 0x2f, 0x01, 0xa9,
		0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9, 0x20, 0x01, 0x3f, 0xd6, 0x3a, 0x00, 0x00, 0x14,
		0x5f, 0x49, 0x00, 0xf1, 0x21, 0x02, 0x00, 0x54, 0x0a, 0x2d, 0x48, 0xa9, 0x06, 0x1d, 0x43, 0xa9,
		0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9, 0xea, 0x2f, 0x04, 0xa9, 0x0a, 0x2d, 0x47, 0xa9,
		0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x03, 0xa9, 0x0a, 0x2d, 0x46, 0xa9, 0xea, 0x2f, 0x02, 0xa9,
		0x0a, 0x2d, 0x45, 0xa9, 0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x28, 0x00, 0x00, 0x14, 0x5f, 0x4d, 0x00, 0xf1, 0x61, 0x02, 0x00, 0x54,
		0x0a, 0x49, 0x40, 0xf9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x2b, 0x00, 0xf9, 0x0a, 0x2d, 0x48, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x04, 0xa9,
		0x0a, 0x2d, 0x47, 0xa9, 0xea, 0x2f, 0x03, 0xa9, 0x0a, 0x2d, 0x46, 0xa9, 0xea, 0x2f, 0x02, 0xa9,
		0x0a, 0x2d, 0x45, 0xa9, 0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x14, 0x00, 0x00, 0x14, 0x5f, 0x51, 0x00, 0xf1, 0x41, 0x02, 0x00, 0x54,
		0x0a, 0x2d, 0x49, 0xa9, 0x06, 0x1d, 0x43, 0xa9, 0x04, 0x15, 0x42, 0xa9, 0x02, 0x0d, 0x41, 0xa9,
		0xea, 0x2f, 0x05, 0xa9, 0x0a, 0x2d, 0x48, 0xa9, 0x00, 0x05, 0x40, 0xa9, 0xea, 0x2f, 0x04, 0xa9,
		0x0a, 0x2d, 0x47, 0xa9, 0xea, 0x2f, 0x03, 0xa9, 0x0a, 0x2d, 0x46, 0xa9, 0xea, 0x2f, 0x02, 0xa9,
		0x0a, 0x2d, 0x45, 0xa9, 0xea, 0x2f, 0x01, 0xa9, 0x0a, 0x2d, 0x44, 0xa9, 0xea, 0x2f, 0x00, 0xa9,
		0x20, 0x01, 0x3f, 0xd6, 0x28, 0x00, 0x80, 0xd2, 0x68, 0x02, 0x02, 0xa9, 0x00, 0x00, 0x80, 0x52,
		0xf3, 0x3b, 0x40, 0xf9, 0xff, 0x83, 0x01, 0x91, 0xfd, 0x7b, 0xc1, 0xa8, 0xff, 0x43, 0x00, 0x91,
		0xc0, 0x03, 0x5f, 0xd6, 0x1f, 0x20, 0x03, 0xd5, 0x23, 0x82, 0x90, 0x43, 0xbe, 0xe9, 0xe3, 0x89,

		// clang-format on
	},
};
#pragma warning(pop)
#pragma code_seg(pop, r1)

#pragma code_seg(push, r1, ".text")
__declspec(allocate(".text"))
inline static const std::uint8_t fastcallSyscallShellcode[] = {
	// clang-format off
	0x89, 0xC8,        // mov eax, ecx
	0xFF, 0xD2,        // call edx
	0xC2, 0x04, 0x00,  // ret 4
	// clang-format on
};
#pragma code_seg(pop, r1)

__declspec(naked) inline void __fastcall fastcallSyscallThunk()
{
	__asm {
		mov eax, offset fastcallSyscallShellcode
		jmp eax
	}
}

// PE64 validation and import table walking for finding the CPU emulator.

inline bool IsPe64Image(std::uint64_t moduleBase) noexcept
{
	const auto* base = reinterpret_cast<const std::byte*>(
		static_cast<std::uintptr_t>(moduleBase));
	constexpr LONG maxHeadersSize = 0x1000;
	const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE ||
		dos->e_lfanew < static_cast<LONG>(sizeof(IMAGE_DOS_HEADER)) ||
		dos->e_lfanew > maxHeadersSize -
			static_cast<LONG>(sizeof(IMAGE_NT_HEADERS64)))
		return false;
	const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
		base + dos->e_lfanew);
	return nt->Signature == IMAGE_NT_SIGNATURE &&
		nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
		nt->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT;
}

inline std::uint64_t* FindImportPtr64(HMODULE module,
	const char* moduleName, const char* importName) noexcept
{
	auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(module);
	auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
		reinterpret_cast<std::byte*>(dos) + dos->e_lfanew);
	if (!nt->OptionalHeader
		.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)
		return nullptr;
	auto* imageBase = reinterpret_cast<std::byte*>(module);
	auto* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
		imageBase + nt->OptionalHeader
			.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	while (desc->OriginalFirstThunk)
	{
		if (_stricmp(reinterpret_cast<const char*>(
			imageBase + desc->Name), moduleName) == 0)
		{
			auto* oft = reinterpret_cast<IMAGE_THUNK_DATA64*>(
				imageBase + desc->OriginalFirstThunk);
			auto* ft = reinterpret_cast<IMAGE_THUNK_DATA64*>(
				imageBase + desc->FirstThunk);
			while (std::uint64_t iter = oft->u1.Function)
			{
				if (!IMAGE_SNAP_BY_ORDINAL64(iter))
				{
					if (reinterpret_cast<std::uint64_t>(importName) & ~0xFFFF)
						if (strcmp(reinterpret_cast<const char*>(
							imageBase + iter + sizeof(std::uint16_t)),
							importName) == 0)
							return &ft->u1.Function;
				}
				else if ((reinterpret_cast<std::uint64_t>(importName) &
					~0xFFFF) == 0 &&
					IMAGE_ORDINAL64(iter) == IMAGE_ORDINAL64(
						reinterpret_cast<std::uint64_t>(importName)))
					return &ft->u1.Function;
				oft++;
				ft++;
			}
		}
		desc++;
	}
	return nullptr;
}

// Find the CPU emulator module's IAT entry for Wow64SystemServiceEx.
// The module is identified by what it imports rather than by name, since the
// name varies across Windows versions (xtajit.dll and its variants).

inline std::uint64_t* FindWow64SystemServiceExPtr(
	std::error_code& ec) noexcept
{
	const auto processImageBase = static_cast<std::uint64_t>(
		reinterpret_cast<std::uint32_t>(GetModuleHandleW(nullptr)));
	std::uint64_t* importPtr = nullptr;
	bool candidateSeen = false;
	const bool found = ForEachModule64(
		[&](const LDR_DATA_TABLE_ENTRY_64& entry)
	{
		const auto base = entry.DllBase;
		if (!base || base > std::numeric_limits<std::uint32_t>::max() ||
			base == processImageBase || !IsPe64Image(base))
			return false;
		candidateSeen = true;
		importPtr = FindImportPtr64(
			reinterpret_cast<HMODULE>(static_cast<std::uintptr_t>(base)),
			"wow64.dll", "Wow64SystemServiceEx");
		return importPtr != nullptr;
	}, ec);
	if (found) return importPtr;
	if (ec) return nullptr;
	ec = { candidateSeen ? ERROR_PROC_NOT_FOUND : ERROR_MOD_NOT_FOUND,
		std::system_category() };
	return nullptr;
}

// ARM64 hook state: installs and restores the IAT patch around each call.

struct Arm64State
{
	void** ppWow64Transition{};
	std::uint64_t* ppSystemServiceEx{};
	std::uint64_t originalServiceEx{};
	SRWLOCK lock = SRWLOCK_INIT;
	int callCount{};
	int error{};
};

inline Arm64State InitializeArm64() noexcept
{
	Arm64State state;
	const auto ntdll = GetModuleHandleW(L"ntdll.dll");
	if (!ntdll)
		{ state.error = static_cast<int>(GetLastError()); return state; }
	state.ppWow64Transition = reinterpret_cast<void**>(
		GetProcAddress(ntdll, "Wow64Transition"));
	if (!state.ppWow64Transition)
		{ state.error = static_cast<int>(GetLastError()); return state; }
	std::error_code ec;
	state.ppSystemServiceEx = FindWow64SystemServiceExPtr(ec);
	if (ec) { state.error = ec.value(); return state; }
	state.originalServiceEx = *state.ppSystemServiceEx;

	DWORD oldProtect;
	if (!VirtualProtect(&wow64ServiceHook.original,
		sizeof(wow64ServiceHook.original), PAGE_READWRITE, &oldProtect))
		{ state.error = static_cast<int>(GetLastError()); return state; }
	wow64ServiceHook.original = state.originalServiceEx;
	VirtualProtect(&wow64ServiceHook.original,
		sizeof(wow64ServiceHook.original), oldProtect, &oldProtect);
	return state;
}

inline Arm64State& GetArm64State() noexcept
{
	static Arm64State state;
	static std::once_flag flag;
	std::call_once(flag, []() { state = InitializeArm64(); });
	return state;
}

template <class... Args>
inline std::uint64_t CallFunction_arm64(std::error_code& ec,
	std::uint64_t func, Args... args) noexcept
{
	auto& state = GetArm64State();
	if (state.error)
		{ ec = { state.error, std::system_category() }; return ~0ULL; }

	std::uint32_t syscallNum = 0x0FEA;
	std::uint64_t arr[sizeof...(args) > 1 ? sizeof...(args) : 1] = {
		static_cast<std::uint64_t>(args)... };

	struct {
		std::uint64_t signature;
		std::uint64_t func;
		std::uint64_t argsCount;
		std::uint64_t args;
		std::uint64_t called;
		std::uint64_t ret;
	} param{
		.signature = 0x89E3E9BE43908223,
		.func = func,
		.argsCount = sizeof...(Args),
		.args = ptr_to_uint64(arr),
	};

	// Install the hook while reference count is positive.
	AcquireSRWLockExclusive(&state.lock);
	if (state.callCount == 0)
	{
		DWORD oldProtect;
		if (!VirtualProtect(state.ppSystemServiceEx,
			sizeof(*state.ppSystemServiceEx), PAGE_READWRITE, &oldProtect))
		{
			ec = { static_cast<int>(GetLastError()), std::system_category() };
			ReleaseSRWLockExclusive(&state.lock);
			return ~0ULL;
		}
		*state.ppSystemServiceEx = ptr_to_uint64(wow64ServiceHook.hook);
		VirtualProtect(state.ppSystemServiceEx,
			sizeof(*state.ppSystemServiceEx), oldProtect, &oldProtect);
	}
	state.callCount++;
	ReleaseSRWLockExclusive(&state.lock);

	using SyscallSig = void(__fastcall*)(std::uint32_t, void*, void*);
	reinterpret_cast<SyscallSig>(&fastcallSyscallThunk)(
		syscallNum, *state.ppWow64Transition, &param);

	// Restore the original dispatcher when the last concurrent caller exits.
	AcquireSRWLockExclusive(&state.lock);
	state.callCount--;
	if (state.callCount == 0)
	{
		DWORD oldProtect;
		if (!VirtualProtect(state.ppSystemServiceEx,
			sizeof(*state.ppSystemServiceEx), PAGE_READWRITE, &oldProtect))
			__fastfail(FAST_FAIL_FATAL_APP_EXIT);
		*state.ppSystemServiceEx = state.originalServiceEx;
		VirtualProtect(state.ppSystemServiceEx,
			sizeof(*state.ppSystemServiceEx), oldProtect, &oldProtect);
	}
	ReleaseSRWLockExclusive(&state.lock);

	if (!param.called) __fastfail(FAST_FAIL_FATAL_APP_EXIT);
	return param.ret;
}

// Cached native machine architecture.

struct MachineState
{
	std::uint16_t machine{};
	int error{};
};

inline const MachineState& GetNativeMachine() noexcept
{
	static MachineState state;
	static std::once_flag flag;
	std::call_once(flag, []()
	{
		using IsWow64Process2T =
			BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
		auto fn = reinterpret_cast<IsWow64Process2T>(GetProcAddress(
			GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));
		if (fn)
		{
			USHORT process = 0, native = 0;
			if (fn(GetCurrentProcess(), &process, &native))
				{ state.machine = native; return; }
			state.error = static_cast<int>(GetLastError());
			return;
		}
		BOOL isWow64 = FALSE;
		if (IsWow64Process(GetCurrentProcess(), &isWow64))
		{
			state.machine = isWow64 ? IMAGE_FILE_MACHINE_AMD64
				: IMAGE_FILE_MACHINE_I386;
			return;
		}
		state.error = static_cast<int>(GetLastError());
	});
	return state;
}

} // namespace detail

// Find a 64-bit module by name in the native loader's module list.

inline std::uint64_t module_handle(std::string_view name,
	std::error_code& ec) noexcept
{
	std::uint64_t moduleBase = 0;
	std::error_code lastReadEc;
	const bool found = detail::ForEachModule64(
		[&](const LDR_DATA_TABLE_ENTRY_64& entry)
	{
		const auto entryLen = entry.BaseDllName.Length / sizeof(wchar_t);
		if (entryLen != name.length()) return false;
		auto entryName = detail::AllocNothrow<wchar_t>(entryLen);
		if (!entryName)
		{
			ec = { ERROR_NOT_ENOUGH_MEMORY, std::system_category() };
			return true;
		}
		std::error_code readEc;
		detail::ReadMemory64(entry.BaseDllName.Buffer, entryName.get(),
			entryLen * sizeof(wchar_t), readEc);
		if (readEc) { lastReadEc = readEc; return false; }
		auto fold = [](wchar_t c) -> wchar_t
			{ return (c >= L'A' && c <= L'Z') ? c - L'A' + L'a' : c; };
		auto eq = [&](char a, wchar_t b)
			{ return fold(static_cast<unsigned char>(a)) == fold(b); };
		if (std::equal(name.begin(), name.end(), entryName.get(), eq))
		{
			moduleBase = entry.DllBase;
			return true;
		}
		return false;
	}, ec);
	if (ec) return 0;
	if (found) return moduleBase;
	ec = lastReadEc ? lastReadEc
		: std::error_code(ERROR_MOD_NOT_FOUND, std::system_category());
	return 0;
}

// Call a 64-bit function from 32-bit code.

template <class... Args>
inline std::uint64_t call_function(std::error_code& ec,
	std::uint64_t func, Args... args) noexcept
{
	const auto& machine = detail::GetNativeMachine();
	if (machine.error)
		{ ec = { machine.error, std::system_category() }; return 0; }
	switch (machine.machine)
	{
		case IMAGE_FILE_MACHINE_AMD64:
			return detail::CallFunction_x64(func, args...);
		case IMAGE_FILE_MACHINE_ARM64:
			return detail::CallFunction_arm64(ec, func, args...);
		default:
			ec = { ERROR_NOT_SUPPORTED, std::system_category() };
			return 0;
	}
}

namespace detail
{

// Cached LdrGetProcedureAddress resolution.

struct LdrState
{
	std::uint64_t address{};
	int error{};
};

inline const LdrState& CachedLdrProcedureAddress() noexcept
{
	static LdrState state;
	static std::once_flag flag;
	std::call_once(flag, []()
	{
		std::error_code ec;
		const auto ntdllBase = module_handle("ntdll.dll", ec);
		if (ec) { state.error = ec.value(); return; }
		state.address = FindLdrProcedureAddress(ntdllBase, ec);
		if (ec) state.error = ec.value();
	});
	return state;
}

} // namespace detail

// Resolve an export from a 64-bit module (equivalent to GetProcAddress).

inline std::uint64_t import(std::uint64_t hmodule,
	std::string_view procedureName, std::error_code& ec) noexcept
{
	const auto& ldr = detail::CachedLdrProcedureAddress();
	if (ldr.error) { ec = { ldr.error, std::system_category() }; return 0; }

	// LdrGetProcedureAddress takes an ANSI_STRING whose layout matches
	// UNICODE_STRING_64 (Length, MaximumLength, Buffer).
	UNICODE_STRING_64 ansiName{
		.Length = static_cast<std::uint16_t>(procedureName.size()),
		.MaximumLength = static_cast<std::uint16_t>(procedureName.size()),
		.Buffer = ptr_to_uint64(procedureName.data()),
	};

	std::uint64_t result = 0;
	auto status = call_function(ec, ldr.address, hmodule,
		ptr_to_uint64(&ansiName), std::uint64_t(0), ptr_to_uint64(&result));
	if (ec) return 0;
	if (status)
	{
		ec = { static_cast<int>(status), std::system_category() };
		return 0;
	}
	return result;
}

} // namespace winpriv::wow64
