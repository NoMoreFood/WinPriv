#include <Windows.h>

static DWORD contextWrites;
static bool simulateContextFailure;

static BOOL WINAPI TestSetThreadContext(HANDLE thread, const CONTEXT* context)
{
    if (!simulateContextFailure) return SetThreadContext(thread, context);
    if (++contextWrites <= 3) return TRUE;
    SetLastError(contextWrites == 4 ? ERROR_ACCESS_DENIED : ERROR_INVALID_HANDLE);
    return FALSE;
}

#define SetThreadContext TestSetThreadContext
#include "../../../WinPrivLibrary/WinPrivDetoursFork.cpp"
#undef SetThreadContext

#if defined(_M_ARM64)
DWORD TestDetourArm64Branches()
{
    // Reserve enough space to exercise both direct and indirect relocated branches in each direction.
    const auto release = [](PVOID memory) { VirtualFree(memory, 0, MEM_RELEASE); };
    std::unique_ptr<void, decltype(release)> memory(
        VirtualAlloc(nullptr, 0x12000000, MEM_RESERVE, PAGE_NOACCESS), release);
    if (!memory) return GetLastError();
    auto source = static_cast<PBYTE>(memory.get()) + 0x9000000;
    if (!VirtualAlloc(source, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) return GetLastError();
    auto instructions = reinterpret_cast<DWORD*>(source);
    instructions[8] = 0x52800540; // mov w0, #42
    instructions[9] = 0xd65f03c0; // ret

    for (const LONG distance : { -0x8100000L, -0x200000L, -0x10000L, -0x4000L,
        0x4000L, 0x10000L, 0x200000L, 0x8100000L })
    {
        auto destination = source + distance;
        if (!VirtualAlloc(destination, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE)) return GetLastError();

        // Execute relocated B.AL, B.NV, BC.AL and BC.NV; a lost branch returns zero instead of 42.
        for (const DWORD instruction : { 0x5400010eUL, 0x5400010fUL, 0x5400011eUL, 0x5400011fUL })
        {
            instructions[0] = instruction;
            LONG extra = 0;
            if (DetourCopyInstruction(destination, source, extra) != source + 4 || extra < 0 || extra > 20)
                return ERROR_INVALID_DATA;
            auto continuation = reinterpret_cast<DWORD*>(destination + 4 + extra);
            continuation[0] = 0x52800000; // mov w0, #0
            continuation[1] = 0xd65f03c0; // ret
            if (!FlushInstructionCache(GetCurrentProcess(), source, 40) ||
                !FlushInstructionCache(GetCurrentProcess(), destination, 32)) return GetLastError();
            if (reinterpret_cast<DWORD(*)()>(destination)() != 42) return ERROR_INVALID_DATA;
        }

        // Branches that test x17 must use its incoming value, including when the far jump also needs x17.
        for (const DWORD instruction : { 0xb4000111UL, 0xb5000111UL, 0x34000111UL,
            0x35000111UL, 0x36000111UL, 0x37000111UL })
        {
            instructions[0] = instruction;
            *reinterpret_cast<DWORD*>(destination) = 0xaa0003f1; // mov x17, x0
            LONG extra = 0;
            if (DetourCopyInstruction(destination + 4, source, extra) != source + 4 || extra < 0 || extra > 20)
                return ERROR_INVALID_DATA;
            auto continuation = reinterpret_cast<DWORD*>(destination + 8 + extra);
            continuation[0] = 0xaa1103e0; // mov x0, x17
            continuation[1] = 0xd65f03c0; // ret
            if (!FlushInstructionCache(GetCurrentProcess(), source, 40) ||
                !FlushInstructionCache(GetCurrentProcess(), destination, 40)) return GetLastError();
            for (const DWORD value : { 0UL, 1UL })
            {
                const bool branch = (instruction & 0x01000000) != 0 ? value != 0 : value == 0;
                if (reinterpret_cast<DWORD(*)(DWORD)>(destination)(value) != (branch ? 42 : value))
                    return ERROR_INVALID_DATA;
            }
        }

        // Relocated integer loads must read mutable memory and leave unrelated registers intact.
        auto literal = reinterpret_cast<UINT64*>(source + 64);
        for (DWORD size = 0; size < 3; ++size)
        {
            for (const DWORD reg : { 0UL, 31UL })
            {
                instructions[0] = 0x18000200 | (size << 30) | reg;
                *literal = 1;
                *reinterpret_cast<DWORD*>(destination) = 0xaa0003f1; // mov x17, x0
                LONG extra = 0;
                if (DetourCopyInstruction(destination + 4, source, extra) != source + 4) return ERROR_INVALID_DATA;
                const auto delta = source + 64 - (destination + 4);
                if (reg == 31 && (delta < -(1 << 20) || delta >= (1 << 20)))
                {
                    if (extra != -1) return ERROR_INVALID_DATA;
                    continue;
                }
                if (extra < 0 || extra > 16) return ERROR_INVALID_DATA;
                auto continuation = reinterpret_cast<DWORD*>(destination + 8 + extra);
                continuation[0] = 0xf9000031; // str x17, [x1]
                continuation[1] = 0xd65f03c0; // ret
                if (!FlushInstructionCache(GetCurrentProcess(), destination, 32)) return GetLastError();
                for (const UINT64 value : { 0x1122334480000000ULL, 0xfedcba9889abcdefULL })
                {
                    *literal = value;
                    UINT64 scratch = 0;
                    const UINT64 expected = reg == 31 ? 42 : size == 0 ? static_cast<DWORD>(value) :
                        size == 1 ? value : static_cast<UINT64>(static_cast<LONG>(value));
                    if (reinterpret_cast<UINT64(*)(UINT64, UINT64*)>(destination)(42, &scratch) != expected ||
                        scratch != 42) return ERROR_INVALID_DATA;
                }
            }
        }
    }

    // The surrounding reservation forces far trampolines; a rejected zero-register load must abort the batch.
    const std::array<DWORD, 4> rejectedCode{ 0x5800021f, 0xd503201f, 0xd503201f, 0xd65f03c0 };
    const std::array<DWORD, 4> validCode{ 0x52800540, 0xd503201f, 0xd503201f, 0xd65f03c0 };
    std::ranges::copy(rejectedCode, instructions);
    std::ranges::copy(validCode, instructions + 32);
    std::ranges::copy(validCode, instructions + 64);
    DWORD protection = 0;
    if (!VirtualProtect(source, 4096, PAGE_EXECUTE_READ, &protection) ||
        !FlushInstructionCache(GetCurrentProcess(), source, 272)) return GetLastError();
    using Function = DWORD(*)();
    const auto original = reinterpret_cast<Function>(source + 128);
    const auto unsupported = reinterpret_cast<Function>(source);
    const auto replacement = reinterpret_cast<Function>(source + 256);
    auto target = original;
    auto rejected = unsupported;
    winpriv::detours::transaction transaction;
    transaction.attach(target, replacement);
    if (transaction.error() != NO_ERROR) return transaction.error();
    transaction.attach(rejected, replacement);
    const LONG error = transaction.commit();
    MEMORY_BASIC_INFORMATION memoryInfo{};
    if (error != ERROR_INVALID_BLOCK || target != original || rejected != unsupported || target() != 42 ||
        memcmp(source, rejectedCode.data(), sizeof(rejectedCode)) != 0 ||
        memcmp(source + 128, validCode.data(), sizeof(validCode)) != 0 ||
        VirtualQuery(source, &memoryInfo, sizeof(memoryInfo)) != sizeof(memoryInfo) ||
        memoryInfo.Protect != PAGE_EXECUTE_READ) return ERROR_INVALID_DATA;
    return NO_ERROR;
}
#endif

DWORD TestDetourContextRollback()
{
    // Simulate a failed context write followed by a failed restore on a peer that has not exited.
    std::unique_ptr<void, decltype(&CloseHandle)> live(CreateEventW(nullptr, TRUE, FALSE, nullptr), CloseHandle);
    if (!live) return GetLastError();

    struct Operation
    {
        PBYTE pbTarget;
        PDETOUR_TRAMPOLINE pTrampoline;
        bool retainTrampoline;
    };
    std::array<std::array<BYTE, 8>, 2> targets{};
    std::array<DETOUR_TRAMPOLINE, 2> trampolines{};
    std::array<Operation, 2> operations{};
    DetourSuspendedThreads threads(2);
    for (size_t index = 0; index < operations.size(); ++index)
    {
        auto& trampoline = trampolines[index];
        trampoline.cbRestore = 8;
        trampoline.alignCount = 1;
        trampoline.rAlign[0] = { 8, 8 };
        operations[index] = { targets[index].data(), &trampoline, false };
        threads[index].handle = live.get();
        detour_context_instruction_pointer(threads[index].originalContext) =
            reinterpret_cast<ULONG_PTR>(targets[index].data());
    }

    contextWrites = 0;
    simulateContextFailure = true;
    const LONG error = detour_relocate_suspended_threads(threads, std::span(operations));
    simulateContextFailure = false;
    return error == ERROR_ACCESS_DENIED && contextWrites == 5 && operations[0].retainTrampoline &&
        !operations[1].retainTrampoline ? NO_ERROR : ERROR_INVALID_DATA;
}
