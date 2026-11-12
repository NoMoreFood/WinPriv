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

    for (const LONG distance : { -0x8100000L, -0x200000L, -0x10000L, 0x10000L, 0x200000L, 0x8100000L })
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
    }
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
