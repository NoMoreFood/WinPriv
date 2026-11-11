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
