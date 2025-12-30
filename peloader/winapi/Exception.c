#ifndef __USE_GNU
# define __USE_GNU
#endif

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <ucontext.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

// x86_64 uses different registers and segment (GS instead of FS)
#ifdef __x86_64__
# define REG_BP REG_RBP
# define REG_IP REG_RIP
# define REG_SP REG_RSP
# define REG_AX REG_RAX
# define SEG_REG "gs"
#else
# define REG_BP REG_EBP
# define REG_IP REG_EIP
# define REG_SP REG_ESP
# define REG_AX REG_EAX
# define SEG_REG "fs"
#endif

#ifndef NDEBUG
// You can use `call DumpExceptionChain()` in gdb, like !exchain in windbg if
// you need to debug exception handling.
VOID DumpExceptionChain(VOID)
{
    PEXCEPTION_FRAME ExceptionList;
    DWORD Depth;

    // Fetch Exception List
    asm("mov %%" SEG_REG ":0, %[list]" : [list] "=r"(ExceptionList));

    DebugLog("ExceptionList %p, Dumping SEH Chain...", ExceptionList);

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);
    }
}
#endif

static WINAPI PVOID RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, PVOID Arguments)
{
    PEXCEPTION_FRAME ExceptionList;
    PEXCEPTION_FRAME Dispatch = NULL;
    DWORD Disposition;
    DWORD Depth;
    CONTEXT Context = {0};
    EXCEPTION_RECORD Record = {
        .ExceptionCode = dwExceptionCode,
        .ExceptionFlags = dwExceptionFlags,
        .ExceptionAddress =  &&finished,
        .NumberParameters = nNumberOfArguments,
    };

    // Setup Record
    memcpy(&Record.ExceptionInformation, Arguments, nNumberOfArguments * sizeof(ULONG));

    // No need to log C++ Exceptions, this is the common case.
    if (dwExceptionCode != 0xE06D7363) {
        LogMessage("%#x, %#x, %u, %p", dwExceptionCode, dwExceptionFlags, nNumberOfArguments, Arguments);
    }

    // Fetch Exception List
    asm("mov %%" SEG_REG ":0, %[list]" : [list] "=r"(ExceptionList));

    DebugLog("C++ Exception %#x! ExceptionList %p, Dumping SEH Chain...", dwExceptionCode, ExceptionList);

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DWORD Result;

        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);

        Result = ExceptionList->handler(&Record, ExceptionList, &Context, &Dispatch);

        DebugLog("%*s Handler Result: %u, Dispatch: %p", Depth, "", Result, Dispatch);

        if (Result == ExceptionContinueSearch) {
            continue;
        }

        // I've never seen any other handler return code with mpengine.
        __debugbreak();
    }

    // Unhandled Exception?
    DebugLog("%u Element SEH Chain Complete.", Depth);

finished:
    // I've never seen this reached, I'm not sure if it works.
    __debugbreak();
    return NULL;
}

#define EH_NONCONTINUABLE   0x01
#define EH_UNWINDING        0x02
#define EH_EXIT_UNWIND      0x04
#define EH_STACK_INVALID    0x08
#define EH_NESTED_CALL      0x10

static WINAPI void RtlUnwind(PEXCEPTION_FRAME TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord, PVOID ReturnValue)
{
    PEXCEPTION_FRAME ExceptionList;
    DWORD Depth;
    ucontext_t Context;

    DebugLog("%p, %p, %p, %p", TargetFrame, TargetIp, ExceptionRecord, ReturnValue);

    assert(ExceptionRecord);
    assert(TargetFrame);
    assert(TargetIp);

    ExceptionRecord->ExceptionFlags |= EH_UNWINDING;

    // Save current registers
    if (getcontext(&Context) != 0) {
        abort();
    }

    // This was suuuuuuper complicated to get right and make mpengine happy.
    Context.uc_mcontext.gregs[REG_BP] = ((uintptr_t *)(__builtin_frame_address(0)))[0];
    Context.uc_mcontext.gregs[REG_IP] = ((uintptr_t *)(__builtin_frame_address(0)))[1];
#ifdef __x86_64__
    // x86_64: +8 for return addr, +8*4 for 4 register args (rcx, rdx, r8, r9)
    Context.uc_mcontext.gregs[REG_SP] = ((uintptr_t)(__builtin_frame_address(0))) + 8 + 32;
#else
    // x86: +8 for return addr, +4*4 for 4 stack args
    Context.uc_mcontext.gregs[REG_SP] = ((uintptr_t)(__builtin_frame_address(0))) + 8 + 16;
#endif
    Context.uc_mcontext.gregs[REG_AX] = ((uintptr_t)(ReturnValue));

    // Fetch Exception List
    asm("mov %%" SEG_REG ":0, %[list]" : [list] "=r"(ExceptionList));

    for (Depth = 0; ExceptionList; ExceptionList = ExceptionList->prev) {
        DWORD Result;
        DWORD Dispatch = 0;

        DebugLog("%*s @%p { Prev: %p, Handler: %p }",
                 Depth++, "",
                 ExceptionList,
                 ExceptionList->prev,
                 ExceptionList->handler);

        // You don't call the final handler, you just install the new context.
        if (ExceptionList == TargetFrame) {
            DebugLog("TargetFrame %p == ExceptionList %p, Restore Context", ExceptionList, TargetFrame);

            setcontext(&Context);

            // Should not reach here.
            __debugbreak();
        }

        // Call all handlers before the TargetFrame.
        Result = ExceptionList->handler(ExceptionRecord, ExceptionList, NULL, (PVOID) &Dispatch);

        DebugLog("%*s Result: %u, Dispatch: %p", Depth, "", Result, Dispatch);

        if (Result != ExceptionContinueSearch) {
            // I've never seen any other handler return code with mpengine.
            __debugbreak();
        }

        // Remove handler.
        asm("mov %[list], %%" SEG_REG ":0" :: [list] "r"(ExceptionList->prev));
    }

    // Unhandled C++ Exception?
    __debugbreak();
}


DECLARE_CRT_EXPORT("RaiseException", RaiseException);
DECLARE_CRT_EXPORT("RtlUnwind", RtlUnwind);
