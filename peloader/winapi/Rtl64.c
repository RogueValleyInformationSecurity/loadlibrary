// x64 Runtime Library stubs for SEH/exception handling
// These are required for MSVC CRT initialization on 64-bit
// Only compiled on x86_64

#ifdef __x86_64__

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

// 64-bit types
typedef uint64_t DWORD64;
typedef DWORD64 *PDWORD64;

// RUNTIME_FUNCTION structure for x64 exception handling
typedef struct _RUNTIME_FUNCTION {
    DWORD BeginAddress;
    DWORD EndAddress;
    DWORD UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;

// UNWIND_HISTORY_TABLE for RtlLookupFunctionEntry
typedef struct _UNWIND_HISTORY_TABLE {
    DWORD Count;
    BYTE  LocalHint;
    BYTE  GlobalHint;
    BYTE  Search;
    BYTE  Once;
    DWORD64 LowAddress;
    DWORD64 HighAddress;
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

// KNONVOLATILE_CONTEXT_POINTERS
typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    PVOID Dummy;
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

// RtlCaptureContext - captures the current CPU context
static VOID WINAPI RtlCaptureContext(PVOID ContextRecord)
{
    DebugLog("%p", ContextRecord);
    // Just zero it out - we do not need accurate context for fuzzing.
    if (ContextRecord) {
        memset(ContextRecord, 0, 1232);  // sizeof(CONTEXT) on x64
    }
}

// RtlLookupFunctionEntry - finds exception handling info for an address
static PRUNTIME_FUNCTION WINAPI RtlLookupFunctionEntry(
    DWORD64 ControlPc,
    PDWORD64 ImageBase,
    PUNWIND_HISTORY_TABLE HistoryTable)
{
    DebugLog("%#llx, %p, %p", (unsigned long long)ControlPc, ImageBase, HistoryTable);
    // Return NULL to indicate no function entry found.
    // This prevents exception unwinding.
    if (ImageBase) {
        *ImageBase = 0;
    }
    return NULL;
}

// RtlVirtualUnwind - unwinds one frame
static PVOID WINAPI RtlVirtualUnwind(
    DWORD HandlerType,
    DWORD64 ImageBase,
    DWORD64 ControlPc,
    PRUNTIME_FUNCTION FunctionEntry,
    PVOID ContextRecord,
    PVOID *HandlerData,
    PDWORD64 EstablisherFrame,
    PKNONVOLATILE_CONTEXT_POINTERS ContextPointers)
{
    DebugLog("%u, %#llx, %#llx, %p, %p, %p, %p, %p",
             HandlerType, (unsigned long long)ImageBase,
             (unsigned long long)ControlPc, FunctionEntry,
             ContextRecord, HandlerData, EstablisherFrame, ContextPointers);

    if (EstablisherFrame) {
        *EstablisherFrame = 0;
    }
    if (HandlerData) {
        *HandlerData = NULL;
    }

    return NULL;  // No language-specific handler
}

// RtlUnwindEx - x64 version of unwind (different from 32-bit RtlUnwind)
static VOID WINAPI RtlUnwindEx(
    PVOID TargetFrame,
    PVOID TargetIp,
    PVOID ExceptionRecord,
    PVOID ReturnValue,
    PVOID ContextRecord,
    PUNWIND_HISTORY_TABLE HistoryTable)
{
    DebugLog("%p, %p, %p, %p, %p, %p",
             TargetFrame, TargetIp, ExceptionRecord,
             ReturnValue, ContextRecord, HistoryTable);
    // For fuzzing, we just ignore unwind.
}

// RtlPcToFileHeader - finds the module containing an address
static PVOID WINAPI RtlPcToFileHeader(PVOID PcValue, PVOID *BaseOfImage)
{
    DebugLog("%p, %p", PcValue, BaseOfImage);
    // Return NULL to indicate address not in any known module.
    if (BaseOfImage) {
        *BaseOfImage = NULL;
    }
    return NULL;
}

// __C_specific_handler - x64 C exception handler
static LONG WINAPI C_specific_handler(
    PVOID ExceptionRecord,
    PVOID EstablisherFrame,
    PVOID ContextRecord,
    PVOID DispatcherContext)
{
    DebugLog("%p, %p, %p, %p",
             ExceptionRecord, EstablisherFrame,
             ContextRecord, DispatcherContext);
    return 1;  // ExceptionContinueSearch
}

// __CxxFrameHandler3 - C++ exception frame handler
static LONG WINAPI CxxFrameHandler3(
    PVOID ExceptionRecord,
    PVOID EstablisherFrame,
    PVOID ContextRecord,
    PVOID DispatcherContext)
{
    DebugLog("%p, %p, %p, %p",
             ExceptionRecord, EstablisherFrame,
             ContextRecord, DispatcherContext);
    return 1;  // ExceptionContinueSearch
}

// __GSHandlerCheck - GS cookie check handler
static VOID WINAPI GSHandlerCheck(PVOID EstablisherFrame, PVOID DispatcherContext)
{
    DebugLog("%p, %p", EstablisherFrame, DispatcherContext);
    // Just return - we do not actually check GS cookies.
}

// __security_check_cookie - GS cookie validation stub
static VOID WINAPI security_check_cookie(uintptr_t cookie)
{
    DebugLog("%#lx", (unsigned long)cookie);
    // Always pass - we do not actually validate.
}

// RtlAddFunctionTable - register function tables for dynamic code
static BOOLEAN WINAPI RtlAddFunctionTable(
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount,
    DWORD64 BaseAddress)
{
    DebugLog("%p, %u, %#llx", FunctionTable, EntryCount, (unsigned long long)BaseAddress);
    return TRUE;  // Pretend success
}

// RtlDeleteFunctionTable - unregister function tables
static BOOLEAN WINAPI RtlDeleteFunctionTable(PRUNTIME_FUNCTION FunctionTable)
{
    DebugLog("%p", FunctionTable);
    return TRUE;
}

DECLARE_CRT_EXPORT("RtlCaptureContext", RtlCaptureContext);
DECLARE_CRT_EXPORT("RtlLookupFunctionEntry", RtlLookupFunctionEntry);
DECLARE_CRT_EXPORT("RtlVirtualUnwind", RtlVirtualUnwind);
DECLARE_CRT_EXPORT("RtlUnwindEx", RtlUnwindEx);
DECLARE_CRT_EXPORT("RtlPcToFileHeader", RtlPcToFileHeader);
DECLARE_CRT_EXPORT("__C_specific_handler", C_specific_handler);
DECLARE_CRT_EXPORT("__CxxFrameHandler3", CxxFrameHandler3);
DECLARE_CRT_EXPORT("__GSHandlerCheck", GSHandlerCheck);
DECLARE_CRT_EXPORT("__security_check_cookie", security_check_cookie);
DECLARE_CRT_EXPORT("RtlAddFunctionTable", RtlAddFunctionTable);
DECLARE_CRT_EXPORT("RtlDeleteFunctionTable", RtlDeleteFunctionTable);

#endif // __x86_64__
