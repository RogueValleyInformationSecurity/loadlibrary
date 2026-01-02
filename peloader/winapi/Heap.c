#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <malloc.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define HEAP_ZERO_MEMORY 8

STATIC HANDLE WINAPI GetProcessHeap(void)
{
    return (HANDLE) 'HEAP';
}

STATIC HANDLE WINAPI HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)
{
    DebugLog("%#x, %u, %u", flOptions, dwInitialSize, dwMaximumSize);
    return (HANDLE) 'HEAP';
}

STATIC PVOID WINAPI HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)
{
    PVOID Buffer;

    // DebugLog("%p, %#x, %u", hHeap, dwFlags, dwBytes);

    if (dwFlags & HEAP_ZERO_MEMORY) {
        Buffer = calloc(dwBytes, 1);
    } else {
        Buffer = malloc(dwBytes);
    }

    return Buffer;
}

STATIC BOOL WINAPI HeapFree(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    // DebugLog("%p, %#x, %p", hHeap, dwFlags, lpMem);

    free(lpMem);

    return TRUE;
}

STATIC BOOL WINAPI RtlFreeHeap(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress)
{
    DebugLog("%p, %#x, %p", HeapHandle, Flags, BaseAddress);

    free(BaseAddress);

    return TRUE;
}

STATIC SIZE_T WINAPI HeapSize(HANDLE hHeap, DWORD dwFlags, PVOID lpMem)
{
    return malloc_usable_size(lpMem);
}

STATIC PVOID WINAPI HeapReAlloc(HANDLE hHeap, DWORD dwFlags, PVOID lpMem, SIZE_T dwBytes)
{
    return realloc(lpMem, dwBytes);
}

STATIC PVOID WINAPI LocalAlloc(UINT uFlags, SIZE_T uBytes)
{
    PVOID Buffer = malloc(uBytes);
    assert(uFlags == 0);

    DebugLog("%#x, %u => %p", uFlags, uBytes, Buffer);

    return Buffer;
}

STATIC PVOID WINAPI LocalFree(PVOID hMem)
{
    DebugLog("%p", hMem);
    free(hMem);
    return NULL;
}

STATIC PVOID WINAPI RtlCreateHeap(ULONG Flags,
                                  PVOID HeapBase,
                                  SIZE_T ReserveSize,
                                  SIZE_T CommitSize,
                                  PVOID Lock,
                                  PVOID Parameters)
{
    DebugLog("%#x, %p, %#x, %#x, %p, %p",
             Flags,
             HeapBase,
             ReserveSize,
             CommitSize,
             Lock,
             Parameters);

    return (HANDLE) 'HEAP';
}

STATIC PVOID WINAPI RtlAllocateHeap(PVOID HeapHandle,
                                    ULONG Flags,
                                    SIZE_T Size)
{
    DebugLog("%p, %#x, %u", HeapHandle, Flags, Size);

    return malloc(Size);
}

STATIC NTSTATUS WINAPI RtlSetHeapInformation(PVOID Heap,
                                             HEAP_INFORMATION_CLASS HeapInformationClass,
                                             PVOID HeapInformation,
                                             SIZE_T HeapInformationLength)
{
    DebugLog("%p, %d", Heap, HeapInformationLength);
    return 0;
}

// GlobalAlloc flags
#define GMEM_FIXED          0x0000
#define GMEM_MOVEABLE       0x0002
#define GMEM_ZEROINIT       0x0040
#define GPTR                (GMEM_FIXED | GMEM_ZEROINIT)
#define GHND                (GMEM_MOVEABLE | GMEM_ZEROINIT)

STATIC PVOID WINAPI GlobalAlloc(UINT uFlags, SIZE_T uBytes)
{
    PVOID Buffer;

    // We treat all memory as GMEM_FIXED - no distinction.
    if (uFlags & GMEM_ZEROINIT) {
        Buffer = calloc(1, uBytes);
    } else {
        Buffer = malloc(uBytes);
    }

    DebugLog("%#x, %zu => %p", uFlags, uBytes, Buffer);

    return Buffer;
}

STATIC PVOID WINAPI GlobalFree(PVOID hMem)
{
    DebugLog("%p", hMem);
    free(hMem);
    return NULL;
}

// GlobalLock - for GMEM_FIXED memory, just returns the handle itself.
STATIC PVOID WINAPI GlobalLock(HANDLE hMem)
{
    // For fixed memory (our implementation), the handle IS the pointer.
    DebugLog("%p => %p", hMem, hMem);
    return hMem;
}

// GlobalUnlock - for GMEM_FIXED memory, always succeeds.
STATIC BOOL WINAPI GlobalUnlock(HANDLE hMem)
{
    DebugLog("%p", hMem);
    return TRUE;
}

// GlobalHandle - for GMEM_FIXED memory, returns the pointer.
STATIC HANDLE WINAPI GlobalHandle(PVOID pMem)
{
    DebugLog("%p => %p", pMem, pMem);
    return (HANDLE)pMem;
}

// GlobalSize - returns size of allocated block.
STATIC SIZE_T WINAPI GlobalSize(HANDLE hMem)
{
    SIZE_T size = malloc_usable_size(hMem);
    DebugLog("%p => %zu", hMem, size);
    return size;
}

// GlobalReAlloc - reallocate global memory.
STATIC HANDLE WINAPI GlobalReAlloc(HANDLE hMem, SIZE_T dwBytes, UINT uFlags)
{
    PVOID result = realloc(hMem, dwBytes);
    DebugLog("%p, %zu, %#x => %p", hMem, dwBytes, uFlags, result);
    return (HANDLE)result;
}

DECLARE_CRT_EXPORT("HeapCreate", HeapCreate);
DECLARE_CRT_EXPORT("GetProcessHeap", GetProcessHeap);
DECLARE_CRT_EXPORT("HeapAlloc", HeapAlloc);
DECLARE_CRT_EXPORT("HeapFree", HeapFree);
DECLARE_CRT_EXPORT("RtlFreeHeap", RtlFreeHeap);
DECLARE_CRT_EXPORT("RtlSetHeapInformation", RtlSetHeapInformation);
DECLARE_CRT_EXPORT("HeapSize", HeapSize);
DECLARE_CRT_EXPORT("HeapReAlloc", HeapReAlloc);
DECLARE_CRT_EXPORT("LocalAlloc", LocalAlloc);
DECLARE_CRT_EXPORT("LocalFree", LocalFree);
DECLARE_CRT_EXPORT("RtlCreateHeap", RtlCreateHeap);
DECLARE_CRT_EXPORT("RtlAllocateHeap", RtlAllocateHeap);
DECLARE_CRT_EXPORT("GlobalAlloc", GlobalAlloc);
DECLARE_CRT_EXPORT("GlobalFree", GlobalFree);
DECLARE_CRT_EXPORT("GlobalLock", GlobalLock);
DECLARE_CRT_EXPORT("GlobalUnlock", GlobalUnlock);
DECLARE_CRT_EXPORT("GlobalHandle", GlobalHandle);
DECLARE_CRT_EXPORT("GlobalSize", GlobalSize);
DECLARE_CRT_EXPORT("GlobalReAlloc", GlobalReAlloc);
