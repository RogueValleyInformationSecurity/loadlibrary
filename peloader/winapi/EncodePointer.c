#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"


// XOR cookie for pointer encoding (must be same for encode/decode).
static uintptr_t PointerEncodeCookie = 0xDEADBEEFCAFEBABEULL;

STATIC PVOID WINAPI EncodePointer(PVOID Ptr)
{
    DebugLog("%p", Ptr);

    // XOR with cookie - works correctly for both 32-bit and 64-bit pointers.
    return (PVOID)((uintptr_t)Ptr ^ PointerEncodeCookie);
}

STATIC PVOID WINAPI DecodePointer(PVOID Ptr)
{
    DebugLog("%p", Ptr);

    // Same XOR to decode.
    return (PVOID)((uintptr_t)Ptr ^ PointerEncodeCookie);
}


DECLARE_CRT_EXPORT("EncodePointer", EncodePointer);
DECLARE_CRT_EXPORT("DecodePointer", DecodePointer);
