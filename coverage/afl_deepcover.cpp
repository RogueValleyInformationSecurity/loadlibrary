//
// AFL-integrated PIN tool for coverage-guided fuzzing
//
// This PIN tool provides edge coverage feedback to AFL by writing
// to AFL's shared memory bitmap. Use this with afl-fuzz for
// coverage-guided fuzzing of Windows DLLs via loadlibrary.
//
// Usage:
//   afl-fuzz -i corpus -o findings -- \
//     ./coverage/pin -t coverage/afl_deepcover.so -- ./harness target.dll
//
// Environment:
//   __AFL_SHM_ID is set automatically by afl-fuzz
//
// For standalone testing (without AFL):
//   ./coverage/pin -t coverage/afl_deepcover.so -- ./harness target.dll
//   (Uses a local bitmap and prints coverage stats at exit)
//

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <iostream>

#include "pin.H"

extern "C" {
    #include "afl_instrument.h"
}

// Blacklisted addresses (optional, from blacklist.h)
static uintptr_t blacklist[] = {
    #include "blacklist.h"
};

static int compare_block_address(const void *a, const void *b)
{
    uintptr_t x =  (uintptr_t  ) a;
    uintptr_t y = *(uintptr_t *) b;

    if (x > y) return +1;
    if (x < y) return -1;

    return 0;
}

// Image parameters set by InstrumentationCallback
ADDRINT TraceImageStart = 0;
ADDRINT TraceImageSize = 0;

VOID SetImageParameters(ADDRINT ImageStart, ADDRINT ImageSize)
{
    TraceImageStart = ImageStart;
    TraceImageSize = ImageSize;
    fprintf(stderr, "[AFL-PIN] Tracing image at %p, size %lu\n",
            (void*)ImageStart, (unsigned long)ImageSize);
}

// PIN calls this function every time a new trace is encountered
VOID trace(TRACE trace, VOID *ptr)
{
    if (!TraceImageStart)
        return;

    // Visit every basic block in the trace
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        ADDRINT addr = BBL_Address(bbl);

        // Only instrument blocks within the target image
        if (addr < TraceImageStart || addr > TraceImageStart + TraceImageSize)
            continue;

        // Check if this block is in our blacklist
        if (bsearch((const void *)(addr - TraceImageStart),
                    blacklist,
                    sizeof blacklist / sizeof blacklist[0],
                    sizeof blacklist[0],
                    compare_block_address)) {
            continue;
        }

        // Insert AFL edge tracking call
        // Use the relative address within the image for consistency
        BBL_InsertCall(bbl, IPOINT_ANYWHERE, AFUNPTR(afl_trace_edge),
            IARG_FAST_ANALYSIS_CALL,
            IARG_ADDRINT, addr - TraceImageStart,
            IARG_END);
    }
}

// Called when an image is loaded
VOID loadimage(IMG img, VOID *ptr)
{
    // Look for InstrumentationCallback to get image parameters
    RTN Callback = RTN_FindByName(img, "InstrumentationCallback");

    if (RTN_Valid(Callback)) {
        RTN_Open(Callback);
        RTN_InsertCall(Callback, IPOINT_BEFORE, (AFUNPTR) SetImageParameters,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                IARG_END);
        RTN_Close(Callback);
    }
}

int main(int argc, char **argv)
{
    // Initialize PIN
    if (PIN_Init(argc, argv)) {
        fprintf(stderr, "PIN initialization failed\n");
        return 1;
    }

    // Initialize AFL shared memory
    afl_setup_shm();

    // Initialize symbols for function name lookup
    PIN_InitSymbols();

    // Monitor image loads
    IMG_AddInstrumentFunction(loadimage, NULL);

    // Register trace instrumentation
    TRACE_AddInstrumentFunction(trace, NULL);

    // Register finalization callback
    PIN_AddFiniFunction(afl_fini_callback, NULL);

    fprintf(stderr, "[AFL-PIN] Starting instrumented execution\n");

    // Start the program (never returns)
    PIN_StartProgram();

    return 0;
}
