#ifndef __AFL_INSTRUMENT_H
#define __AFL_INSTRUMENT_H

#include <stdint.h>

// PIN type definitions (when included from PIN code)
#ifndef ADDRINT
typedef uintptr_t ADDRINT;
#endif
#ifndef UINT32
typedef uint32_t UINT32;
#endif
#ifndef INT32
typedef int32_t INT32;
#endif
#ifndef VOID
#define VOID void
#endif

// Fast analysis call convention
#if defined(TARGET_IA32) && defined(TARGET_LINUX) && !defined(PIN_FAST_ANALYSIS_CALL)
# define PIN_FAST_ANALYSIS_CALL __attribute__((regparm(3)))
#elif !defined(PIN_FAST_ANALYSIS_CALL)
# define PIN_FAST_ANALYSIS_CALL
#endif

// Initialize AFL shared memory connection
// Returns: 0 on success (attached to AFL), 1 if using local bitmap, -1 on error
int afl_setup_shm(void);

// Record an edge hit (basic block execution)
// address: Virtual address of the basic block
VOID PIN_FAST_ANALYSIS_CALL afl_trace_edge(ADDRINT address);

// Record a basic block hit with size info
// address: Virtual address of the basic block
// size: Number of instructions in the block
VOID PIN_FAST_ANALYSIS_CALL afl_trace_block(ADDRINT address, UINT32 size);

// Reset coverage state (call between test cases in persistent mode)
void afl_reset_coverage(void);

// Finalization callback - prints statistics
VOID afl_fini_callback(INT32 code, VOID *v);

// Get pointer to coverage bitmap
uint8_t *afl_get_area_ptr(void);

// Get current map size
uint32_t afl_get_map_size(void);

#endif // __AFL_INSTRUMENT_H
