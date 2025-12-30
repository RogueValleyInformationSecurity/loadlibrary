//
// AFL-compatible instrumentation for Intel PIN
//
// This module provides edge coverage tracking that writes directly to
// AFL's shared memory bitmap, enabling coverage-guided fuzzing of
// Windows DLLs loaded via loadlibrary.
//
// Environment variables:
//   __AFL_SHM_ID - AFL's shared memory ID (set by afl-fuzz)
//   AFL_MAP_SIZE - Optional custom map size (default 65536)
//
// Usage:
//   afl-fuzz -i corpus -o findings -- \
//     ./coverage/pin -t coverage/afl_deepcover.so -- ./harness target.dll
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/types.h>

#include "afl_instrument.h"

// AFL shared memory configuration
#define AFL_DEFAULT_MAP_SIZE 65536
#define AFL_SHM_ENV_VAR      "__AFL_SHM_ID"
#define AFL_MAP_SIZE_ENV_VAR "AFL_MAP_SIZE"

// Shared memory bitmap (AFL's coverage map)
static uint8_t *afl_area_ptr = NULL;
static uint32_t afl_map_size = AFL_DEFAULT_MAP_SIZE;

// Previous location for edge coverage calculation
static __thread uint32_t afl_prev_loc = 0;

// Fallback local bitmap when not running under AFL
static uint8_t afl_local_map[AFL_DEFAULT_MAP_SIZE];

// Statistics (for debugging/reporting)
static uint64_t total_edges = 0;
static uint64_t unique_edges = 0;

//
// Initialize AFL shared memory connection
// Called once at startup before any instrumentation
//
int afl_setup_shm(void)
{
    char *shm_id_str = getenv(AFL_SHM_ENV_VAR);
    char *map_size_str = getenv(AFL_MAP_SIZE_ENV_VAR);

    // Check for custom map size
    if (map_size_str) {
        afl_map_size = atoi(map_size_str);
        if (afl_map_size < 1024) {
            afl_map_size = AFL_DEFAULT_MAP_SIZE;
        }
    }

    if (shm_id_str) {
        // Running under AFL - attach to shared memory
        int shm_id = atoi(shm_id_str);
        afl_area_ptr = (uint8_t *)shmat(shm_id, NULL, 0);

        if (afl_area_ptr == (void *)-1) {
            fprintf(stderr, "[AFL-PIN] Failed to attach to shared memory %d\n", shm_id);
            afl_area_ptr = afl_local_map;
            return -1;
        }

        fprintf(stderr, "[AFL-PIN] Attached to AFL shared memory (id=%d, size=%u)\n",
                shm_id, afl_map_size);
        return 0;
    } else {
        // Not running under AFL - use local bitmap
        fprintf(stderr, "[AFL-PIN] No AFL shared memory detected, using local bitmap\n");
        fprintf(stderr, "[AFL-PIN] Set %s to enable AFL integration\n", AFL_SHM_ENV_VAR);
        afl_area_ptr = afl_local_map;
        memset(afl_local_map, 0, sizeof(afl_local_map));
        return 1;
    }
}

//
// Record an edge in AFL's coverage bitmap
// Called for each basic block execution
//
// The edge ID is computed as: (prev_loc >> 1) XOR cur_loc
// This gives us directional edge coverage (A->B != B->A)
//
VOID PIN_FAST_ANALYSIS_CALL afl_trace_edge(ADDRINT address)
{
    // Compute edge ID using AFL's algorithm
    uint32_t cur_loc = (uint32_t)(address & 0xFFFFFFFF);

    // Use a hash to better distribute addresses into the map
    // This helps when addresses are clustered
    cur_loc = cur_loc ^ (cur_loc >> 16);
    cur_loc = cur_loc & (afl_map_size - 1);

    uint32_t edge_id = cur_loc ^ afl_prev_loc;

    // Record the edge hit
    if (afl_area_ptr[edge_id] < 255) {
        if (afl_area_ptr[edge_id] == 0) {
            unique_edges++;
        }
        afl_area_ptr[edge_id]++;
    }

    // Update previous location for next edge
    afl_prev_loc = cur_loc >> 1;

    total_edges++;
}

//
// Alternative: Record basic block with size info
// Provides same coverage as afl_trace_edge but includes block size
//
VOID PIN_FAST_ANALYSIS_CALL afl_trace_block(ADDRINT address, UINT32 size)
{
    (void)size;  // Size not used for AFL coverage, but available if needed
    afl_trace_edge(address);
}

//
// Reset coverage state between test cases
// Call this at the start of each new input in persistent mode
//
void afl_reset_coverage(void)
{
    afl_prev_loc = 0;
    // Note: We don't clear the bitmap - AFL handles that
}

//
// Print coverage statistics (for debugging)
// Called at program exit
//
VOID afl_fini_callback(INT32 code, VOID *v)
{
    (void)code;
    (void)v;

    // Calculate bitmap density
    uint32_t filled = 0;
    for (uint32_t i = 0; i < afl_map_size; i++) {
        if (afl_area_ptr[i]) filled++;
    }

    fprintf(stderr, "\n----- AFL COVERAGE ANALYSIS -----\n");
    fprintf(stderr, "    Total edges executed: %lu\n", (unsigned long)total_edges);
    fprintf(stderr, "    Unique edges (approx): %lu\n", (unsigned long)unique_edges);
    fprintf(stderr, "    Bitmap density: %u/%u (%.2f%%)\n",
            filled, afl_map_size, 100.0 * filled / afl_map_size);

    // Detach from shared memory if attached
    if (afl_area_ptr && afl_area_ptr != afl_local_map) {
        shmdt(afl_area_ptr);
    }
}

//
// Get pointer to coverage bitmap (for testing/debugging)
//
uint8_t *afl_get_area_ptr(void)
{
    return afl_area_ptr;
}

//
// Get current map size
//
uint32_t afl_get_map_size(void)
{
    return afl_map_size;
}
