//
// AFL Persistent Mode Fuzzing Harness
//
// This harness demonstrates how to use AFL++ persistent mode with loadlibrary
// for high-performance fuzzing of Windows DLLs on Linux.
//
// Build: make afl_persistent
// Fuzz:  afl-fuzz -i corpus -o findings -- ./afl_persistent [dll_path]
//
// For best performance, compile with afl-clang-fast:
//   make CC=afl-clang-fast afl_persistent
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

// AFL persistent mode macros
// These are defined by afl-clang-fast/afl-clang-lto
// For regular gcc, we provide fallback definitions for testing
#ifndef __AFL_FUZZ_TESTCASE_LEN
  // Fallback for non-AFL compilation (testing without fuzzer)
  #define __AFL_FUZZ_INIT() do {} while (0)
  #define __AFL_INIT() do {} while (0)
  #define __AFL_LOOP(n) ({ \
    static int _afl_loop_count = (n); \
    (_afl_loop_count-- > 0); \
  })
  #define __AFL_FUZZ_TESTCASE_LEN (afl_input_len)
  #define __AFL_FUZZ_TESTCASE_BUF (afl_input_buf)

  // Fallback input buffer for non-AFL mode
  static unsigned char afl_input_buf[1024 * 1024];
  static size_t afl_input_len = 0;
#else
  __AFL_FUZZ_INIT();
#endif

// Function pointer types for target DLL exports
typedef int (*parse_records_fn)(const uint8_t *data, int size);
typedef uint32_t (*compute_checksum_fn)(const uint8_t *data, int size);

// Global state that persists across loop iterations
static struct {
    struct pe_image pe;
    parse_records_fn parse_records;
    compute_checksum_fn compute_checksum;
    bool initialized;
} g_state = {0};

// Initialize the DLL - called once before the fuzz loop
static int init_target(const char *dll_path)
{
    void *image = NULL;
    size_t size = 0;

    // Load the DLL into memory
    if (!pe_load_library(dll_path, &image, &size)) {
        fprintf(stderr, "Failed to load %s\n", dll_path);
        return -1;
    }

    // Set up pe_image structure and link
    memset(&g_state.pe, 0, sizeof(g_state.pe));
    strncpy(g_state.pe.name, dll_path, sizeof(g_state.pe.name) - 1);
    g_state.pe.image = image;
    g_state.pe.size = size;

    if (link_pe_images(&g_state.pe, 1) != 0) {
        fprintf(stderr, "Failed to link PE image\n");
        return -1;
    }

    // Call DllMain (required for many DLLs)
    if (g_state.pe.entry) {
        g_state.pe.entry(g_state.pe.image, DLL_PROCESS_ATTACH, NULL);
    }

    // Get function pointers to exports we want to fuzz
    g_state.parse_records = get_export_address("parse_records");
    g_state.compute_checksum = get_export_address("compute_checksum");

    if (!g_state.parse_records || !g_state.compute_checksum) {
        fprintf(stderr, "Failed to find required exports\n");
        return -1;
    }

    g_state.initialized = true;
    return 0;
}

// Fuzz one input - called in the persistent loop
static void fuzz_one(const uint8_t *data, size_t size)
{
    if (!g_state.initialized || size == 0) {
        return;
    }

    // Call target functions with fuzz input
    // Crashes and hangs will be detected by AFL
    volatile int records = g_state.parse_records(data, (int)size);
    volatile uint32_t checksum = g_state.compute_checksum(data, (int)size);

    // Prevent compiler from optimizing away the calls
    (void)records;
    (void)checksum;
}

int main(int argc, char *argv[])
{
    const char *dll_path = "test/fuzz32.dll";

    // Allow overriding DLL path
    if (argc > 1) {
        dll_path = argv[1];
    }

    // =========================================================
    // PHASE 1: Expensive initialization (before fork server)
    // =========================================================
    // Load and link the DLL. This is slow, so we do it BEFORE
    // calling __AFL_INIT() to avoid repeating it for each fork.

    if (init_target(dll_path) != 0) {
        return 1;
    }

    fprintf(stderr, "[*] DLL loaded, starting fuzz loop\n");

    // =========================================================
    // PHASE 2: Deferred fork server initialization
    // =========================================================
    // AFL forks HERE, after expensive DLL loading is complete.
    // Each forked child inherits the already-loaded DLL.

    __AFL_INIT();

    // Get pointer to AFL's shared memory input buffer
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // =========================================================
    // PHASE 3: Persistent mode loop
    // =========================================================
    // Instead of forking for each input, we loop N times.
    // This gives ~10-100x speedup over fork-per-input.
    //
    // The loop count (10000) is a tradeoff:
    // - Higher = faster, but state may accumulate/corrupt
    // - Lower = slower, but more reliable state reset
    // - Adjust based on target DLL behavior

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;

        // Fuzz with this input
        fuzz_one(buf, len);

        // NOTE: If your target DLL accumulates state that causes
        // issues, you may need to add state reset logic here.
        // Common approaches:
        // - Call a "reset" function if the DLL provides one
        // - Track and free allocations made during fuzz_one()
        // - Reduce loop count if state corruption is unavoidable
    }

    return 0;
}
