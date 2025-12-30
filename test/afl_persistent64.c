//
// AFL++ Persistent Mode Fuzzing Harness (64-bit)
//
// This harness demonstrates high-performance fuzzing of 64-bit Windows DLLs
// on Linux using AFL++ persistent mode.
//
// Build: make afl_persistent64
// Fuzz:  afl-fuzz -i corpus -o findings -- ./afl_persistent64 [dll_path]
//
// For best performance, compile with afl-clang-fast:
//   make CC=afl-clang-fast afl_persistent64
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

  // Fallback input buffer for non-AFL mode (read from stdin)
  static unsigned char afl_input_buf[1024 * 1024];
  static size_t afl_input_len = 0;

  static void read_stdin_input(void) {
      afl_input_len = read(STDIN_FILENO, afl_input_buf, sizeof(afl_input_buf));
      if (afl_input_len == (size_t)-1) afl_input_len = 0;
  }
#else
  __AFL_FUZZ_INIT();
  #define read_stdin_input() do {} while (0)
#endif

// Function pointer types for target DLL exports
// WINCALL ensures correct calling convention (ms_abi on x64)
typedef int (WINCALL *parse_records_fn)(const uint8_t *data, int size);
typedef uint32_t (WINCALL *compute_checksum_fn)(const uint8_t *data, int size);

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
    const char *dll_path = "test/fuzz64.dll";

    // Allow overriding DLL path
    if (argc > 1) {
        dll_path = argv[1];
    }

    // =========================================================
    // PHASE 1: Expensive initialization (before fork server)
    // =========================================================
    if (init_target(dll_path) != 0) {
        return 1;
    }

    fprintf(stderr, "[*] DLL loaded: %s\n", dll_path);
    fprintf(stderr, "[*] Starting persistent mode fuzz loop\n");

    // =========================================================
    // PHASE 2: Deferred fork server initialization
    // =========================================================
    // AFL forks HERE, after expensive DLL loading is complete.

    __AFL_INIT();

    // For non-AFL mode, read from stdin once
    read_stdin_input();

    // Get pointer to AFL's shared memory input buffer
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    // =========================================================
    // PHASE 3: Persistent mode loop
    // =========================================================
    // Instead of forking for each input, we loop N times.
    // This gives ~10-100x speedup over fork-per-input.

    while (__AFL_LOOP(10000)) {
        size_t len = __AFL_FUZZ_TESTCASE_LEN;
        fuzz_one(buf, len);
    }

    return 0;
}
