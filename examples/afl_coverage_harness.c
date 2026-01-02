//
// Example: AFL-style PE Callsite Coverage Harness
//
// This harness demonstrates loadlibrary's AFL-style coverage tracking for
// PE code that calls into the loader (imported Windows APIs). It prints a
// coverage digest when LL_AFL_COVERAGE_STATS is set.
//
// Build (32-bit): make afl_cov
// Build (64-bit): make afl_cov64
//
// Run: LL_AFL_COVERAGE=1 LL_AFL_COVERAGE_STATS=1 ./afl_cov64 < input.bin
//

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "winnt_types.h"
#include "afl_coverage.h"
#include "pe_linker.h"
#include "ntoskernel.h"

// Function pointer types for our target DLL exports.
typedef int (WINCALL *parse_records_fn)(const uint8_t *data, int size);
typedef uint32_t (WINCALL *compute_checksum_fn)(const uint8_t *data, int size);

#define MAX_INPUT_SIZE (1024 * 1024)

static void print_coverage_stats(void)
{
    const char *env = getenv("LL_AFL_COVERAGE_STATS");
    if (env == NULL || env[0] == '\0' || env[0] == '0') {
        return;
    }

    size_t count = afl_coverage_count();
    uint64_t hash = afl_coverage_hash();

    fprintf(stderr, "[coverage] edges=%zu hash=0x%016" PRIx64 "\n", count, hash);
}

int main(int argc, char *argv[])
{
#ifdef __x86_64__
    const char *dll_path = "test/fuzz64.dll";
#else
    const char *dll_path = "test/fuzz32.dll";
#endif
    void *image = NULL;
    size_t size = 0;
    struct pe_image pe;

    if (argc > 1) {
        dll_path = argv[1];
    }

    if (!pe_load_library(dll_path, &image, &size)) {
        fprintf(stderr, "Failed to load %s\n", dll_path);
        return 1;
    }

    memset(&pe, 0, sizeof(pe));
    strncpy(pe.name, dll_path, sizeof(pe.name) - 1);
    pe.image = image;
    pe.size = size;

    if (link_pe_images(&pe, 1) != 0) {
        fprintf(stderr, "Failed to link PE image\n");
        return 1;
    }

    if (pe.entry) {
        pe.entry(pe.image, DLL_PROCESS_ATTACH, NULL);
    }

    parse_records_fn parse_records = get_export_address("parse_records");
    compute_checksum_fn compute_checksum = get_export_address("compute_checksum");

    if (!parse_records || !compute_checksum) {
        fprintf(stderr, "Failed to find required exports\n");
        return 1;
    }

    uint8_t *input = malloc(MAX_INPUT_SIZE);
    if (!input) {
        fprintf(stderr, "Failed to allocate input buffer\n");
        return 1;
    }

    ssize_t input_size = read(STDIN_FILENO, input, MAX_INPUT_SIZE);
    if (input_size <= 0) {
        fprintf(stderr, "No input data\n");
        free(input);
        return 1;
    }

    afl_coverage_reset();

    int records = parse_records(input, (int)input_size);
    uint32_t checksum = compute_checksum(input, (int)input_size);

#ifndef FUZZING_BUILD
    printf("Records: %d, Checksum: 0x%08x\n", records, checksum);
#endif

    print_coverage_stats();

    free(input);
    return 0;
}
