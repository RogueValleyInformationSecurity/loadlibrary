//
// Example: Simple 32-bit DLL Fuzzing Harness
//
// This demonstrates the minimal code needed to load a 32-bit Windows DLL
// and fuzz it on Linux. Use with AFL, libFuzzer, or similar tools.
//
// Build: make harness32
// Run:   ./harness32 < input.bin
// Fuzz:  afl-fuzz -i corpus -o findings -- ./harness32
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

// Function pointer types for our target DLL exports
typedef int (*parse_records_fn)(const uint8_t *data, int size);
typedef uint32_t (*compute_checksum_fn)(const uint8_t *data, int size);

// Maximum input size for fuzzing (adjust as needed)
#define MAX_INPUT_SIZE (1024 * 1024)

int main(int argc, char *argv[])
{
    const char *dll_path = "test/fuzz32.dll";
    void *image = NULL;
    size_t size = 0;
    struct pe_image pe;

    // Allow overriding DLL path
    if (argc > 1) {
        dll_path = argv[1];
    }

    // Step 1: Load the DLL into memory
    if (!pe_load_library(dll_path, &image, &size)) {
        fprintf(stderr, "Failed to load %s\n", dll_path);
        return 1;
    }

    // Step 2: Set up pe_image structure and link
    memset(&pe, 0, sizeof(pe));
    strncpy(pe.name, dll_path, sizeof(pe.name) - 1);
    pe.image = image;
    pe.size = size;

    if (link_pe_images(&pe, 1) != 0) {
        fprintf(stderr, "Failed to link PE image\n");
        return 1;
    }

    // Step 3: Call DllMain (required for many DLLs)
    if (pe.entry) {
        pe.entry(pe.image, DLL_PROCESS_ATTACH, NULL);
    }

    // Step 4: Get function pointers to exports we want to fuzz
    parse_records_fn parse_records = get_export_address("parse_records");
    compute_checksum_fn compute_checksum = get_export_address("compute_checksum");

    if (!parse_records || !compute_checksum) {
        fprintf(stderr, "Failed to find required exports\n");
        return 1;
    }

    // Step 5: Read input (from stdin for AFL compatibility)
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

    // Step 6: Call the target function(s) with fuzz input
    // This is where crashes/bugs would be detected
    int records = parse_records(input, (int)input_size);
    uint32_t checksum = compute_checksum(input, (int)input_size);

    // Optional: Print results (useful for debugging, disable for fuzzing)
#ifndef FUZZING_BUILD
    printf("Records: %d, Checksum: 0x%08x\n", records, checksum);
#endif

    free(input);
    return 0;
}
