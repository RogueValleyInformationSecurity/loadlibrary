//
// Simple test client for 64-bit PE loading
//
// This loads a simple 64-bit DLL and calls its exported functions
// to verify the PE64 loading code works correctly.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

// Function pointer types matching test64.dll exports
// Use WINCALL (ms_abi on x64) to match Windows DLL calling convention
typedef int (WINCALL *add_numbers_fn)(int a, int b);
typedef uint64_t (WINCALL *get_magic_fn)(void);
typedef int (WINCALL *parse_buffer_fn)(const char *buf, int len);

int main(int argc, char *argv[])
{
    const char *dll_path = "test/test64.dll";
    void *image = NULL;
    size_t size = 0;
    struct pe_image pe;

    printf("64-bit PE Loader Test\n");
    printf("=====================\n\n");

    if (argc > 1) {
        dll_path = argv[1];
    }

    printf("Loading: %s\n", dll_path);

    // Load the DLL into memory
    if (!pe_load_library(dll_path, &image, &size)) {
        fprintf(stderr, "Failed to load %s\n", dll_path);
        return 1;
    }

    printf("Loaded at %p, size %zu bytes\n", image, size);

    // Set up the pe_image structure
    memset(&pe, 0, sizeof(pe));
    strncpy(pe.name, dll_path, sizeof(pe.name) - 1);
    pe.image = image;
    pe.size = size;

    // Link the PE image
    if (link_pe_images(&pe, 1) != 0) {
        fprintf(stderr, "Failed to link PE image\n");
        return 1;
    }

    printf("PE image linked successfully\n");
    printf("  Architecture: %s\n", pe.is_64bit ? "64-bit (PE32+)" : "32-bit (PE32)");
    printf("  Entry point: %p\n", pe.entry);

    // Call DllMain if it exists (entry point)
    if (pe.entry) {
        printf("\nCalling DllMain...\n");
        BOOL result = pe.entry(pe.image, DLL_PROCESS_ATTACH, NULL);
        printf("  DllMain returned: %d\n", result);
    }

    // Get and call exported functions
    printf("\nTesting exports:\n");

    // Try our test DLL exports first
    add_numbers_fn add_numbers = get_export_address("add_numbers");
    if (add_numbers) {
        int result = add_numbers(40, 2);
        printf("  add_numbers(40, 2) = %d %s\n", result, result == 42 ? "[OK]" : "[FAIL]");
    }

    get_magic_fn get_magic = get_export_address("get_magic");
    if (get_magic) {
        uint64_t magic = get_magic();
        printf("  get_magic() = 0x%llx %s\n", (unsigned long long)magic,
               magic == 0xDEADBEEF64ULL ? "[OK]" : "[FAIL]");
    }

    parse_buffer_fn parse_buffer = get_export_address("parse_buffer");
    if (parse_buffer) {
        const char *test_data = "Hello, World!";
        int result = parse_buffer(test_data, strlen(test_data));
        // Sum of ASCII values of "Hello, World!" = 1129
        printf("  parse_buffer(\"%s\", %zu) = %d %s\n",
               test_data, strlen(test_data), result, result == 1129 ? "[OK]" : "[FAIL]");
    }

    // Try 7z.dll exports (just verify they are readable)
    void *create_object = get_export_address("CreateObject");
    if (create_object) {
        printf("  CreateObject: %p [OK - export found]\n", create_object);
    }
    void *get_method_prop = get_export_address("GetMethodProperty");
    if (get_method_prop) {
        printf("  GetMethodProperty: %p [OK - export found]\n", get_method_prop);
    }

    // If no exports were found at all
    if (!add_numbers && !get_magic && !parse_buffer && !create_object && !get_method_prop) {
        printf("  (no known exports found)\n");
    }

    printf("\nTest completed.\n");
    return 0;
}
