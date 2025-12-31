//
// Test client for ordinal import resolution
//
// This loads a test DLL that imports OLEAUT32 functions by ordinal
// and verifies the ordinal resolution works correctly.
//
// Build 32-bit: make test_ordinal
// Build 64-bit: make test_ordinal64
// Run:   ./test_ordinal or ./test_ordinal64
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

// Determine architecture at compile time
#if defined(__x86_64__) || defined(_M_X64)
#define TEST_64BIT 1
typedef int (WINCALL *test_bstr_functions_fn)(void);
typedef uint64_t (WINCALL *get_ordinal_test_marker_fn)(void);
#define DLL_PATH "test/test_ordinal64.dll"
#define ARCH_NAME "64-bit"
#define EXPECTED_MARKER 0x4F5244494E414C00ULL
#define MARKER_FMT "0x%llx"
#define MARKER_CAST (unsigned long long)
#else
#define TEST_64BIT 0
typedef int (*test_bstr_functions_fn)(void);
typedef uint32_t (*get_ordinal_test_marker_fn)(void);
#define DLL_PATH "test/test_ordinal32.dll"
#define ARCH_NAME "32-bit"
#define EXPECTED_MARKER 0x4F524431U
#define MARKER_FMT "0x%x"
#define MARKER_CAST (unsigned int)
#endif

int main(int argc, char *argv[])
{
    const char *dll_path = DLL_PATH;
    void *image = NULL;
    size_t size = 0;
    struct pe_image pe;
    int result = 0;
    int tests_passed = 0;
    int tests_total = 0;

    (void)argc;
    (void)argv;

    printf("OLEAUT32 Ordinal Import Test (%s)\n", ARCH_NAME);
    printf("======================================\n");
    printf("This test verifies that the PE loader correctly resolves\n");
    printf("ordinal-based imports from OLEAUT32.dll.\n\n");

    printf("Loading: %s\n", dll_path);

    // Load the DLL into memory
    if (!pe_load_library(dll_path, &image, &size)) {
        fprintf(stderr, "FAIL: Could not load %s\n", dll_path);
        fprintf(stderr, "Make sure to compile the test DLLs first:\n");
#if TEST_64BIT
        fprintf(stderr, "  x86_64-w64-mingw32-gcc -shared -o test/test_ordinal64.dll test/test_ordinal64.c test/test_ordinal64.def\n");
#else
        fprintf(stderr, "  i686-w64-mingw32-gcc -shared -o test/test_ordinal32.dll test/test_ordinal32.c test/test_ordinal32.def\n");
#endif
        return 1;
    }

    printf("Loaded at %p, size %zu bytes\n", image, size);

    // Set up the pe_image structure
    memset(&pe, 0, sizeof(pe));
    strncpy(pe.name, dll_path, sizeof(pe.name) - 1);
    pe.image = image;
    pe.size = size;

    // Link the PE image - this is where ordinal resolution happens
    printf("Linking PE image (ordinal resolution happens here)...\n");
    if (link_pe_images(&pe, 1) != 0) {
        fprintf(stderr, "FAIL: Could not link PE image\n");
        fprintf(stderr, "This likely means ordinal imports were not resolved.\n");
        return 1;
    }

    printf("PE image linked successfully!\n");
    printf("  Architecture: %s\n", pe.is_64bit ? "64-bit (PE32+)" : "32-bit (PE32)");

    // Test 1: Verify architecture matches
    tests_total++;
#if TEST_64BIT
    if (pe.is_64bit) {
#else
    if (!pe.is_64bit) {
#endif
        printf("  [PASS] Correctly identified as %s\n", ARCH_NAME);
        tests_passed++;
    } else {
        printf("  [FAIL] Architecture mismatch\n");
    }

    // Test 2: Call DllMain
    if (pe.entry) {
        BOOL dll_result = pe.entry(pe.image, DLL_PROCESS_ATTACH, NULL);
        tests_total++;
        if (dll_result) {
            printf("  [PASS] DllMain returned success\n");
            tests_passed++;
        } else {
            printf("  [FAIL] DllMain returned failure\n");
        }
    }

    // Test 3: get_ordinal_test_marker
    get_ordinal_test_marker_fn get_marker = get_export_address("get_ordinal_test_marker");
    tests_total++;
    if (get_marker) {
#if TEST_64BIT
        uint64_t marker = get_marker();
#else
        uint32_t marker = get_marker();
#endif
        if (marker == EXPECTED_MARKER) {
            printf("  [PASS] get_ordinal_test_marker() = " MARKER_FMT " (correct)\n",
                   MARKER_CAST marker);
            tests_passed++;
        } else {
            printf("  [FAIL] get_ordinal_test_marker() = " MARKER_FMT " (expected " MARKER_FMT ")\n",
                   MARKER_CAST marker, MARKER_CAST EXPECTED_MARKER);
        }
    } else {
        printf("  [FAIL] Could not find get_ordinal_test_marker export\n");
    }

    // Test 4: test_bstr_functions (uses ordinal-imported OLEAUT32 functions)
    test_bstr_functions_fn test_bstr = get_export_address("test_bstr_functions");
    tests_total++;
    if (test_bstr) {
        printf("  Calling test_bstr_functions() (uses OLEAUT32 ordinal imports)...\n");
        result = test_bstr();
        if (result == 4) {
            printf("  [PASS] test_bstr_functions() = %d (BSTR operations worked!)\n", result);
            tests_passed++;
        } else if (result == -1) {
            printf("  [FAIL] test_bstr_functions() = %d (SysAllocString failed)\n", result);
        } else {
            printf("  [FAIL] test_bstr_functions() = %d (expected 4)\n", result);
        }
    } else {
        printf("  [FAIL] Could not find test_bstr_functions export\n");
    }

    // Summary
    printf("\n=== SUMMARY ===\n");
    printf("%s ordinal import tests: %d/%d passed\n", ARCH_NAME, tests_passed, tests_total);

    if (tests_passed == tests_total) {
        printf("\nSUCCESS: All ordinal import tests passed!\n");
        printf("The PE loader correctly resolved OLEAUT32 ordinal imports.\n");
        return 0;
    } else {
        printf("\nFAILURE: Some tests failed.\n");
        return 1;
    }
}
