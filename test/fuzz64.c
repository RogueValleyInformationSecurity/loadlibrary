// Example 64-bit DLL for fuzzing demonstration
// Compile with: x86_64-w64-mingw32-gcc -shared -nostdlib -e _DllMainCRTStartup -o fuzz64.dll fuzz64.c
#include <stdint.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

// Simple buffer parser - simulates parsing logic that could have bugs
// Returns: number of "records" found, or -1 on error
EXPORT int parse_records(const uint8_t *data, int size) {
    int count = 0;
    int i = 0;

    while (i < size) {
        // Each "record" starts with a length byte
        uint8_t record_len = data[i];

        // Check bounds
        if (i + 1 + record_len > size) {
            return -1;  // Truncated record
        }

        // Skip over the record data
        i += 1 + record_len;
        count++;
    }

    return count;
}

// Checksum function - another simple example
EXPORT uint32_t compute_checksum(const uint8_t *data, int size) {
    uint32_t sum = 0;
    for (int i = 0; i < size; i++) {
        sum = (sum << 1) | (sum >> 31);  // Rotate left
        sum ^= data[i];
    }
    return sum;
}

// DllMain entry point
EXPORT int __stdcall DllMain(void *hinstDLL, uint32_t fdwReason, void *lpvReserved) {
    (void)hinstDLL;
    (void)fdwReason;
    (void)lpvReserved;
    return 1;
}

// Entry point for -nostdlib
int __stdcall _DllMainCRTStartup(void *hinstDLL, uint32_t fdwReason, void *lpvReserved) {
    return DllMain(hinstDLL, fdwReason, lpvReserved);
}
