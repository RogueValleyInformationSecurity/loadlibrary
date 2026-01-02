// Example 64-bit DLL for fuzzing demonstration
// Compile with: x86_64-w64-mingw32-gcc -shared -nostdlib -e _DllMainCRTStartup -o fuzz64.dll fuzz64.c
#include <stdint.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif

#if defined(__GNUC__)
#define NOINLINE __attribute__((noinline))
#define NAKED __attribute__((naked))
#else
#define NOINLINE
#define NAKED
#endif

// Keep small basic blocks around to verify instrumentation skips tiny blocks.
NOINLINE NAKED static void tiny_block(void) {
#if defined(__GNUC__)
    __asm__ volatile(
        "nop\n\t"
        "ret\n\t"
    );
#endif
}

// Force varied basic block sizes with inline asm padding.
NOINLINE static uint32_t varied_blocks(const uint8_t *data, int size) {
    volatile uint32_t v = 0xABCDEF01;

    if (size > 0) {
        if (data[0] == 0x10) {
            __asm__ volatile("nop\n\tnop\n\tnop\n\t");
            v += 1;
        } else if (data[0] == 0x20) {
            __asm__ volatile("nop\n\tnop\n\tnop\n\tnop\n\tnop\n\t");
            v += 2;
        } else {
            __asm__ volatile("nop\n\t");
            v += 3;
        }
    }

    if (size > 1) {
        if ((data[1] & 1) == 0) {
            __asm__ volatile("nop\n\tnop\n\t");
            v ^= data[1];
        } else {
            __asm__ volatile("nop\n\tnop\n\tnop\n\tnop\n\t");
            v += data[1];
        }
    }

    return v;
}

static uint32_t branchy_mix(const uint8_t *data, int size) {
    uint32_t v = 0x12345678;

    if (size > 0) {
        switch (data[0] & 3) {
        case 0:
            v ^= 0x11111111;
            break;
        case 1:
            v += 0x22222222;
            break;
        case 2:
            v ^= 0x33333333;
            break;
        default:
            v += 0x44444444;
            break;
        }
    }

    if (size > 1) {
        if ((uint8_t)(data[0] ^ data[1]) == 0x5A) {
            v ^= 0x0F0F0F0F;
        } else if (data[1] == 0x00) {
            v += 0x01010101;
        }
    }

    if (size > 2) {
        if (data[2] == 0xFF) {
            v ^= 0x00FF00FF;
        } else if (data[2] == 0x7F) {
            v += 0x13579BDF;
        }
    }

    return v;
}

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
    if (size > 0 && (data[0] == 0xA5 || data[0] == 0x5A)) {
        tiny_block();
    }
    sum ^= branchy_mix(data, size);
    sum ^= varied_blocks(data, size);
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
