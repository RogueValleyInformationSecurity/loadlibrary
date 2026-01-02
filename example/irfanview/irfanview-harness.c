//
// AFL++ Persistent Mode Fuzzing Harness for IrfanView Plugins (64-bit)
//
// This harness fuzzes IrfanView format parsing DLLs using loadlibrary.
// It supports basic block coverage via LL_AFL_BB_COVERAGE=1 for in-DLL
// code coverage during fuzzing.
//
// Build: make
// Fuzz:  afl-fuzz -i seeds/{ext} -o output/{ext} -t 1000 -- ./harness {ext} @@
//
// Enable BB coverage:
//   export LL_AFL_BB_COVERAGE=1
//   export LL_PE_FIXED_BASE=1
//   afl-fuzz -i seeds/ani -o output/ani -t 1000 -- ./harness ani @@
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <wchar.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ctype.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

// AFL persistent mode macros
#ifndef __AFL_FUZZ_TESTCASE_LEN
  #define __AFL_FUZZ_INIT() do {} while (0)
  #define __AFL_INIT() do {} while (0)
  #define __AFL_LOOP(n) ({ \
    static int _afl_loop_count = (n); \
    (_afl_loop_count-- > 0); \
  })
  #define __AFL_FUZZ_TESTCASE_LEN (afl_input_len)
  #define __AFL_FUZZ_TESTCASE_BUF (afl_input_buf)

  static unsigned char afl_input_buf[4 * 1024 * 1024];
  static size_t afl_input_len = 0;

  static void read_stdin_input(void) {
      afl_input_len = read(STDIN_FILENO, afl_input_buf, sizeof(afl_input_buf));
      if (afl_input_len == (size_t)-1) afl_input_len = 0;
  }
#else
  __AFL_FUZZ_INIT();
  #define read_stdin_input() do {} while (0)
#endif

// IrfanView plugin function signatures (64-bit, ms_abi calling convention)
// HGLOBAL Read{FORMAT}_W(LPCWSTR filename, DWORD flags, int mode, void* struct_ptr, DWORD max_items, wchar_t* error)
typedef void* (WINCALL *ReadFunc)(const wchar_t *filename, uint32_t flags, int mode,
                                   void *struct_ptr, uint32_t max_items, wchar_t *error_buf);
typedef void (WINCALL *GetPlugInInfoFunc)(char *version, char *formats);

// Extension to DLL/function mapping
typedef struct {
    const char *extension;
    const char *dll_path;
    const char *read_func_name;
} ExtensionMapping;

// Mapping of extensions to their handler DLLs and functions
static const ExtensionMapping extension_map[] = {
    // Formats.dll handles many formats
    {"ani", "extracted/Formats.dll", "ReadANI_W"},
    {"blp", "extracted/Formats.dll", "ReadBLP_W"},
    {"cam", "extracted/Formats.dll", "ReadCasioCAM_W"},
    {"clp", "extracted/Formats.dll", "ReadCLP_W"},
    {"dds", "extracted/Formats.dll", "ReadDDS_W"},
    {"dcx", "extracted/Formats.dll", "ReadDCX_W"},
    {"fit", "extracted/Formats.dll", "ReadFITS_W"},
    {"fits", "extracted/Formats.dll", "ReadFITS_W"},
    {"g3", "extracted/Formats.dll", "ReadG3_W"},
    {"mpo", "extracted/Formats.dll", "ReadMPO_W"},
    {"pcx", "extracted/Formats.dll", "ReadPCX_W"},
    {"psp", "extracted/Formats.dll", "ReadPSP_W"},
    {"pvr", "extracted/Formats.dll", "ReadPVR_W"},
    {"qoi", "extracted/Formats.dll", "Read_QOI_W"},
    {"ras", "extracted/Formats.dll", "ReadRAS_W"},
    {"raw", "extracted/Formats.dll", "ReadRAW_W"},
    {"rle", "extracted/Formats.dll", "Read_Utah_RLE"},
    {"sfw", "extracted/Formats.dll", "ReadSFW_W"},
    {"sgi", "extracted/Formats.dll", "ReadSGI_W"},
    {"rgb", "extracted/Formats.dll", "ReadSGI_W"},
    {"sun", "extracted/Formats.dll", "ReadRAS_W"},
    {"ttf", "extracted/Formats.dll", "ReadTTF_W"},
    {"otf", "extracted/Formats.dll", "ReadTTF_W"},
    {"wbmp", "extracted/Formats.dll", "ReadWBMP_W"},
    {"xbm", "extracted/Formats.dll", "ReadXBM_W"},
    {"xpm", "extracted/Formats.dll", "ReadXPM_W"},

    // Specialized DLLs for specific formats
    {"webp", "extracted/WebP.dll", "ReadWebP_W"},
    {"jp2", "extracted/JPEG2000.dll", "ReadJPEG2000_W"},
    {"j2k", "extracted/JPEG2000.dll", "ReadJPEG2000_W"},
    {"jpc", "extracted/JPEG2000.dll", "ReadJPEG2000_W"},
    {"jpx", "extracted/JPEG2000.dll", "ReadJPEG2000_W"},
    {"mng", "extracted/Mng.dll", "ReadMNG_W"},
    {"jng", "extracted/Mng.dll", "ReadMNG_W"},
    {"b3d", "extracted/B3d.dll", "ReadB3D_W"},
    {"djvu", "extracted/DjVu.dll", "ReadDJVU_W"},
    {"djv", "extracted/DjVu.dll", "ReadDJVU_W"},
    {"dicom", "extracted/Dicom.dll", "ReadDICOM_W"},
    {"dcm", "extracted/Dicom.dll", "ReadDICOM_W"},
    {"ecw", "extracted/Ecw.dll", "ReadECW_W"},
    {"xcf", "extracted/Xcf.dll", "ReadXCF_W"},
    {"svg", "extracted/SVG.dll", "ReadSVG_W"},
    {"pdf", "extracted/PDF.dll", "ReadPDF_W"},
    {"flif", "extracted/Flif.dll", "ReadFLIF_W"},
    {"cr2", "extracted/CamRAW.dll", "ReadRAW_W"},
    {"crw", "extracted/CamRAW.dll", "ReadRAW_W"},
    {"avif", "extracted/Avif.dll", "ReadAVIF_W"},
    {"sff", "extracted/Sff.dll", "ReadSFF_W"},
    {"dwg", "extracted/CADImage.dll", "ReadDWG_W"},
    {"dxf", "extracted/CADImage.dll", "ReadDXF_W"},

    {NULL, NULL, NULL}  // Terminator
};

// Global state
static struct {
    struct pe_image pe;
    ReadFunc read_func;
    char current_ext[32];
    char current_dll[256];
    bool initialized;
} g_state = {0};

// Temporary file for fuzzing input
static char g_temp_path[256] = "/tmp/irfanview_fuzz_XXXXXX";
static int g_temp_fd = -1;

// Find the extension mapping
static const ExtensionMapping* find_mapping(const char *ext) {
    for (int i = 0; extension_map[i].extension != NULL; i++) {
        if (strcasecmp(extension_map[i].extension, ext) == 0) {
            return &extension_map[i];
        }
    }
    return NULL;
}

// Convert narrow string to wide string
static void narrow_to_wide(const char *src, wchar_t *dst, size_t dst_size) {
    size_t i;
    for (i = 0; i < dst_size - 1 && src[i]; i++) {
        dst[i] = (wchar_t)(unsigned char)src[i];
    }
    dst[i] = L'\0';
}

// Initialize the DLL for a specific extension
static int init_target(const char *ext) {
    const ExtensionMapping *mapping = find_mapping(ext);
    if (mapping == NULL) {
        fprintf(stderr, "Unknown extension: %s\n", ext);
        fprintf(stderr, "Supported extensions:\n");
        for (int i = 0; extension_map[i].extension != NULL; i++) {
            fprintf(stderr, "  %s\n", extension_map[i].extension);
        }
        return -1;
    }

    void *image = NULL;
    size_t size = 0;

    // Load the DLL
    if (!pe_load_library(mapping->dll_path, &image, &size)) {
        fprintf(stderr, "Failed to load %s\n", mapping->dll_path);
        return -1;
    }

    // Set up pe_image structure
    memset(&g_state.pe, 0, sizeof(g_state.pe));
    strncpy(g_state.pe.name, mapping->dll_path, sizeof(g_state.pe.name) - 1);
    g_state.pe.image = image;
    g_state.pe.size = size;

    // Link PE image (handles imports, relocations, etc.)
    if (link_pe_images(&g_state.pe, 1) != 0) {
        fprintf(stderr, "Failed to link PE image\n");
        return -1;
    }

    // Call DllMain
    if (g_state.pe.entry) {
        g_state.pe.entry(g_state.pe.image, DLL_PROCESS_ATTACH, NULL);
    }

    // Get the read function
    g_state.read_func = get_export_address(mapping->read_func_name);
    if (!g_state.read_func) {
        fprintf(stderr, "Failed to find export: %s\n", mapping->read_func_name);

        // Try alternative function name patterns
        char alt_name[64];
        snprintf(alt_name, sizeof(alt_name), "Read%s_W", mapping->extension);
        alt_name[4] = toupper(alt_name[4]);  // Capitalize first letter
        g_state.read_func = get_export_address(alt_name);

        if (!g_state.read_func) {
            fprintf(stderr, "Also tried: %s\n", alt_name);
            return -1;
        }
        fprintf(stderr, "Found alternative: %s\n", alt_name);
    }

    strncpy(g_state.current_ext, ext, sizeof(g_state.current_ext) - 1);
    strncpy(g_state.current_dll, mapping->dll_path, sizeof(g_state.current_dll) - 1);
    g_state.initialized = true;

    return 0;
}

// Create a temp file for fuzzing
static int create_temp_file(void) {
    strcpy(g_temp_path, "/tmp/irfanview_fuzz_XXXXXX");
    g_temp_fd = mkstemp(g_temp_path);
    if (g_temp_fd < 0) {
        perror("mkstemp");
        return -1;
    }
    return 0;
}

// Write data to temp file and fuzz
static void fuzz_one(const uint8_t *data, size_t size) {
    if (!g_state.initialized || size == 0 || g_temp_fd < 0) {
        return;
    }

    // Write data to temp file
    if (ftruncate(g_temp_fd, 0) < 0) return;
    if (lseek(g_temp_fd, 0, SEEK_SET) < 0) return;
    if (write(g_temp_fd, data, size) != (ssize_t)size) return;

    // Convert temp path to wide string
    wchar_t wide_path[256];
    narrow_to_wide(g_temp_path, wide_path, sizeof(wide_path) / sizeof(wchar_t));

    // Error buffer
    wchar_t error_buf[512];
    error_buf[0] = L'\0';

    // Call the read function
    // Parameters: filename, flags=0, mode=0, struct_ptr=NULL, max_items=1, error_buf
    void *result = g_state.read_func(wide_path, 0, 0, NULL, 1, error_buf);

    // Free the result if it's a valid HGLOBAL
    if (result != NULL && result != (void*)-1) {
        // Note: In a real scenario, we'd call GlobalFree, but we're fuzzing
        // and don't want to crash on invalid handles
    }
}

// Fuzz from a file path (for @@-style invocation)
static void fuzz_file(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) {
        return;
    }

    size_t size = st.st_size;
    if (size == 0 || size > 64 * 1024 * 1024) {  // 64MB limit
        return;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return;
    }

    uint8_t *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (data == MAP_FAILED) {
        return;
    }

    fuzz_one(data, size);
    munmap(data, size);
}

static void print_usage(const char *prog) {
    fprintf(stderr, "Usage: %s <extension> [input_file]\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Arguments:\n");
    fprintf(stderr, "  extension   - File extension to parse (e.g., 'ani', 'webp', 'jp2')\n");
    fprintf(stderr, "  input_file  - Path to input file (optional, reads stdin if not provided)\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Examples:\n");
    fprintf(stderr, "  %s ani input.ani           # Parse single file\n", prog);
    fprintf(stderr, "  echo data | %s pcx          # Parse from stdin\n", prog);
    fprintf(stderr, "  afl-fuzz -i seeds/ani -o out -- %s ani @@\n", prog);
    fprintf(stderr, "\n");
    fprintf(stderr, "Environment variables:\n");
    fprintf(stderr, "  LL_AFL_BB_COVERAGE=1  - Enable basic block coverage in DLL\n");
    fprintf(stderr, "  LL_PE_FIXED_BASE=1    - Use fixed base address for stable coverage\n");
    fprintf(stderr, "  AFL_MAP_SIZE=N        - Set map size at build time for AFL++\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Supported extensions:\n");
    for (int i = 0; extension_map[i].extension != NULL; i++) {
        fprintf(stderr, "  %-8s -> %s\n", extension_map[i].extension, extension_map[i].dll_path);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *extension = argv[1];
    const char *input_file = (argc > 2) ? argv[2] : NULL;

    // =========================================================
    // PHASE 1: Expensive initialization (before fork server)
    // =========================================================
    if (init_target(extension) != 0) {
        return 1;
    }

    if (create_temp_file() != 0) {
        return 1;
    }

    fprintf(stderr, "[*] DLL loaded: %s\n", g_state.current_dll);
    fprintf(stderr, "[*] Extension: %s\n", g_state.current_ext);
    fprintf(stderr, "[*] Temp file: %s\n", g_temp_path);
    fprintf(stderr, "[*] Starting persistent mode fuzz loop\n");

    // =========================================================
    // PHASE 2: Deferred fork server initialization
    // =========================================================
    __AFL_INIT();

    // Handle file input mode (afl-fuzz with @@)
    if (input_file != NULL) {
        // In file mode, just process the single file repeatedly
        while (__AFL_LOOP(1000)) {
            fuzz_file(input_file);
        }
    } else {
        // Stdin mode - read once for non-AFL, repeatedly for AFL
        read_stdin_input();
        unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

        while (__AFL_LOOP(1000)) {
            size_t len = __AFL_FUZZ_TESTCASE_LEN;
            fuzz_one(buf, len);
        }
    }

    // Cleanup
    if (g_temp_fd >= 0) {
        close(g_temp_fd);
        unlink(g_temp_path);
    }

    return 0;
}
