// Test DLL that imports OLEAUT32 functions by ordinal
// This tests the ordinal import resolution feature
//
// Compile with:
//   x86_64-w64-mingw32-gcc -shared -o test_ordinal64.dll test_ordinal64.c test_ordinal64.def
//
#include <stdint.h>

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#define IMPORT __declspec(dllimport)
#else
#define EXPORT
#define IMPORT
#endif

// Windows types
typedef uint16_t WCHAR;
typedef WCHAR *BSTR;
typedef uint32_t UINT;
typedef int32_t HRESULT;

// Declare OLEAUT32 functions - these will be imported by ordinal via .def file
IMPORT BSTR __stdcall SysAllocString(const WCHAR *sz);
IMPORT void __stdcall SysFreeString(BSTR bstr);
IMPORT UINT __stdcall SysStringLen(BSTR bstr);

// Test function that uses OLEAUT32 functions
EXPORT int __stdcall test_bstr_functions(void) {
    // Create a simple BSTR with "Test" (4 chars + null)
    WCHAR test_str[] = { 'T', 'e', 's', 't', 0 };

    BSTR bstr = SysAllocString(test_str);
    if (!bstr) {
        return -1;  // Allocation failed
    }

    UINT len = SysStringLen(bstr);

    SysFreeString(bstr);

    // Return the length - should be 4
    return (int)len;
}

// Export a marker to verify the DLL loaded
EXPORT uint64_t __stdcall get_ordinal_test_marker(void) {
    return 0x4F5244494E414C00ULL;  // "ORDINAL\0" as hex
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
