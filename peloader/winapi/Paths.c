#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

static const uint16_t kTempPath[] = L"C:\\Windows\\Temp\\";
static const uint16_t kCurrentPath[] = L"C:\\dummy";
static const char kTempPathA[] = "C:\\Windows\\Temp\\";

DWORD WINAPI GetTempPathW(DWORD nBufferLength, PVOID lpBuffer)
{
    size_t needed = ARRAY_SIZE(kTempPath);

    DebugLog("%u, %p", nBufferLength, lpBuffer);

    if (!lpBuffer || nBufferLength == 0) {
        return (DWORD)needed;
    }

    if (nBufferLength < needed) {
        return (DWORD)needed;
    }

    memcpy(lpBuffer, kTempPath, sizeof(kTempPath));

    return (DWORD)(needed - 1);
}

DWORD WINAPI GetTempPath2W(DWORD nBufferLength, PVOID lpBuffer)
{
    DebugLog("%u, %p", nBufferLength, lpBuffer);
    return GetTempPathW(nBufferLength, lpBuffer);
}

DWORD WINAPI GetTempPathA(DWORD nBufferLength, PCHAR lpBuffer)
{
    DebugLog("%u, %p", nBufferLength, lpBuffer);

    if (!lpBuffer) {
        return (DWORD)strlen(kTempPathA) + 1;
    }

    if (nBufferLength < strlen(kTempPathA) + 1) {
        return (DWORD)strlen(kTempPathA) + 1;
    }

    memcpy(lpBuffer, kTempPathA, sizeof(kTempPathA));
    return (DWORD)strlen(kTempPathA);
}

UINT WINAPI GetTempFileNameW(PWCHAR lpPathName,
                             PWCHAR lpPrefixString,
                             UINT uUnique,
                             PWCHAR lpTempFileName)
{
    const WCHAR name[] = L"C:\\dummy\\faketemp\\tmp1.tmp";
    size_t needed = (sizeof(name) / sizeof(name[0])) - 1;

    DebugLog("%p, %p, %u, %p", lpPathName, lpPrefixString, uUnique, lpTempFileName);

    if (!lpTempFileName) {
        return 0;
    }

    memcpy(lpTempFileName, name, sizeof(name));
    return 1;
}

DWORD WINAPI GetCurrentDirectoryW(DWORD nBufferLength, PWCHAR lpBuffer)
{
    DebugLog("%u, %p", nBufferLength, lpBuffer);

    if (!lpBuffer) {
        return sizeof(kCurrentPath) / sizeof(kCurrentPath[0]);
    }

    if (nBufferLength < (sizeof(kCurrentPath) / sizeof(kCurrentPath[0]))) {
        return sizeof(kCurrentPath) / sizeof(kCurrentPath[0]);
    }

    memcpy(lpBuffer, kCurrentPath, sizeof(kCurrentPath));
    return (sizeof(kCurrentPath) / sizeof(kCurrentPath[0])) - 1;
}

DWORD WINAPI GetLogicalDrives(void)
{
    DebugLog("");

    return 1 << 2;
}

#define DRIVE_FIXED 3

UINT WINAPI GetDriveTypeW(PWCHAR lpRootPathName)
{
    char *path = CreateAnsiFromWide(lpRootPathName);
    DebugLog("%p [%s]", lpRootPathName, path);
    free(path);
    return DRIVE_FIXED;
}

DWORD WINAPI GetLongPathNameA(LPCSTR lpszShortPath,
                              LPSTR lpszLongPath,
                              DWORD cchBuffer)
{
    // For now we just return the 8.3 format path as the long path
    if (cchBuffer > strlen(lpszShortPath)) {
        memcpy(lpszLongPath, lpszShortPath, sizeof(lpszShortPath));
    }

    return strlen(lpszShortPath);
}

DWORD WINAPI GetLongPathNameW(LPCWSTR lpszShortPath,
                              LPWSTR lpszLongPath,
                              DWORD cchBuffer)
{
    // For now we just return the 8.3 format path as the long path
    if (cchBuffer > CountWideChars(lpszShortPath)) {
        memcpy(lpszLongPath, lpszShortPath, CountWideChars(lpszShortPath) * sizeof(WCHAR));
    }

    return CountWideChars(lpszShortPath);
}

DECLARE_CRT_EXPORT("GetTempPathW", GetTempPathW);
DECLARE_CRT_EXPORT("GetTempPath2W", GetTempPath2W);
DECLARE_CRT_EXPORT("GetTempPathA", GetTempPathA);
DECLARE_CRT_EXPORT("GetTempFileNameW", GetTempFileNameW);
DECLARE_CRT_EXPORT("GetCurrentDirectoryW", GetCurrentDirectoryW);
DECLARE_CRT_EXPORT("GetLogicalDrives", GetLogicalDrives);
DECLARE_CRT_EXPORT("GetDriveTypeW", GetDriveTypeW);
DECLARE_CRT_EXPORT("GetLongPathNameA", GetLongPathNameA);
DECLARE_CRT_EXPORT("GetLongPathNameW", GetLongPathNameW);
