#include <sys/mman.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "codealloc.h"

#define PAGE_READONLY 0x02
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE 0x10
#define PAGE_EXECUTE_READ 0x20
#define PAGE_EXECUTE_READWRITE 0x40

#define MEM_COMMIT 0x00001000
#define MEM_RESERVE 0x00002000

#define MEM_RELEASE 0x8000

STATIC PVOID WINAPI VirtualAlloc(PVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    if (flAllocationType & ~(MEM_COMMIT | MEM_RESERVE)) {
        DebugLog("flAllocationType %#x not implemnted", flAllocationType);
        return NULL;
    }

    // Ignore protection differences and return RWX memory for common cases.
    DWORD basic_protect = flProtect & 0xff;
    switch (basic_protect) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
            if (basic_protect == PAGE_EXECUTE_READWRITE) {
                DebugLog("JIT PAGE_EXECUTE_READWRITE Allocation Requested");
            }
            return code_malloc(dwSize);
        default:
            DebugLog("flProtect flags %#x not implemented", flProtect);
            return NULL;
    }
}

STATIC BOOL WINAPI VirtualProtect(PVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)
{
    if (flNewProtect != PAGE_READONLY &&
        flNewProtect != PAGE_READWRITE &&
        flNewProtect != PAGE_EXECUTE &&
        flNewProtect != PAGE_EXECUTE_READ &&
        flNewProtect != PAGE_EXECUTE_READWRITE) {
        DebugLog("unimplemented VirtualProtect() request, %#x", flNewProtect);
    }
    return TRUE;
}

STATIC BOOL WINAPI VirtualUnlock(PVOID lpAddress, SIZE_T dwSize)
{
    return TRUE;
}

STATIC BOOL WINAPI VirtualFree(PVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
    if (dwFreeType == MEM_RELEASE)
        code_free(lpAddress);
    return TRUE;
}

STATIC BOOL WINAPI GlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer)
{
    if (!lpBuffer || lpBuffer->dwLength < sizeof(MEMORYSTATUSEX)) {
        return FALSE;
    }

    lpBuffer->dwMemoryLoad = 40;
    lpBuffer->ullTotalPhys = 2147483648ULL;
    lpBuffer->ullAvailPhys = 2147483648ULL;
    lpBuffer->ullTotalPageFile = 2147483648ULL;
    lpBuffer->ullAvailPageFile = 2147483648ULL;
    lpBuffer->ullTotalVirtual = 2147483648ULL;
    lpBuffer->ullAvailVirtual = 2147483648ULL;
    lpBuffer->ullAvailExtendedVirtual = 0;
    return TRUE;
}

enum {
    FILE_MAPPING_MAGIC = 0x50414d46
};

struct file_mapping {
    uint32_t magic;
    FILE *file;
    size_t size;
};

static struct file_mapping *mapping_handles[64];
static size_t mapping_handle_count;

static struct file_mapping *lookup_mapping(HANDLE hFileMappingObject)
{
    for (size_t i = 0; i < mapping_handle_count; i++) {
        if (mapping_handles[i] == hFileMappingObject) {
            return mapping_handles[i];
        }
    }
    return NULL;
}

bool IsFileMappingHandle(HANDLE hFileMappingObject)
{
    struct file_mapping *mapping = lookup_mapping(hFileMappingObject);
    return mapping && mapping->magic == FILE_MAPPING_MAGIC;
}

void CloseFileMappingHandle(HANDLE hFileMappingObject)
{
    for (size_t i = 0; i < mapping_handle_count; i++) {
        if (mapping_handles[i] == hFileMappingObject) {
            struct file_mapping *mapping = mapping_handles[i];
            if (i + 1 < mapping_handle_count) {
                memmove(&mapping_handles[i],
                        &mapping_handles[i + 1],
                        (mapping_handle_count - i - 1) * sizeof(mapping_handles[0]));
            }
            mapping_handle_count--;
            free(mapping);
            return;
        }
    }
}

STATIC HANDLE WINAPI CreateFileMappingW(HANDLE hFile,
                                        PVOID lpAttributes,
                                        DWORD flProtect,
                                        DWORD dwMaximumSizeHigh,
                                        DWORD dwMaximumSizeLow,
                                        PWCHAR lpName)
{
    DebugLog("%p, %p, %#x, %#x, %#x, %p", hFile, lpAttributes, flProtect,
             dwMaximumSizeHigh, dwMaximumSizeLow, lpName);

    if (hFile != INVALID_HANDLE_VALUE && hFile && mapping_handle_count < ARRAY_SIZE(mapping_handles)) {
        FILE *file = (FILE *)hFile;
        long curpos = ftell(file);
        size_t size = 0;

        if (fseek(file, 0, SEEK_END) == 0) {
            long end = ftell(file);
            if (end > 0) {
                size = (size_t)end;
            }
        }

        if (curpos >= 0) {
            fseek(file, curpos, SEEK_SET);
        }

        struct file_mapping *mapping = calloc(1, sizeof(*mapping));
        if (mapping) {
            mapping->magic = FILE_MAPPING_MAGIC;
            mapping->file = file;
            mapping->size = size;
            mapping_handles[mapping_handle_count++] = mapping;
            return (HANDLE)mapping;
        }
    }

    return (HANDLE)NULL;
}

STATIC PVOID WINAPI MapViewOfFile(HANDLE hFileMappingObject,
                                  DWORD dwDesiredAccess,
                                  DWORD dwFileOffsetHigh,
                                  DWORD dwFileOffsetLow,
                                  SIZE_T dwNumberOfBytesToMap)
{
    struct file_mapping *mapping = lookup_mapping(hFileMappingObject);
    SIZE_T size = dwNumberOfBytesToMap;
    FILE *file = NULL;

    if (mapping && mapping->magic == FILE_MAPPING_MAGIC) {
        file = mapping->file;
        if (size == 0) {
            size = mapping->size;
        }
    }

    if (size == 0) {
        size = 4096;
    }
    PVOID buffer = malloc(size);
    long curpos = -1;
    size_t read_size = 0;

    DebugLog("%p, %#x, %#x, %#x, %zu", hFileMappingObject, dwDesiredAccess,
             dwFileOffsetHigh, dwFileOffsetLow, (size_t)dwNumberOfBytesToMap);

    if (buffer) {
        memset(buffer, 0, size);

        if (file && size > 0) {
            uint64_t offset = ((uint64_t)dwFileOffsetHigh << 32) | dwFileOffsetLow;
            curpos = ftell(file);
            if (fseek(file, (long)offset, SEEK_SET) == 0) {
                read_size = fread(buffer, 1, size, file);
            }
            if (curpos >= 0) {
                fseek(file, curpos, SEEK_SET);
            }
        }
    }

    return buffer;
}

STATIC BOOL WINAPI UnmapViewOfFile(PVOID lpBaseAddress)
{
    DebugLog("%p", lpBaseAddress);
    free(lpBaseAddress);
    return TRUE;
}

DECLARE_CRT_EXPORT("VirtualAlloc", VirtualAlloc);
DECLARE_CRT_EXPORT("VirtualProtect", VirtualProtect);
DECLARE_CRT_EXPORT("VirtualUnlock", VirtualUnlock);
DECLARE_CRT_EXPORT("VirtualFree", VirtualFree);
DECLARE_CRT_EXPORT("GlobalMemoryStatusEx", GlobalMemoryStatusEx);
DECLARE_CRT_EXPORT("CreateFileMappingW", CreateFileMappingW);
DECLARE_CRT_EXPORT("MapViewOfFile", MapViewOfFile);
DECLARE_CRT_EXPORT("UnmapViewOfFile", UnmapViewOfFile);
