#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>
#include <wchar.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

typedef struct _WIN32_FILE_ATTRIBUTE_DATA {
  DWORD    dwFileAttributes;
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;
  DWORD    nFileSizeLow;
} WIN32_FILE_ATTRIBUTE_DATA, *LPWIN32_FILE_ATTRIBUTE_DATA;

typedef struct _IO_STATUS_BLOCK {
  NTSTATUS Status;
  ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_BASIC_INFORMATION {
  LARGE_INTEGER CreationTime;
  LARGE_INTEGER LastAccessTime;
  LARGE_INTEGER LastWriteTime;
  LARGE_INTEGER ChangeTime;
  ULONG FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _FILE_STANDARD_INFORMATION {
  LARGE_INTEGER AllocationSize;
  LARGE_INTEGER EndOfFile;
  ULONG NumberOfLinks;
  BOOLEAN DeletePending;
  BOOLEAN Directory;
  BYTE Reserved[2];
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;
extern void WINAPI SetLastError(DWORD dwErrCode);
extern bool IsFileMappingHandle(HANDLE hFileMappingObject);
extern void CloseFileMappingHandle(HANDLE hFileMappingObject);

#define ERROR_FILE_NOT_FOUND 2
#define ERROR_INVALID_HANDLE 6
#define ERROR_INVALID_PARAMETER 87
#define ERROR_NO_MORE_FILES 18
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_MORE_DATA 234

#define FILE_ATTRIBUTE_NORMAL 128
#define FILE_ATTRIBUTE_DIRECTORY 16
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000

#define FILE_BASIC_INFORMATION_CLASS 4
#define FILE_STANDARD_INFORMATION_CLASS 5

#define INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFFu)
static const uint64_t k_windows_epoch_offset = 11644473600ULL;

static void FillFileTime(FILETIME *ft, time_t t)
{
    if (!ft) {
        return;
    }

    uint64_t filetime = ((uint64_t)t + k_windows_epoch_offset) * 10000000ULL;
    ft->dwLowDateTime = (DWORD)(filetime & 0xffffffffu);
    ft->dwHighDateTime = (DWORD)(filetime >> 32);
}

static unsigned int g_failed_open_logs;
static FILE *g_open_files[128];
static size_t g_open_file_count;

static void mkdir_p(const char *path);

static void RememberOpenFile(FILE *file)
{
    if (!file) {
        return;
    }

    for (size_t i = 0; i < g_open_file_count; ++i) {
        if (g_open_files[i] == file) {
            return;
        }
    }

    if (g_open_file_count < (sizeof(g_open_files) / sizeof(g_open_files[0]))) {
        g_open_files[g_open_file_count++] = file;
    }
}

static bool ForgetOpenFile(FILE *file)
{
    if (!file) {
        return false;
    }

    for (size_t i = 0; i < g_open_file_count; ++i) {
        if (g_open_files[i] == file) {
            g_open_files[i] = g_open_files[g_open_file_count - 1];
            g_open_files[g_open_file_count - 1] = NULL;
            g_open_file_count--;
            return true;
        }
    }

    return false;
}

static DWORD GetFileAttributesInternal(const char *input)
{
    DWORD Result = FILE_ATTRIBUTE_NORMAL;
    char *filename = NULL;

    if (!input) {
        return INVALID_FILE_ATTRIBUTES;
    }

    filename = strdup(input);
    if (!filename) {
        return INVALID_FILE_ATTRIBUTES;
    }

    if (strstr(filename, "RebootActions") || strstr(filename, "RtSigs") ||
        strstr(filename, "mpcache-")) {
        Result = INVALID_FILE_ATTRIBUTES;
        goto finish;
    }

    for (char *t = filename; *t; t++) {
        if (*t == '\\') {
            *t = '/';
        }
    }

    for (char *t = filename; *t; t++) {
        *t = tolower(*t);
    }

    if (strncmp(filename, "c:/system32/", strlen("c:/system32/")) == 0 ||
        strncmp(filename, "c:/windows/", strlen("c:/windows/")) == 0) {
        Result = FILE_ATTRIBUTE_NORMAL;
        goto finish;
    }

    {
        struct stat st;
        if (stat(filename, &st) != 0) {
            Result = INVALID_FILE_ATTRIBUTES;
            goto finish;
        }

        if (S_ISDIR(st.st_mode)) {
            Result = FILE_ATTRIBUTE_DIRECTORY;
        }
    }

finish:
    free(filename);
    return Result;
}

static DWORD WINAPI GetFileAttributesW(PVOID lpFileName)
{
    char *filename = CreateAnsiFromWide(lpFileName);
    DebugLog("%p [%s]", lpFileName, filename);

    DWORD Result = GetFileAttributesInternal(filename);
    free(filename);
    return Result;
}

static DWORD WINAPI GetFileAttributesA(PCHAR lpFileName)
{
    DebugLog("%s", lpFileName);
    return GetFileAttributesInternal(lpFileName);
}

static DWORD WINAPI GetFileAttributesExW(PWCHAR lpFileName, DWORD fInfoLevelId, LPWIN32_FILE_ATTRIBUTE_DATA lpFileInformation)
{
    char *filename = CreateAnsiFromWide(lpFileName);
    DebugLog("%p [%s], %u, %p", lpFileName, filename, fInfoLevelId, lpFileInformation);

    assert(fInfoLevelId == 0);
    if (!lpFileInformation || !filename) {
        free(filename);
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    DWORD attrs = GetFileAttributesInternal(filename);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        free(filename);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    struct stat st;
    if (stat(filename, &st) != 0) {
        free(filename);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return FALSE;
    }

    memset(lpFileInformation, 0, sizeof(*lpFileInformation));
    lpFileInformation->dwFileAttributes = attrs;
    FillFileTime(&lpFileInformation->ftCreationTime, st.st_ctime);
    FillFileTime(&lpFileInformation->ftLastAccessTime, st.st_atime);
    FillFileTime(&lpFileInformation->ftLastWriteTime, st.st_mtime);
    lpFileInformation->nFileSizeHigh = (DWORD)((uint64_t)st.st_size >> 32);
    lpFileInformation->nFileSizeLow = (DWORD)((uint64_t)st.st_size & 0xffffffffu);

    free(filename);
    SetLastError(0);
    return TRUE;
}

enum {
    CREATE_NEW          = 1,
    CREATE_ALWAYS       = 2,
    OPEN_EXISTING       = 3,
    OPEN_ALWAYS         = 4,
    TRUNCATE_EXISTING   = 5
};

static HANDLE WINAPI CreateFileA(PCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    FILE *FileHandle;

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Translate path seperator.
    while (strchr(lpFileName, '\\'))
        *strchr(lpFileName, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = lpFileName; *t; t++)
        *t = tolower(*t);

    if (strstr(lpFileName, "mpcache-")) {
        LogMessage("CreateFileA mpcache path seen: %s", lpFileName);
        SetLastError(ERROR_FILE_NOT_FOUND);
        return INVALID_HANDLE_VALUE;
    }

    if (strncmp(lpFileName, "//./", 4) == 0 || strncmp(lpFileName, "//?/", 4) == 0) {
        FileHandle = fopen("/dev/null", "r+");
        if (FileHandle) {
            SetLastError(0);
            return FileHandle;
        }
    }

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = fopen(lpFileName, "r");
            if (!FileHandle && (dwFlagsAndAttributes & (FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY))) {
                struct stat st;
                if (stat(lpFileName, &st) != 0) {
                    mkdir_p(lpFileName);
                }
                if (stat(lpFileName, &st) == 0 && S_ISDIR(st.st_mode)) {
                    FileHandle = fopen("/dev/null", "r");
                }
            }
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen("/dev/null", "w");
            break;
        // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(lpFileName, "/faketemp/")) {
                FileHandle = fopen(lpFileName, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(lpFileName);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", lpFileName, FileHandle);

    if (FileHandle) {
        SetLastError(0);
        RememberOpenFile(FileHandle);
        return FileHandle;
    }

    if (g_failed_open_logs < 20) {
        LogMessage("CreateFileA failed: %s (access=%#x disp=%#x flags=%#x)",
                   lpFileName, dwDesiredAccess, dwCreationDisposition, dwFlagsAndAttributes);
        g_failed_open_logs++;
    }
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}


static HANDLE WINAPI CreateFileW(PWCHAR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, PVOID lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    FILE *FileHandle;
    char *filename = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %#x, %#x, %p, %#x, %#x, %p", lpFileName, filename, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    // Translate path seperator.
    while (strchr(filename, '\\'))
        *strchr(filename, '\\') = '/';

    // I'm just going to tolower() everything.
    for (char *t = filename; *t; t++)
        *t = tolower(*t);

    if (strstr(filename, "mpcache-")) {
        LogMessage("CreateFileW mpcache path seen: %s", filename);
        SetLastError(ERROR_FILE_NOT_FOUND);
        free(filename);
        return INVALID_HANDLE_VALUE;
    }

    if (strncmp(filename, "//./", 4) == 0 || strncmp(filename, "//?/", 4) == 0) {
        FileHandle = fopen("/dev/null", "r+");
        if (FileHandle) {
            SetLastError(0);
            free(filename);
            return FileHandle;
        }
    }

    //LogMessage("%u %s", dwCreationDisposition, filename);

    switch (dwCreationDisposition) {
        case OPEN_EXISTING:
            FileHandle = fopen(filename, "r");
            if (!FileHandle && (dwFlagsAndAttributes & (FILE_FLAG_BACKUP_SEMANTICS | FILE_ATTRIBUTE_DIRECTORY))) {
                struct stat st;
                if (stat(filename, &st) != 0) {
                    mkdir_p(filename);
                }
                if (stat(filename, &st) == 0 && S_ISDIR(st.st_mode)) {
                    FileHandle = fopen("/dev/null", "r");
                }
            }
            break;
        case OPEN_ALWAYS:
            FileHandle = fopen(filename, "r+");
            if (!FileHandle) {
                FileHandle = fopen(filename, "w+");
            }
            break;
        case CREATE_ALWAYS:
            FileHandle = fopen("/dev/null", "w");
            break;
        // This is the disposition used by CreateTempFile().
        case CREATE_NEW:
            if (strstr(filename, "/faketemp/")) {
                FileHandle = fopen(filename, "w");
                // Unlink it immediately so it's cleaned up on exit.
                unlink(filename);
            } else {
                FileHandle = fopen("/dev/null", "w");
            }
            break;
        case TRUNCATE_EXISTING:
            FileHandle = fopen(filename, "r+");
            if (FileHandle) {
                ftruncate(fileno(FileHandle), 0);
            }
            break;
        default:
            abort();
    }

    DebugLog("%s => %p", filename, FileHandle);

    if (FileHandle) {
        free(filename);
        SetLastError(0);
        RememberOpenFile(FileHandle);
        return FileHandle;
    }

    if (g_failed_open_logs < 20) {
        LogMessage("CreateFileW failed: %s (access=%#x disp=%#x flags=%#x)",
                   filename, dwDesiredAccess, dwCreationDisposition, dwFlagsAndAttributes);
        g_failed_open_logs++;
    }

    free(filename);
    SetLastError(ERROR_FILE_NOT_FOUND);
    return INVALID_HANDLE_VALUE;
}

/**
 * TODO: handle 64 bit 
 */
static DWORD WINAPI SetFilePointer(HANDLE hFile, LONG liDistanceToMove,  LONG *lpDistanceToMoveHigh, DWORD dwMoveMethod)
{
    int result;
    long pos;

    DebugLog("%p, %llu, %p, %u", hFile, liDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);

    result = fseek(hFile, liDistanceToMove, dwMoveMethod);

    if (result != 0) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0xFFFFFFFF;
    }

    pos = ftell(hFile);
    if (pos < 0) {
        SetLastError(ERROR_FILE_NOT_FOUND);
        return 0xFFFFFFFF;
    }

    if (lpDistanceToMoveHigh) {
        *lpDistanceToMoveHigh = 0;
    }

    SetLastError(0);
    return (DWORD)pos;
}


static BOOL WINAPI SetFilePointerEx(HANDLE hFile, uint64_t liDistanceToMove,  uint64_t *lpNewFilePointer, DWORD dwMoveMethod)
{
    int result;

    //DebugLog("%p, %llu, %p, %u", hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);

    result = fseek(hFile, liDistanceToMove, dwMoveMethod);

    // dwMoveMethod maps onto SEEK_SET/SEEK_CUR/SEEK_END perfectly.
    if (lpNewFilePointer) {
        *lpNewFilePointer = ftell(hFile);
    }

    // Windows is permissive here.
    return TRUE;
    //return result != -1; 
}

static BOOL WINAPI CloseHandle(HANDLE hObject)
{
    DebugLog("%p", hObject);
    if (IsFileMappingHandle(hObject)) {
        CloseFileMappingHandle(hObject);
        return TRUE;
    }
    if (hObject != (HANDLE) 'EVNT'
     && hObject != INVALID_HANDLE_VALUE
     && hObject != (HANDLE) 'SEMA'
     && hObject != (HANDLE) 'TOKN') {
        if (ForgetOpenFile(hObject)) {
            fclose(hObject);
        }
    }
    return TRUE;
}

static BOOL WINAPI ReadFile(HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToRead, PDWORD lpNumberOfBytesRead, PVOID lpOverlapped)
{
    *lpNumberOfBytesRead = fread(lpBuffer, 1, nNumberOfBytesToRead, hFile);
    return TRUE;
}

static BOOL WINAPI WriteFile(HANDLE hFile, PVOID lpBuffer, DWORD nNumberOfBytesToWrite, PDWORD lpNumberOfBytesWritten, PVOID lpOverlapped)
{
    *lpNumberOfBytesWritten = fwrite(lpBuffer, 1, nNumberOfBytesToWrite, hFile);
    return TRUE;
}

static BOOL WINAPI DeleteFileW(PWCHAR lpFileName)
{
    char *AnsiFilename = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s]", lpFileName, AnsiFilename);

    free(AnsiFilename);
    return TRUE;
}

static void mkdir_p(const char *path)
{
    char tmp[PATH_MAX];
    size_t len;

    if (!path) {
        return;
    }

    len = strlen(path);
    if (len == 0 || len >= sizeof(tmp)) {
        return;
    }

    memcpy(tmp, path, len + 1);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
                return;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) != 0 && errno != EEXIST) {
        return;
    }
}

static BOOL WINAPI CreateDirectoryW(PWCHAR lpPathName, PVOID lpSecurityAttributes)
{
    char *path = CreateAnsiFromWide(lpPathName);
    DebugLog("%p [%s] %p", lpPathName, path, lpSecurityAttributes);

    if (!path) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    for (char *t = path; *t; t++) {
        if (*t == '\\') {
            *t = '/';
        }
        *t = (char) tolower((unsigned char) *t);
    }

    if (strncmp(path, "//./", 4) == 0 || strncmp(path, "//?/", 4) == 0) {
        free(path);
        SetLastError(0);
        return TRUE;
    }

    if (path[0] == '/') {
        char rel_path[PATH_MAX];
        snprintf(rel_path, sizeof(rel_path), ".%s", path);
        mkdir_p(rel_path);
    } else {
        mkdir_p(path);
    }

    free(path);
    SetLastError(0);
    return TRUE;
}

static BOOL WINAPI RemoveDirectoryW(PWCHAR lpPathName)
{
    char *AnsiPath = CreateAnsiFromWide(lpPathName);

    DebugLog("%p [%s]", lpPathName, AnsiPath);

    free(AnsiPath);
    SetLastError(0);
    return TRUE;
}

static BOOL WINAPI GetFileSizeEx(HANDLE hFile, uint64_t *lpFileSize)
{
    long curpos = ftell(hFile);

    fseek(hFile, 0, SEEK_END);

    *lpFileSize = ftell(hFile);

    fseek(hFile, curpos, SEEK_SET);

    DebugLog("%p, %p => %llu", hFile, lpFileSize, *lpFileSize);


    return TRUE;
}

static DWORD WINAPI GetFileSize(HANDLE hFile, PDWORD lpFileSizeHigh)
{
    uint64_t size = 0;

    DebugLog("%p, %p", hFile, lpFileSizeHigh);

    if (!GetFileSizeEx(hFile, &size)) {
        return INVALID_FILE_ATTRIBUTES;
    }

    if (lpFileSizeHigh) {
        *lpFileSizeHigh = (DWORD)(size >> 32);
    }

    return (DWORD)size;
}

static BOOL WINAPI AreFileApisANSI(VOID)
{
    DebugLog("");
    return TRUE;
}

static HANDLE WINAPI FindFirstFileW(PWCHAR lpFileName, PVOID lpFindFileData)
{
    char *name = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %p", lpFileName, name, lpFindFileData);

    free(name);

    SetLastError(ERROR_FILE_NOT_FOUND);

    return INVALID_HANDLE_VALUE;
}

static HANDLE WINAPI FindFirstFileExW(PWCHAR lpFileName,
                                      DWORD fInfoLevelId,
                                      PVOID lpFindFileData,
                                      DWORD fSearchOp,
                                      PVOID lpSearchFilter,
                                      DWORD dwAdditionalFlags)
{
    char *name = CreateAnsiFromWide(lpFileName);

    DebugLog("%p [%s], %u, %p, %u, %p, %#x",
             lpFileName, name, fInfoLevelId, lpFindFileData,
             fSearchOp, lpSearchFilter, dwAdditionalFlags);

    free(name);

    SetLastError(ERROR_FILE_NOT_FOUND);

    return INVALID_HANDLE_VALUE;
}

static BOOL WINAPI FindNextFileW(HANDLE hFindFile, PVOID lpFindFileData)
{
    DebugLog("%p, %p", hFindFile, lpFindFileData);

    SetLastError(ERROR_NO_MORE_FILES);

    return FALSE;
}

static HANDLE volume_enum_handle = (HANDLE)(uintptr_t)0x564f4c31; /* 'VOL1' */
static int volume_enum_state = 0;

static HANDLE WINAPI FindFirstVolumeW(PWCHAR lpszVolumeName, DWORD cchBufferLength)
{
    static const wchar_t volume_name[] = L"\\\\?\\Volume{00000000-0000-0000-0000-000000000000}\\";
    size_t volume_len = wcslen(volume_name) + 1;

    DebugLog("%p, %u", lpszVolumeName, cchBufferLength);

    if (!lpszVolumeName || cchBufferLength < volume_len) {
        SetLastError(ERROR_MORE_DATA);
        return INVALID_HANDLE_VALUE;
    }

    wcscpy(lpszVolumeName, volume_name);
    volume_enum_state = 1;
    SetLastError(0);
    return volume_enum_handle;
}

static BOOL WINAPI FindNextVolumeW(HANDLE hFindVolume, PWCHAR lpszVolumeName, DWORD cchBufferLength)
{
    DebugLog("%p, %p, %u", hFindVolume, lpszVolumeName, cchBufferLength);

    if (hFindVolume != volume_enum_handle || volume_enum_state == 0) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    volume_enum_state = 2;
    SetLastError(ERROR_NO_MORE_FILES);
    return FALSE;
}

static BOOL WINAPI FindVolumeClose(HANDLE hFindVolume)
{
    DebugLog("%p", hFindVolume);

    if (hFindVolume != volume_enum_handle) {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    volume_enum_state = 0;
    SetLastError(0);
    return TRUE;
}

static DWORD WINAPI NtOpenSymbolicLinkObject(PHANDLE LinkHandle, DWORD DesiredAccess, PVOID ObjectAttributes)
{
    *LinkHandle = (HANDLE) 'SYMB';
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI NtQuerySymbolicLinkObject(HANDLE LinkHandle, PUNICODE_STRING LinkTarget, PULONG ReturnedLength)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI NtClose(HANDLE Handle)
{
    return STATUS_SUCCESS;
}

static BOOL WINAPI DeviceIoControl(
  HANDLE       hDevice,
  DWORD        dwIoControlCode,
  PVOID       lpInBuffer,
  DWORD        nInBufferSize,
  PVOID       lpOutBuffer,
  DWORD        nOutBufferSize,
  PDWORD      lpBytesReturned,
  PVOID       lpOverlapped)
{
    DebugLog("");
    if (lpBytesReturned) {
        *lpBytesReturned = 0;
    }
    if (lpOutBuffer && nOutBufferSize) {
        memset(lpOutBuffer, 0, nOutBufferSize);
    }
    SetLastError(0);
    return TRUE;
}

static NTSTATUS WINAPI NtQueryVolumeInformationFile(
 HANDLE               FileHandle,
 PVOID                IoStatusBlock,
 PVOID                FsInformation,
 ULONG                Length,
 DWORD FsInformationClass)
{
    DebugLog("");
    if (IoStatusBlock) {
        memset(IoStatusBlock, 0, sizeof(ULONG_PTR) * 2);
    }
    if (FsInformation && Length) {
        memset(FsInformation, 0, Length);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI NtQueryInformationFile(
 HANDLE FileHandle,
 PIO_STATUS_BLOCK IoStatusBlock,
 PVOID FileInformation,
 ULONG Length,
 DWORD FileInformationClass)
{
    struct stat st;
    bool has_stat = false;

    DebugLog("%p, %p, %p, %u, %#x", FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

    if (FileHandle && FileHandle != INVALID_HANDLE_VALUE) {
        int fd = fileno((FILE *) FileHandle);
        if (fd >= 0 && fstat(fd, &st) == 0) {
            has_stat = true;
        }
    }

    if (IoStatusBlock) {
        IoStatusBlock->Status = STATUS_SUCCESS;
        IoStatusBlock->Information = 0;
    }

    if (!FileInformation || Length == 0) {
        return STATUS_SUCCESS;
    }

    memset(FileInformation, 0, Length);

    switch (FileInformationClass) {
        case FILE_BASIC_INFORMATION_CLASS: {
            if (Length < sizeof(FILE_BASIC_INFORMATION)) {
                return STATUS_SUCCESS;
            }
            FILE_BASIC_INFORMATION *info = (FILE_BASIC_INFORMATION *) FileInformation;
            if (has_stat && S_ISDIR(st.st_mode)) {
                info->FileAttributes = FILE_ATTRIBUTE_DIRECTORY;
            } else {
                info->FileAttributes = FILE_ATTRIBUTE_NORMAL;
            }
            if (IoStatusBlock) {
                IoStatusBlock->Information = sizeof(*info);
            }
            break;
        }
        case FILE_STANDARD_INFORMATION_CLASS: {
            if (Length < sizeof(FILE_STANDARD_INFORMATION)) {
                return STATUS_SUCCESS;
            }
            FILE_STANDARD_INFORMATION *info = (FILE_STANDARD_INFORMATION *) FileInformation;
            if (has_stat) {
                info->AllocationSize = (LARGE_INTEGER) st.st_blocks * 512;
                info->EndOfFile = (LARGE_INTEGER) st.st_size;
                info->NumberOfLinks = (ULONG) st.st_nlink;
                info->Directory = S_ISDIR(st.st_mode) ? 1 : 0;
            }
            if (IoStatusBlock) {
                IoStatusBlock->Information = sizeof(*info);
            }
            break;
        }
        default:
            break;
    }

    return STATUS_SUCCESS;
}

static DWORD WINAPI GetFullPathNameW(
  PWCHAR lpFileName,
  DWORD   nBufferLength,
  PWCHAR  lpBuffer,
  PWCHAR  *lpFilePart)
{
    size_t len = CountWideChars(lpFileName);
    size_t needed = len + 1;

    DebugLog("%p, %u, %p, %p", lpFileName, nBufferLength, lpBuffer, lpFilePart);

    if (lpFilePart) {
        *lpFilePart = NULL;
    }

    if (!lpBuffer || nBufferLength == 0) {
        return (DWORD)needed;
    }

    if (nBufferLength < needed) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return (DWORD)needed;
    }

    memcpy(lpBuffer, lpFileName, needed * sizeof(*lpBuffer));

    if (lpFilePart) {
        PWCHAR last = lpBuffer;
        for (PWCHAR cur = lpBuffer; *cur; cur++) {
            if (*cur == L'\\' || *cur == L'/') {
                last = cur + 1;
            }
        }
        *lpFilePart = last;
    }

    return (DWORD)len;
}

static BOOL WINAPI SetEndOfFile(HANDLE hFile)
{
    DebugLog("");
    return ftruncate(fileno(hFile), ftell(hFile)) != -1;
}

static DWORD WINAPI GetFileVersionInfoSizeExW(DWORD dwFlags, PWCHAR lptstrFilename, PDWORD lpdwHandle)
{
    DebugLog("%#x, %p, %p", dwFlags, lptstrFilename, lpdwHandle);
    return 0;
}

static BOOL WINAPI GetFileVersionInfoExW(DWORD dwFlags, PWCHAR lptstrFilename, DWORD dwHandle, DWORD dwLen, PVOID lpData)
{
    DebugLog("");
    return FALSE;
}

static BOOL WINAPI VerQueryValueW(PVOID pBlock, PWCHAR lpSubBlock, PVOID  *lplpBuffer, PDWORD puLen)
{
    DebugLog("");
    return FALSE;
}

static DWORD WINAPI QueryDosDevice(PVOID lpDeviceName, PVOID lpTargetPath, DWORD ucchMax)
{
    static const wchar_t mapping[] = L"\\Device\\HarddiskVolume3";
    PWCHAR target = (PWCHAR)lpTargetPath;
    PWCHAR device = (PWCHAR)lpDeviceName;

    if (device) {
        char *device_name = CreateAnsiFromWide(device);
        DebugLog("%p [%s] %p %u", device, device_name, target, ucchMax);
        free(device_name);
    } else {
        DebugLog("%p %p %u", device, target, ucchMax);
    }

    if (!target || ucchMax == 0) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return 0;
    }

    {
        size_t mapping_len = wcslen(mapping);
        if (ucchMax <= mapping_len) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }
        memcpy(target, mapping, (mapping_len + 1) * sizeof(*mapping));
        SetLastError(0);
        return (DWORD)mapping_len;
    }
}

static BOOL WINAPI GetDiskFreeSpaceExW(PWCHAR lpDirectoryName, PVOID lpFreeBytesAvailableToCaller, PVOID lpTotalNumberOfBytes, QWORD *lpTotalNumberOfFreeBytes)
{
    DebugLog("%S", lpDirectoryName);
    const QWORD total = 100ULL * 1024ULL * 1024ULL * 1024ULL;
    if (lpFreeBytesAvailableToCaller) {
        *(QWORD *) lpFreeBytesAvailableToCaller = total;
    }
    if (lpTotalNumberOfBytes) {
        *(QWORD *) lpTotalNumberOfBytes = total;
    }
    if (lpTotalNumberOfFreeBytes) {
        *lpTotalNumberOfFreeBytes = total;
    }
    SetLastError(0);
    return TRUE;
}

STATIC BOOL WINAPI SetFileInformationByHandle(HANDLE hFile,
                                              FILE_INFO_BY_HANDLE_CLASS FileInformationClass,
                                              LPVOID lpFileInformation,
                                              DWORD dwBufferSize)
{
    DebugLog("%p %p %u", hFile, lpFileInformation, dwBufferSize);
    return TRUE;
}

DECLARE_CRT_EXPORT("VerQueryValueW", VerQueryValueW);
DECLARE_CRT_EXPORT("GetFileVersionInfoExW", GetFileVersionInfoExW);
DECLARE_CRT_EXPORT("GetFileVersionInfoSizeExW", GetFileVersionInfoSizeExW);
DECLARE_CRT_EXPORT("GetFileAttributesW", GetFileAttributesW);
DECLARE_CRT_EXPORT("GetFileAttributesA", GetFileAttributesA);
DECLARE_CRT_EXPORT("GetFileAttributesExW", GetFileAttributesExW);
DECLARE_CRT_EXPORT("CreateFileA", CreateFileA);
DECLARE_CRT_EXPORT("CreateFileW", CreateFileW);
DECLARE_CRT_EXPORT("SetFilePointer", SetFilePointer);
DECLARE_CRT_EXPORT("SetFilePointerEx", SetFilePointerEx);
DECLARE_CRT_EXPORT("CloseHandle", CloseHandle);
DECLARE_CRT_EXPORT("ReadFile", ReadFile);
DECLARE_CRT_EXPORT("WriteFile", WriteFile);
DECLARE_CRT_EXPORT("DeleteFileW", DeleteFileW);
DECLARE_CRT_EXPORT("CreateDirectoryW", CreateDirectoryW);
DECLARE_CRT_EXPORT("RemoveDirectoryW", RemoveDirectoryW);
DECLARE_CRT_EXPORT("GetFileSizeEx", GetFileSizeEx);
DECLARE_CRT_EXPORT("GetFileSize", GetFileSize);
DECLARE_CRT_EXPORT("AreFileApisANSI", AreFileApisANSI);
DECLARE_CRT_EXPORT("FindFirstFileW", FindFirstFileW);
DECLARE_CRT_EXPORT("FindFirstFileExW", FindFirstFileExW);
DECLARE_CRT_EXPORT("FindNextFileW", FindNextFileW);
DECLARE_CRT_EXPORT("FindFirstVolumeW", FindFirstVolumeW);
DECLARE_CRT_EXPORT("FindNextVolumeW", FindNextVolumeW);
DECLARE_CRT_EXPORT("FindVolumeClose", FindVolumeClose);
DECLARE_CRT_EXPORT("NtOpenSymbolicLinkObject", NtOpenSymbolicLinkObject);
DECLARE_CRT_EXPORT("NtQuerySymbolicLinkObject", NtQuerySymbolicLinkObject);
DECLARE_CRT_EXPORT("NtClose", NtClose);
DECLARE_CRT_EXPORT("NtQueryInformationFile", NtQueryInformationFile);
DECLARE_CRT_EXPORT("DeviceIoControl", DeviceIoControl);
DECLARE_CRT_EXPORT("NtQueryVolumeInformationFile", NtQueryVolumeInformationFile);
DECLARE_CRT_EXPORT("GetFullPathNameW", GetFullPathNameW);
DECLARE_CRT_EXPORT("SetEndOfFile", SetEndOfFile);
DECLARE_CRT_EXPORT("QueryDosDeviceW", QueryDosDevice);
DECLARE_CRT_EXPORT("GetDiskFreeSpaceExW", GetDiskFreeSpaceExW);
DECLARE_CRT_EXPORT("SetFileInformationByHandle", SetFileInformationByHandle);
