#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <search.h>
#include <string.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

STATIC NTSTATUS WINAPI NtSetInformationProcess(HANDLE ProcessHandle,
                                               PROCESS_INFORMATION_CLASS ProcessInformationClass,
                                               PVOID ProcessInformation,
                                               ULONG ProcessInformationLength)
{
    DebugLog("%p", ProcessHandle);
    return 0;
}

STATIC BOOL WINAPI QueryFullProcessImageNameW(HANDLE hProcess,
                                              DWORD dwFlags,
                                              PWCHAR lpExeName,
                                              PDWORD lpdwSize)
{
    const WCHAR name[] = L"C:\\dummy\\fakename.exe";
    DWORD needed = (sizeof(name) / sizeof(name[0])) - 1;

    DebugLog("%p, %#x, %p, %p", hProcess, dwFlags, lpExeName, lpdwSize);

    if (!lpExeName || !lpdwSize) {
        return FALSE;
    }

    if (*lpdwSize <= needed) {
        *lpdwSize = needed + 1;
        return FALSE;
    }

    memcpy(lpExeName, name, sizeof(name));
    *lpdwSize = needed;
    return TRUE;
}

STATIC HANDLE WINAPI OpenProcess(DWORD dwDesiredAccess,
                                 BOOL bInheritHandle,
                                 DWORD dwProcessId)
{
    DebugLog("%#x, %u, %u", dwDesiredAccess, bInheritHandle, dwProcessId);
    (void)bInheritHandle;
    return (HANDLE)(uintptr_t)dwProcessId;
}

STATIC DWORD WINAPI GetProcessId(HANDLE Process)
{
    DebugLog("%p", Process);
    return (DWORD)(uintptr_t)Process;
}

STATIC BOOL WINAPI GetExitCodeProcess(HANDLE ProcessHandle, LPDWORD lpExitCode)
{
    DebugLog("%p %p", ProcessHandle, lpExitCode);
    if (lpExitCode) {
        *lpExitCode = 0;
    }
    return TRUE;
}

DECLARE_CRT_EXPORT("NtSetInformationProcess", NtSetInformationProcess);
DECLARE_CRT_EXPORT("OpenProcess", OpenProcess);
DECLARE_CRT_EXPORT("GetProcessId", GetProcessId);
DECLARE_CRT_EXPORT("QueryFullProcessImageNameW", QueryFullProcessImageNameW);
DECLARE_CRT_EXPORT("GetExitCodeProcess", GetExitCodeProcess);
