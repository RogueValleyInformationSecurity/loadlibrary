#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

/* Lightweight stubs for APIs imported by newer mpengine builds. */

LPTOP_LEVEL_EXCEPTION_FILTER g_top_level_exception_filter;
static const uint64_t k_windows_epoch_offset = 11644473600ULL;

static LARGE_INTEGER UnixTimeToFileTime(time_t t)
{
    uint64_t filetime = ((uint64_t)t + k_windows_epoch_offset) * 10000000ULL;
    return (LARGE_INTEGER)filetime;
}

static FILETIME UnixTimeToFileTimeStruct(time_t t)
{
    uint64_t filetime = (uint64_t)UnixTimeToFileTime(t);
    FILETIME out;
    out.dwLowDateTime = (DWORD)(filetime & 0xffffffffULL);
    out.dwHighDateTime = (DWORD)(filetime >> 32);
    return out;
}

#define STUB_PVOID(name) \
    static PVOID WINAPI name(void) { DebugLog("%s", #name); return NULL; }

#define STUB_BOOL(name, value) \
    static BOOL WINAPI name(void) { DebugLog("%s", #name); return (value); }

#define STUB_DWORD(name, value) \
    static DWORD WINAPI name(void) { DebugLog("%s", #name); return (value); }

STUB_PVOID(AreFileApisANSI)
STUB_PVOID(CompareStringEx)
STUB_PVOID(EnumSystemLocalesEx)
STUB_PVOID(GetDateFormatEx)
STUB_PVOID(GetTimeFormatEx)
STUB_PVOID(IsValidLocaleName)
STUB_PVOID(LCIDToLocaleName)
STUB_PVOID(CancelSynchronousIo)
STUB_PVOID(CreateSymbolicLinkW)
STUB_PVOID(DeleteProcThreadAttributeList)
STUB_PVOID(FindFirstFileNameW)
STUB_PVOID(FindNextFileNameW)
STUB_PVOID(GetFirmwareEnvironmentVariableA)
STUB_PVOID(GetFirmwareEnvironmentVariableExW)
STUB_PVOID(GetFirmwareType)
STUB_PVOID(GetProcessInformation)
STUB_PVOID(GetThreadInformation)
STUB_PVOID(GetUserDefaultLocaleName)
STUB_PVOID(InitializeProcThreadAttributeList)
STUB_PVOID(K32EnumPageFilesW)
STUB_PVOID(K32EnumProcessModules)
STUB_PVOID(K32EnumProcesses)
STUB_PVOID(K32GetMappedFileNameW)
STUB_PVOID(K32GetModuleBaseNameW)
STUB_PVOID(K32GetModuleFileNameExW)
STUB_PVOID(K32GetModuleInformation)
STUB_PVOID(K32GetProcessImageFileNameW)
STUB_PVOID(K32GetProcessMemoryInfo)
STUB_PVOID(K32QueryWorkingSetEx)
STUB_PVOID(PrefetchVirtualMemory)
STUB_PVOID(SetThreadInformation)
STUB_PVOID(TryAcquireSRWLockExclusive)
STUB_PVOID(UpdateProcThreadAttribute)
STUB_PVOID(EventWriteTransfer)
STUB_PVOID(NotifyServiceStatusChangeW)
STUB_PVOID(RegDisableReflectionKey)
STUB_PVOID(RegEnableReflectionKey)
STUB_PVOID(RegQueryReflectionKey)
STUB_PVOID(GetTempPath2W)

typedef struct _FILE_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    DWORD NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFO;

typedef struct _FILE_BASIC_INFO {
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    DWORD FileAttributes;
} FILE_BASIC_INFO;

typedef struct _FILE_ATTRIBUTE_TAG_INFO {
    DWORD FileAttributes;
    DWORD ReparseTag;
} FILE_ATTRIBUTE_TAG_INFO;

typedef struct _FILE_NAME_INFO {
    DWORD FileNameLength;
    WCHAR FileName[1];
} FILE_NAME_INFO;

typedef struct _BY_HANDLE_FILE_INFORMATION {
    DWORD dwFileAttributes;
    FILETIME ftCreationTime;
    FILETIME ftLastAccessTime;
    FILETIME ftLastWriteTime;
    DWORD dwVolumeSerialNumber;
    DWORD nFileSizeHigh;
    DWORD nFileSizeLow;
    DWORD nNumberOfLinks;
    DWORD nFileIndexHigh;
    DWORD nFileIndexLow;
} BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION;

static BOOL WINAPI GetFileInformationByHandle(HANDLE hFile,
                                              PBY_HANDLE_FILE_INFORMATION lpFileInformation)
{
    if (!hFile || hFile == INVALID_HANDLE_VALUE || !lpFileInformation) {
        return FALSE;
    }

    FILE *file = (FILE *)hFile;
    struct stat st;
    if (fstat(fileno(file), &st) != 0) {
        return FALSE;
    }

    memset(lpFileInformation, 0, sizeof(*lpFileInformation));
    lpFileInformation->dwFileAttributes = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
    lpFileInformation->ftCreationTime = UnixTimeToFileTimeStruct(st.st_ctime);
    lpFileInformation->ftLastAccessTime = UnixTimeToFileTimeStruct(st.st_atime);
    lpFileInformation->ftLastWriteTime = UnixTimeToFileTimeStruct(st.st_mtime);
    lpFileInformation->nFileSizeHigh = (DWORD)(((uint64_t)st.st_size) >> 32);
    lpFileInformation->nFileSizeLow = (DWORD)((uint64_t)st.st_size & 0xffffffffULL);
    lpFileInformation->nNumberOfLinks = (DWORD)st.st_nlink;
    return TRUE;
}

static BOOL WINAPI GetFileInformationByHandleEx(HANDLE hFile,
                                                DWORD FileInformationClass,
                                                PVOID lpFileInformation,
                                                DWORD dwBufferSize)
{
    if (!hFile || hFile == INVALID_HANDLE_VALUE || !lpFileInformation) {
        return FALSE;
    }

    FILE *file = (FILE *)hFile;
    struct stat st;
    if (fstat(fileno(file), &st) != 0) {
        return FALSE;
    }

    switch (FileInformationClass) {
        case FileStandardInfo: {
            if (dwBufferSize < sizeof(FILE_STANDARD_INFO)) {
                return FALSE;
            }
            FILE_STANDARD_INFO *info = (FILE_STANDARD_INFO *)lpFileInformation;
            info->AllocationSize = (LARGE_INTEGER)st.st_size;
            info->EndOfFile = (LARGE_INTEGER)st.st_size;
            info->NumberOfLinks = (DWORD)st.st_nlink;
            info->DeletePending = 0;
            info->Directory = S_ISDIR(st.st_mode) ? 1 : 0;
            return TRUE;
        }
        case FileBasicInfo: {
            if (dwBufferSize < sizeof(FILE_BASIC_INFO)) {
                return FALSE;
            }
            FILE_BASIC_INFO *info = (FILE_BASIC_INFO *)lpFileInformation;
            info->CreationTime = UnixTimeToFileTime(st.st_ctime);
            info->LastAccessTime = UnixTimeToFileTime(st.st_atime);
            info->LastWriteTime = UnixTimeToFileTime(st.st_mtime);
            info->ChangeTime = UnixTimeToFileTime(st.st_ctime);
            info->FileAttributes = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
            return TRUE;
        }
        case FileAttributeTagInfo: {
            if (dwBufferSize < sizeof(FILE_ATTRIBUTE_TAG_INFO)) {
                return FALSE;
            }
            FILE_ATTRIBUTE_TAG_INFO *info = (FILE_ATTRIBUTE_TAG_INFO *)lpFileInformation;
            info->FileAttributes = S_ISDIR(st.st_mode) ? 0x10 : 0x80;
            info->ReparseTag = 0;
            return TRUE;
        }
        case FileNameInfo: {
            if (dwBufferSize < offsetof(FILE_NAME_INFO, FileName)) {
                return FALSE;
            }

            FILE_NAME_INFO *info = (FILE_NAME_INFO *)lpFileInformation;
            char linkpath[64];
            char path[PATH_MAX];
            char winpath[PATH_MAX * 2];
            int fd = fileno(file);

            snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
            ssize_t len = readlink(linkpath, path, sizeof(path) - 1);
            if (len < 0) {
                return FALSE;
            }
            path[len] = '\0';

            const char *drive_path = strstr(path, "/c:/");
            if (!drive_path) {
                drive_path = strstr(path, "/C:/");
            }

            if (drive_path) {
                snprintf(winpath, sizeof(winpath), "%s", drive_path + 1);
            } else if (path[0] == '/') {
                snprintf(winpath, sizeof(winpath), "c:%s", path);
            } else {
                snprintf(winpath, sizeof(winpath), "%s", path);
            }

            size_t wlen = 0;
            size_t max_wchars = (dwBufferSize - offsetof(FILE_NAME_INFO, FileName)) / sizeof(WCHAR);
            for (const char *p = winpath; *p && wlen < max_wchars; ++p) {
                char c = (*p == '/') ? '\\' : *p;
                info->FileName[wlen++] = (WCHAR)(unsigned char)c;
            }

            info->FileNameLength = (DWORD)(wlen * sizeof(WCHAR));
            return wlen > 0;
        }
        default:
            memset(lpFileInformation, 0, dwBufferSize);
            return TRUE;
    }
}

static DWORD WINAPI GetFinalPathNameByHandleW(HANDLE hFile,
                                              PWCHAR lpszFilePath,
                                              DWORD cchFilePath,
                                              DWORD dwFlags)
{
    (void)dwFlags;

    if (!hFile || hFile == INVALID_HANDLE_VALUE) {
        return 0;
    }

    FILE *file = (FILE *)hFile;
    int fd = fileno(file);
    char linkpath[64];
    char path[PATH_MAX];
    char winpath[PATH_MAX * 2];

    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(linkpath, path, sizeof(path) - 1);
    if (len < 0) {
        return 0;
    }
    path[len] = '\0';

    const char *drive_path = strstr(path, "/c:/");
    if (!drive_path) {
        drive_path = strstr(path, "/C:/");
    }

    if (drive_path) {
        snprintf(winpath, sizeof(winpath), "%s", drive_path + 1);
    } else if (path[0] == '/') {
        snprintf(winpath, sizeof(winpath), "c:%s", path);
    } else {
        snprintf(winpath, sizeof(winpath), "%s", path);
    }

    size_t out_len = 0;
    for (const char *p = winpath; *p; ++p) {
        if (cchFilePath && out_len + 1 < cchFilePath && lpszFilePath) {
            char c = (*p == '/') ? '\\' : *p;
            lpszFilePath[out_len] = (WCHAR)(unsigned char)c;
        }
        out_len++;
    }

    if (cchFilePath == 0) {
        return (DWORD)out_len;
    }

    if (out_len + 1 > cchFilePath) {
        if (lpszFilePath && cchFilePath > 0) {
            lpszFilePath[0] = L'\0';
        }
        return (DWORD)(out_len + 1);
    }

    if (lpszFilePath) {
        lpszFilePath[out_len] = L'\0';
    }

    return (DWORD)out_len;
}

static PVOID WINAPI NdrClientCall3(PVOID StubDescriptor, PVOID Format, ...)
{
    DebugLog("%p %p", StubDescriptor, Format);
    return NULL;
}

static PVOID WINAPI NdrServerCall2(PVOID RpcMsg)
{
    DebugLog("%p", RpcMsg);
    return NULL;
}

static DWORD WINAPI RpcBindingBind(PVOID Binding, PVOID IfSpec)
{
    DebugLog("%p %p", Binding, IfSpec);
    return 0;
}

static DWORD WINAPI RpcBindingCreateW(PVOID Template, PVOID Security, PVOID Options, PVOID Binding)
{
    DebugLog("%p %p %p %p", Template, Security, Options, Binding);
    if (Binding) {
        *(PVOID *)Binding = (PVOID) 'RPCH';
    }
    return 0;
}

static DWORD WINAPI RpcBindingFree(PVOID Binding)
{
    DebugLog("%p", Binding);
    if (Binding) {
        *(PVOID *)Binding = NULL;
    }
    return 0;
}

static DWORD WINAPI RpcBindingVectorFree(PVOID BindingVector)
{
    DebugLog("%p", BindingVector);
    if (BindingVector) {
        *(PVOID *)BindingVector = NULL;
    }
    return 0;
}

static DWORD WINAPI RpcEpRegisterW(PVOID IfSpec, PVOID BindingVector, PVOID ObjectUuidVec, PVOID Annotation)
{
    DebugLog("%p %p %p %p", IfSpec, BindingVector, ObjectUuidVec, Annotation);
    return 0;
}

static DWORD WINAPI RpcEpUnregister(PVOID IfSpec, PVOID BindingVector, PVOID ObjectUuidVec)
{
    DebugLog("%p %p %p", IfSpec, BindingVector, ObjectUuidVec);
    return 0;
}

static DWORD WINAPI RpcServerInqBindings(PVOID BindingVector)
{
    DebugLog("%p", BindingVector);
    if (BindingVector) {
        *(PVOID *)BindingVector = NULL;
    }
    return 0;
}

static DWORD WINAPI RpcServerListen(UINT MinimumCallThreads, UINT MaxCalls, UINT DontWait)
{
    DebugLog("%u %u %u", MinimumCallThreads, MaxCalls, DontWait);
    return 0;
}

static DWORD WINAPI RpcServerRegisterIf3(PVOID IfSpec,
                                         PVOID MgrTypeUuid,
                                         PVOID MgrEpv,
                                         UINT Flags,
                                         UINT MaxCalls,
                                         UINT MaxRpcSize,
                                         PVOID IfCallback,
                                         PVOID SecurityDescriptor)
{
    DebugLog("%p %p %p %u %u %u %p %p",
             IfSpec, MgrTypeUuid, MgrEpv, Flags,
             MaxCalls, MaxRpcSize, IfCallback, SecurityDescriptor);
    return 0;
}

static DWORD WINAPI RpcServerUnregisterIfEx(PVOID IfSpec, PVOID MgrTypeUuid, UINT WaitForCallsToComplete)
{
    DebugLog("%p %p %u", IfSpec, MgrTypeUuid, WaitForCallsToComplete);
    return 0;
}

static DWORD WINAPI RpcServerUseProtseqEpW(PWCHAR Protseq, UINT MaxCalls, PWCHAR Endpoint, PVOID SecurityDescriptor)
{
    DebugLog("%p %u %p %p", Protseq, MaxCalls, Endpoint, SecurityDescriptor);
    return 0;
}

static DWORD WINAPI RpcObjectSetType(PVOID ObjUuid, PVOID TypeUuid)
{
    DebugLog("%p %p", ObjUuid, TypeUuid);
    return 0;
}

static DWORD WINAPI MpCleanupServer(void)
{
    DebugLog("MpCleanupServer");
    return 0;
}

static DWORD WINAPI MpInitServer(void)
{
    DebugLog("MpInitServer");
    return 0;
}

static ULONG WINAPI EventSetInformation(HANDLE RegistrationHandle,
                                        ULONG InformationClass,
                                        PVOID EventInformation,
                                        ULONG InformationLength)
{
    DebugLog("%p %u %p %u", RegistrationHandle, InformationClass, EventInformation, InformationLength);
    return 0;
}

static BOOL WINAPI GetLogicalProcessorInformationEx(DWORD RelationshipType,
                                                    PVOID Buffer,
                                                    PDWORD ReturnedLength)
{
    DebugLog("%u %p %p", RelationshipType, Buffer, ReturnedLength);
    if (ReturnedLength) {
        *ReturnedLength = 0;
    }
    return FALSE;
}

static BOOL WINAPI GetProcessMitigationPolicy(HANDLE hProcess,
                                              DWORD MitigationPolicy,
                                              PVOID lpBuffer,
                                              SIZE_T dwLength)
{
    DebugLog("%p %u %p %zu", hProcess, MitigationPolicy, lpBuffer, dwLength);
    return FALSE;
}

static BOOL WINAPI ReadProcessMemory(HANDLE hProcess,
                                     PVOID lpBaseAddress,
                                     PVOID lpBuffer,
                                     SIZE_T nSize,
                                     SIZE_T *lpNumberOfBytesRead)
{
    DebugLog("%p %p %p %zu %p", hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    if (lpNumberOfBytesRead) {
        *lpNumberOfBytesRead = 0;
    }
    return FALSE;
}

static BOOL WINAPI SetProcessInformation(HANDLE hProcess,
                                         DWORD ProcessInformationClass,
                                         PVOID ProcessInformation,
                                         DWORD ProcessInformationSize)
{
    DebugLog("%p %u %p %u", hProcess, ProcessInformationClass, ProcessInformation, ProcessInformationSize);
    return FALSE;
}

static VOID WINAPI ExitProcess(UINT uExitCode)
{
    DebugLog("%u", uExitCode);
}

static VOID WINAPI CorExitProcess(UINT uExitCode)
{
    DebugLog("%u", uExitCode);
}

LPTOP_LEVEL_EXCEPTION_FILTER WINAPI SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER Filter)
{
    LPTOP_LEVEL_EXCEPTION_FILTER OldFilter = g_top_level_exception_filter;
    g_top_level_exception_filter = Filter;
    DebugLog("%p", Filter);
    return OldFilter;
}

LONG WINAPI UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{
    DebugLog("%p", ExceptionInfo);
    if (g_top_level_exception_filter) {
        return g_top_level_exception_filter(ExceptionInfo);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static DWORD WINAPI WldpQueryWindowsLockdownMode(PDWORD lockdown_mode)
{
    DebugLog("%p", lockdown_mode);
    if (lockdown_mode) {
        *lockdown_mode = 0;
    }
    return 0;
}

static HRESULT WINAPI WofSetFileDataLocation(HANDLE hFile,
                                             PVOID ExternalInfo,
                                             DWORD ExternalInfoLength,
                                             PVOID DataSourceInfo,
                                             DWORD DataSourceInfoLength)
{
    DebugLog("%p %p %u %p %u", hFile, ExternalInfo, ExternalInfoLength, DataSourceInfo, DataSourceInfoLength);
    return 0;
}

static HRESULT WINAPI WofShouldCompressBinaries(PBOOL ShouldCompress)
{
    DebugLog("%p", ShouldCompress);
    if (ShouldCompress) {
        *ShouldCompress = FALSE;
    }
    return 0;
}

static LONG WINAPI AppPolicyGetProcessTerminationMethod(HANDLE Process,
                                                        PVOID Policy)
{
    DebugLog("%p %p", Process, Policy);
    if (Policy) {
        *(DWORD *)Policy = 0;
    }
    return 0;
}

static DWORD WINAPI PowerSettingRegisterNotification(PVOID SettingGuid,
                                                     DWORD Flags,
                                                     HANDLE Recipient,
                                                     PVOID *NotificationHandle)
{
    DebugLog("%p %#x %p %p", SettingGuid, Flags, Recipient, NotificationHandle);
    if (NotificationHandle) {
        *NotificationHandle = (HANDLE) 'PWRN';
    }
    return 0;
}

static DWORD WINAPI PowerSettingUnregisterNotification(PVOID NotificationHandle)
{
    DebugLog("%p", NotificationHandle);
    return 0;
}

static ULONG WINAPI TraceMessage(HANDLE SessionHandle,
                                 ULONG MessageFlags,
                                 LPGUID MessageGuid,
                                 USHORT MessageNumber,
                                 ...)
{
    DebugLog("%p %u %p %u", SessionHandle, MessageFlags, MessageGuid, MessageNumber);
    return 0;
}

static long WINAPI EventRegister(PVOID ProviderId,
                                 PVOID EnableCallback,
                                 PVOID CallbackContext,
                                 HANDLE RegHandle)
{
    DebugLog("%p %p %p %p", ProviderId, EnableCallback, CallbackContext, RegHandle);
    return 0;
}

static BOOL WINAPI InitializeSecurityDescriptor(PVOID pSecurityDescriptor, DWORD dwRevision)
{
    DebugLog("%p %u", pSecurityDescriptor, dwRevision);
    return TRUE;
}

static BOOL WINAPI SetSecurityDescriptorDacl(PVOID pSecurityDescriptor,
                                             BOOL bDaclPresent,
                                             PVOID pDacl,
                                             BOOL bDaclDefaulted)
{
    DebugLog("%p %d %p %d", pSecurityDescriptor, bDaclPresent, pDacl, bDaclDefaulted);
    return TRUE;
}

static DWORD WINAPI RegGetValueA(PVOID hkey,
                                 LPCSTR lpSubKey,
                                 LPCSTR lpValue,
                                 DWORD dwFlags,
                                 LPDWORD pdwType,
                                 PVOID pvData,
                                 LPDWORD pcbData)
{
    const char *prod_name = "Windows Server 2022 Standard";
    size_t prod_name_len = strlen(prod_name);

    DebugLog("%p %p %p %u %p %p %p", hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);

    if (pvData && lpValue && pcbData && strcmp(lpValue, "CurrentVersion") == 0 && *pcbData >= 4) {
        strcpy(pvData, "6.3");
        *pcbData = 4;
        return 0;
    }

    if (pvData && lpValue && pcbData && strcmp(lpValue, "ProductName") == 0 && *pcbData >= prod_name_len) {
        strcpy(pvData, prod_name);
        *pcbData = (DWORD)prod_name_len;
        return 0;
    }

    return 1;
}

typedef struct _JOBOBJECT_BASIC_LIMIT_INFORMATION {
    LARGE_INTEGER PerProcessUserTimeLimit;
    LARGE_INTEGER PerJobUserTimeLimit;
    DWORD         LimitFlags;
    SIZE_T        MinimumWorkingSetSize;
    SIZE_T        MaximumWorkingSetSize;
    DWORD         ActiveProcessLimit;
    ULONG_PTR     Affinity;
    DWORD         PriorityClass;
    DWORD         SchedulingClass;
} JOBOBJECT_BASIC_LIMIT_INFORMATION, *PJOBOBJECT_BASIC_LIMIT_INFORMATION;

typedef struct _IO_COUNTERS {
    ULONGLONG ReadOperationCount;
    ULONGLONG WriteOperationCount;
    ULONGLONG OtherOperationCount;
    ULONGLONG ReadTransferCount;
    ULONGLONG WriteTransferCount;
    ULONGLONG OtherTransferCount;
} IO_COUNTERS;

typedef struct _JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
    IO_COUNTERS                       IoInfo;
    SIZE_T                            ProcessMemoryLimit;
    SIZE_T                            JobMemoryLimit;
    SIZE_T                            PeakProcessMemoryUsed;
    SIZE_T                            PeakJobMemoryUsed;
} JOBOBJECT_EXTENDED_LIMIT_INFORMATION, *PJOBOBJECT_EXTENDED_LIMIT_INFORMATION;

static BOOL WINAPI QueryInformationJobObject(HANDLE hJob,
                                             DWORD JobObjectInformationClass,
                                             LPVOID lpJobObjectInformation,
                                             DWORD cbJobObjectInformationLength,
                                             LPDWORD lpReturnLength)
{
    DebugLog("%p %u %p %u %p",
             hJob, JobObjectInformationClass, lpJobObjectInformation,
             cbJobObjectInformationLength, lpReturnLength);

    if (JobObjectInformationClass == 9 && lpJobObjectInformation) {
        PJOBOBJECT_EXTENDED_LIMIT_INFORMATION info =
            (PJOBOBJECT_EXTENDED_LIMIT_INFORMATION)lpJobObjectInformation;
        info->BasicLimitInformation.LimitFlags = 0;
        info->PeakProcessMemoryUsed = 0x41;
        info->PeakJobMemoryUsed = 0x41;
    }

    return TRUE;
}

DECLARE_CRT_EXPORT("QueryInformationJobObject", QueryInformationJobObject);
DECLARE_CRT_EXPORT("RegGetValueA", RegGetValueA);
DECLARE_CRT_EXPORT("SetSecurityDescriptorDacl", SetSecurityDescriptorDacl);
DECLARE_CRT_EXPORT("InitializeSecurityDescriptor", InitializeSecurityDescriptor);
DECLARE_CRT_EXPORT("AreFileApisANSI", AreFileApisANSI);
DECLARE_CRT_EXPORT("CompareStringEx", CompareStringEx);
DECLARE_CRT_EXPORT("GetTempPath2W", GetTempPath2W);
DECLARE_CRT_EXPORT("EnumSystemLocalesEx", EnumSystemLocalesEx);
DECLARE_CRT_EXPORT("GetDateFormatEx", GetDateFormatEx);
DECLARE_CRT_EXPORT("GetTimeFormatEx", GetTimeFormatEx);
DECLARE_CRT_EXPORT("GetUserDefaultLocaleName", GetUserDefaultLocaleName);
DECLARE_CRT_EXPORT("IsValidLocaleName", IsValidLocaleName);
DECLARE_CRT_EXPORT("LCIDToLocaleName", LCIDToLocaleName);
DECLARE_CRT_EXPORT("CancelSynchronousIo", CancelSynchronousIo);
DECLARE_CRT_EXPORT("CreateSymbolicLinkW", CreateSymbolicLinkW);
DECLARE_CRT_EXPORT("DeleteProcThreadAttributeList", DeleteProcThreadAttributeList);
DECLARE_CRT_EXPORT("FindFirstFileNameW", FindFirstFileNameW);
DECLARE_CRT_EXPORT("FindNextFileNameW", FindNextFileNameW);
DECLARE_CRT_EXPORT("GetFileInformationByHandle", GetFileInformationByHandle);
DECLARE_CRT_EXPORT("GetFileInformationByHandleEx", GetFileInformationByHandleEx);
DECLARE_CRT_EXPORT("GetFinalPathNameByHandleW", GetFinalPathNameByHandleW);
DECLARE_CRT_EXPORT("GetFirmwareEnvironmentVariableA", GetFirmwareEnvironmentVariableA);
DECLARE_CRT_EXPORT("GetFirmwareEnvironmentVariableExW", GetFirmwareEnvironmentVariableExW);
DECLARE_CRT_EXPORT("GetFirmwareType", GetFirmwareType);
DECLARE_CRT_EXPORT("GetProcessInformation", GetProcessInformation);
DECLARE_CRT_EXPORT("GetThreadInformation", GetThreadInformation);
DECLARE_CRT_EXPORT("InitializeProcThreadAttributeList", InitializeProcThreadAttributeList);
DECLARE_CRT_EXPORT("K32EnumPageFilesW", K32EnumPageFilesW);
DECLARE_CRT_EXPORT("K32EnumProcessModules", K32EnumProcessModules);
DECLARE_CRT_EXPORT("K32EnumProcesses", K32EnumProcesses);
DECLARE_CRT_EXPORT("K32GetMappedFileNameW", K32GetMappedFileNameW);
DECLARE_CRT_EXPORT("K32GetModuleBaseNameW", K32GetModuleBaseNameW);
DECLARE_CRT_EXPORT("K32GetModuleFileNameExW", K32GetModuleFileNameExW);
DECLARE_CRT_EXPORT("K32GetModuleInformation", K32GetModuleInformation);
DECLARE_CRT_EXPORT("K32GetProcessImageFileNameW", K32GetProcessImageFileNameW);
DECLARE_CRT_EXPORT("K32GetProcessMemoryInfo", K32GetProcessMemoryInfo);
DECLARE_CRT_EXPORT("K32QueryWorkingSetEx", K32QueryWorkingSetEx);
DECLARE_CRT_EXPORT("PrefetchVirtualMemory", PrefetchVirtualMemory);
DECLARE_CRT_EXPORT("SetThreadInformation", SetThreadInformation);
DECLARE_CRT_EXPORT("TryAcquireSRWLockExclusive", TryAcquireSRWLockExclusive);
DECLARE_CRT_EXPORT("UpdateProcThreadAttribute", UpdateProcThreadAttribute);
DECLARE_CRT_EXPORT("EventRegister", EventRegister);
DECLARE_CRT_EXPORT("EventSetInformation", EventSetInformation);
DECLARE_CRT_EXPORT("EventWriteTransfer", EventWriteTransfer);
DECLARE_CRT_EXPORT("TraceMessage", TraceMessage);
DECLARE_CRT_EXPORT("NotifyServiceStatusChangeW", NotifyServiceStatusChangeW);
DECLARE_CRT_EXPORT("RegDisableReflectionKey", RegDisableReflectionKey);
DECLARE_CRT_EXPORT("RegEnableReflectionKey", RegEnableReflectionKey);
DECLARE_CRT_EXPORT("RegQueryReflectionKey", RegQueryReflectionKey);
DECLARE_CRT_EXPORT("GetLogicalProcessorInformationEx", GetLogicalProcessorInformationEx);
DECLARE_CRT_EXPORT("GetProcessMitigationPolicy", GetProcessMitigationPolicy);
DECLARE_CRT_EXPORT("ReadProcessMemory", ReadProcessMemory);
DECLARE_CRT_EXPORT("SetProcessInformation", SetProcessInformation);
DECLARE_CRT_EXPORT("ExitProcess", ExitProcess);
DECLARE_CRT_EXPORT("CorExitProcess", CorExitProcess);
DECLARE_CRT_EXPORT("SetUnhandledExceptionFilter", SetUnhandledExceptionFilter);
DECLARE_CRT_EXPORT("UnhandledExceptionFilter", UnhandledExceptionFilter);
DECLARE_CRT_EXPORT("WldpQueryWindowsLockdownMode", WldpQueryWindowsLockdownMode);
DECLARE_CRT_EXPORT("WofSetFileDataLocation", WofSetFileDataLocation);
DECLARE_CRT_EXPORT("WofShouldCompressBinaries", WofShouldCompressBinaries);
DECLARE_CRT_EXPORT("AppPolicyGetProcessTerminationMethod", AppPolicyGetProcessTerminationMethod);
DECLARE_CRT_EXPORT("NdrClientCall3", NdrClientCall3);
DECLARE_CRT_EXPORT("NdrServerCall2", NdrServerCall2);
DECLARE_CRT_EXPORT("RpcBindingBind", RpcBindingBind);
DECLARE_CRT_EXPORT("RpcBindingCreateW", RpcBindingCreateW);
DECLARE_CRT_EXPORT("RpcBindingFree", RpcBindingFree);
DECLARE_CRT_EXPORT("RpcBindingVectorFree", RpcBindingVectorFree);
DECLARE_CRT_EXPORT("RpcEpRegisterW", RpcEpRegisterW);
DECLARE_CRT_EXPORT("RpcEpUnregister", RpcEpUnregister);
DECLARE_CRT_EXPORT("RpcServerInqBindings", RpcServerInqBindings);
DECLARE_CRT_EXPORT("RpcServerListen", RpcServerListen);
DECLARE_CRT_EXPORT("RpcServerRegisterIf3", RpcServerRegisterIf3);
DECLARE_CRT_EXPORT("RpcServerUnregisterIfEx", RpcServerUnregisterIfEx);
DECLARE_CRT_EXPORT("RpcServerUseProtseqEpW", RpcServerUseProtseqEpW);
DECLARE_CRT_EXPORT("RpcObjectSetType", RpcObjectSetType);
DECLARE_CRT_EXPORT("MpCleanupServer", MpCleanupServer);
DECLARE_CRT_EXPORT("MpInitServer", MpInitServer);
DECLARE_CRT_EXPORT("PowerSettingRegisterNotification", PowerSettingRegisterNotification);
DECLARE_CRT_EXPORT("PowerSettingUnregisterNotification", PowerSettingUnregisterNotification);
