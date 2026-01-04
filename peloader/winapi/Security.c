#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <stdlib.h>
#include <wchar.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_HANDLE 6
#define ERROR_INVALID_PARAMETER 87
#define ERROR_CALL_NOT_IMPLEMENTED 120
#define ERROR_INSUFFICIENT_BUFFER 122
#define ERROR_INVALID_SID 1337
#define ERROR_SERVICE_DOES_NOT_EXIST 1060

typedef struct _SID_IDENTIFIER_AUTHORITY {
    BYTE Value[6];
} SID_IDENTIFIER_AUTHORITY, *PSID_IDENTIFIER_AUTHORITY;

typedef struct _SID {
    BYTE Revision;
    BYTE SubAuthorityCount;
    SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
    DWORD SubAuthority[1];
} SID, *PISID;

typedef struct _SECURITY_ATTRIBUTES {
    DWORD nLength;
    PVOID lpSecurityDescriptor;
    BOOL bInheritHandle;
} SECURITY_ATTRIBUTES, *LPSECURITY_ATTRIBUTES;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD dwProcessId;
    DWORD dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef struct _SERVICE_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SERVICE_STATUS, *LPSERVICE_STATUS;

typedef struct _SERVICE_STATUS_PROCESS {
    SERVICE_STATUS ServiceStatus;
    DWORD dwProcessId;
    DWORD dwServiceFlags;
} SERVICE_STATUS_PROCESS, *LPSERVICE_STATUS_PROCESS;

extern void WINAPI SetLastError(DWORD dwErrCode);

BOOL WINAPI LookupPrivilegeValueW(PVOID lpSystemName, PVOID lpName, PVOID lpLuid)
{
    DebugLog("%p, %p, %p", lpSystemName, lpName, lpLuid);

    if (lpLuid) {
        memset(lpLuid, 0, sizeof(uint64_t));
    }

    return TRUE;
}

BOOL WINAPI GetTokenInformation(HANDLE TokenHandle,
                                DWORD TokenInformationClass,
                                PVOID TokenInformation,
                                DWORD TokenInformationLength,
                                PDWORD ReturnLength)
{
    DebugLog("%p, %u, %p, %u, %p",
             TokenHandle, TokenInformationClass, TokenInformation,
             TokenInformationLength, ReturnLength);

    if (!TokenInformation || TokenInformationLength == 0) {
        if (ReturnLength) {
            *ReturnLength = sizeof(DWORD);
        }
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    memset(TokenInformation, 0, TokenInformationLength);
    if (ReturnLength) {
        *ReturnLength = TokenInformationLength;
    }
    return TRUE;
}

BOOL WINAPI OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)
{
    DebugLog("%p, %#x, %p", ProcessHandle, DesiredAccess, TokenHandle);

    if (TokenHandle) {
        *TokenHandle = (HANDLE) 'TOKN';
    }

    return TRUE;
}

BOOL WINAPI CheckTokenMembership(HANDLE TokenHandle, PVOID SidToCheck, PBOOL IsMember)
{
    DebugLog("%p, %p, %p", TokenHandle, SidToCheck, IsMember);

    if (IsMember) {
        *IsMember = FALSE;
    }

    return TRUE;
}

BOOL WINAPI CreateRestrictedToken(HANDLE ExistingTokenHandle,
                                  DWORD Flags,
                                  DWORD DisableSidCount,
                                  PVOID SidsToDisable,
                                  DWORD DeletePrivilegeCount,
                                  PVOID PrivilegesToDelete,
                                  DWORD RestrictedSidCount,
                                  PVOID SidsToRestrict,
                                  PHANDLE NewTokenHandle)
{
    DebugLog("%p, %#x, %u, %p, %u, %p, %u, %p, %p",
             ExistingTokenHandle, Flags, DisableSidCount, SidsToDisable,
             DeletePrivilegeCount, PrivilegesToDelete, RestrictedSidCount,
             SidsToRestrict, NewTokenHandle);

    if (NewTokenHandle) {
        *NewTokenHandle = ExistingTokenHandle ? ExistingTokenHandle : (HANDLE) 'TOKR';
    }

    SetLastError(0);
    return TRUE;
}

BOOL WINAPI DuplicateToken(HANDLE ExistingTokenHandle, DWORD ImpersonationLevel, PHANDLE DuplicateTokenHandle)
{
    DebugLog("%p, %u, %p", ExistingTokenHandle, ImpersonationLevel, DuplicateTokenHandle);

    if (DuplicateTokenHandle) {
        *DuplicateTokenHandle = ExistingTokenHandle ? ExistingTokenHandle : (HANDLE) 'TOK2';
    }

    return TRUE;
}

BOOL WINAPI AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                                     BYTE nSubAuthorityCount,
                                     DWORD nSubAuthority0,
                                     DWORD nSubAuthority1,
                                     DWORD nSubAuthority2,
                                     DWORD nSubAuthority3,
                                     DWORD nSubAuthority4,
                                     DWORD nSubAuthority5,
                                     DWORD nSubAuthority6,
                                     DWORD nSubAuthority7,
                                     PVOID *pSid)
{
    DebugLog("%p, %u, %u, %u, %u, %u, %u, %u, %u, %u, %p",
             pIdentifierAuthority, nSubAuthorityCount, nSubAuthority0, nSubAuthority1,
             nSubAuthority2, nSubAuthority3, nSubAuthority4, nSubAuthority5,
             nSubAuthority6, nSubAuthority7, pSid);

    if (!pSid) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *pSid = NULL;
    if (nSubAuthorityCount > 8) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    size_t sid_size = sizeof(SID);
    if (nSubAuthorityCount > 0) {
        sid_size += (size_t)(nSubAuthorityCount - 1) * sizeof(DWORD);
    }

    PISID sid = calloc(1, sid_size);
    if (!sid) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    sid->Revision = 1;
    sid->SubAuthorityCount = nSubAuthorityCount;
    if (pIdentifierAuthority) {
        memcpy(&sid->IdentifierAuthority, pIdentifierAuthority, sizeof(SID_IDENTIFIER_AUTHORITY));
    }

    DWORD subs[8] = {
        nSubAuthority0,
        nSubAuthority1,
        nSubAuthority2,
        nSubAuthority3,
        nSubAuthority4,
        nSubAuthority5,
        nSubAuthority6,
        nSubAuthority7
    };

    for (BYTE i = 0; i < nSubAuthorityCount; ++i) {
        sid->SubAuthority[i] = subs[i];
    }

    *pSid = sid;
    SetLastError(0);
    return TRUE;
}

BOOL WINAPI AdjustTokenPrivileges(HANDLE TokenHandle,
                                  BOOL DisableAllPrivileges,
                                  PVOID NewState,
                                  DWORD BufferLength,
                                  PVOID PreviousState,
                                  PDWORD ReturnLength)
{
    DebugLog("%p, %u, %p, %u, %p, %p",
             TokenHandle, DisableAllPrivileges, NewState,
             BufferLength, PreviousState, ReturnLength);

    if (ReturnLength) {
        *ReturnLength = 0;
    }

    return TRUE;
}

BOOL WINAPI CreateProcessAsUserW(HANDLE hToken,
                                 PWCHAR lpApplicationName,
                                 PWCHAR lpCommandLine,
                                 LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                 LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                 BOOL bInheritHandles,
                                 DWORD dwCreationFlags,
                                 PVOID lpEnvironment,
                                 PWCHAR lpCurrentDirectory,
                                 PVOID lpStartupInfo,
                                 LPPROCESS_INFORMATION lpProcessInformation)
{
    DebugLog("%p, %p, %p, %p, %p, %u, %#x, %p, %p, %p, %p",
             hToken, lpApplicationName, lpCommandLine, lpProcessAttributes,
             lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
             lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (lpProcessInformation) {
        memset(lpProcessInformation, 0, sizeof(*lpProcessInformation));
        lpProcessInformation->hProcess = (HANDLE) 'PROC';
        lpProcessInformation->hThread = (HANDLE) 'THRD';
        lpProcessInformation->dwProcessId = (DWORD)getpid();
        lpProcessInformation->dwThreadId = (DWORD)getpid();
    }

    SetLastError(0);
    return TRUE;
}

BOOL WINAPI ConvertStringSecurityDescriptorToSecurityDescriptorW(PWCHAR StringSecurityDescriptor,
                                                                 DWORD StringSDRevision,
                                                                 PVOID *SecurityDescriptor,
                                                                 PDWORD SecurityDescriptorSize)
{
    DebugLog("%p, %#x, %p, %p",
             StringSecurityDescriptor, StringSDRevision, SecurityDescriptor, SecurityDescriptorSize);

    if (SecurityDescriptor) {
        *SecurityDescriptor = NULL;
    }
    if (SecurityDescriptorSize) {
        *SecurityDescriptorSize = 0;
    }

    return TRUE;
}

BOOL WINAPI ConvertStringSidToSidW(PWCHAR StringSid, PVOID *Sid)
{
    DebugLog("%p, %p", StringSid, Sid);

    PISID out_sid = NULL;
    size_t sid_size = 0;

    if (!Sid) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *Sid = NULL;
    if (!StringSid || !StringSid[0]) {
        SetLastError(ERROR_INVALID_SID);
        return FALSE;
    }

    if (StringSid[0] != L'S' || StringSid[1] != L'-') {
        SetLastError(ERROR_INVALID_SID);
        return FALSE;
    }

    const wchar_t *cursor = StringSid + 2;
    wchar_t *end = NULL;
    unsigned long revision = wcstoul(cursor, &end, 10);
    if (end == cursor || *end != L'-') {
        goto fallback_sid;
    }

    cursor = end + 1;
    unsigned long long ident_auth = wcstoull(cursor, &end, 0);
    if (end == cursor) {
        goto fallback_sid;
    }

    DWORD subauths[15];
    size_t subauth_count = 0;
    if (*end == L'-') {
        cursor = end + 1;
        while (*cursor && subauth_count < (sizeof(subauths) / sizeof(subauths[0]))) {
            unsigned long val = wcstoul(cursor, &end, 0);
            if (end == cursor) {
                break;
            }
            subauths[subauth_count++] = (DWORD)val;
            if (*end == L'-') {
                cursor = end + 1;
                continue;
            }
            if (*end == L'\0') {
                break;
            }
            break;
        }
    }

    if (subauth_count == 0) {
        goto fallback_sid;
    }

    sid_size = sizeof(SID) + sizeof(DWORD) * (subauth_count - 1);
    out_sid = malloc(sid_size);
    if (!out_sid) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    memset(out_sid, 0, sid_size);
    out_sid->Revision = (BYTE)revision;
    out_sid->SubAuthorityCount = (BYTE)subauth_count;
    for (int i = 0; i < 6; i++) {
        out_sid->IdentifierAuthority.Value[5 - i] = (BYTE)(ident_auth & 0xff);
        ident_auth >>= 8;
    }
    for (size_t i = 0; i < subauth_count; i++) {
        out_sid->SubAuthority[i] = subauths[i];
    }

    *Sid = out_sid;
    SetLastError(0);
    return TRUE;

fallback_sid:;
    sid_size = sizeof(SID);
    out_sid = malloc(sid_size);
    if (!out_sid) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    memset(out_sid, 0, sid_size);
    out_sid->Revision = 1;
    out_sid->SubAuthorityCount = 1;
    out_sid->IdentifierAuthority.Value[5] = 5;
    out_sid->SubAuthority[0] = 18;
    *Sid = out_sid;
    SetLastError(0);
    return TRUE;
}

BOOL WINAPI ConvertSidToStringSidW(PVOID Sid, PWCHAR *StringSid)
{
    DebugLog("%p, %p", Sid, StringSid);

    if (!StringSid) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *StringSid = NULL;
    if (!Sid) {
        SetLastError(ERROR_INVALID_SID);
        return FALSE;
    }

    PISID sid = (PISID)Sid;
    unsigned long long ident_auth = 0;
    for (int i = 0; i < 6; i++) {
        ident_auth = (ident_auth << 8) | sid->IdentifierAuthority.Value[i];
    }

    char tmp[256];
    int len = snprintf(tmp, sizeof(tmp), "S-%u-%llu", sid->Revision, ident_auth);
    if (len < 0 || (size_t)len >= sizeof(tmp)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    for (int i = 0; i < sid->SubAuthorityCount && i < 15; i++) {
        int used = snprintf(tmp + len, sizeof(tmp) - (size_t)len, "-%u", sid->SubAuthority[i]);
        if (used < 0 || (size_t)used >= (sizeof(tmp) - (size_t)len)) {
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        len += used;
    }

    size_t out_len = strlen(tmp);
    PWCHAR out = calloc(out_len + 1, sizeof(WCHAR));
    if (!out) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    for (size_t i = 0; i < out_len; ++i) {
        out[i] = (unsigned char)tmp[i];
    }
    out[out_len] = L'\0';
    *StringSid = out;
    SetLastError(0);
    return TRUE;
}

PVOID WINAPI FreeSid(PVOID pSid)
{
    DebugLog("%p", pSid);

    if (!pSid || (uintptr_t)pSid < 0x10000) {
        return NULL;
    }

    free(pSid);
    return NULL;
}

BOOL WINAPI GetFileSecurityW(PWCHAR lpFileName,
                             DWORD RequestedInformation,
                             PVOID pSecurityDescriptor,
                             DWORD nLength,
                             PDWORD lpnLengthNeeded)
{
    DebugLog("%p %u %p %u %p", lpFileName, RequestedInformation, pSecurityDescriptor, nLength, lpnLengthNeeded);

    if (lpnLengthNeeded) {
        *lpnLengthNeeded = nLength;
    }

    if (!pSecurityDescriptor || nLength == 0) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    memset(pSecurityDescriptor, 0, nLength);
    SetLastError(0);
    return TRUE;
}

DWORD WINAPI GetSecurityInfo(HANDLE handle,
                             DWORD ObjectType,
                             DWORD SecurityInfo,
                             PVOID *ppsidOwner,
                             PVOID *ppsidGroup,
                             PVOID *ppDacl,
                             PVOID *ppSacl,
                             PVOID *ppSecurityDescriptor)
{
    DebugLog("%p, %#x, %#x, %p, %p, %p, %p, %p",
             handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor);

    if (ppsidOwner) {
        *ppsidOwner = NULL;
    }
    if (ppsidGroup) {
        *ppsidGroup = NULL;
    }
    if (ppDacl) {
        *ppDacl = NULL;
    }
    if (ppSacl) {
        *ppSacl = NULL;
    }
    if (ppSecurityDescriptor) {
        *ppSecurityDescriptor = calloc(1, 1);
        if (!*ppSecurityDescriptor) {
            return ERROR_INSUFFICIENT_BUFFER;
        }
    }

    return 0;
}

DWORD WINAPI SetSecurityInfo(HANDLE handle,
                             DWORD ObjectType,
                             DWORD SecurityInfo,
                             PVOID ppsidOwner,
                             PVOID ppsidGroup,
                             PVOID pDacl,
                             PVOID pSacl)
{
    DebugLog("%p, %#x, %#x, %p, %p, %p, %p",
             handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, pDacl, pSacl);
    return 0;
}

BOOL WINAPI GetSecurityDescriptorDacl(PVOID pSecurityDescriptor,
                                      PBOOL lpbDaclPresent,
                                      PVOID *pDacl,
                                      PBOOL lpbDaclDefaulted)
{
    DebugLog("%p %p %p %p", pSecurityDescriptor, lpbDaclPresent, pDacl, lpbDaclDefaulted);

    if (lpbDaclPresent) {
        *lpbDaclPresent = FALSE;
    }
    if (pDacl) {
        *pDacl = NULL;
    }
    if (lpbDaclDefaulted) {
        *lpbDaclDefaulted = FALSE;
    }
    SetLastError(0);
    return TRUE;
}

BOOL WINAPI GetSecurityDescriptorOwner(PVOID pSecurityDescriptor,
                                       PVOID *pOwner,
                                       PBOOL lpbOwnerDefaulted)
{
    DebugLog("%p %p %p", pSecurityDescriptor, pOwner, lpbOwnerDefaulted);

    if (pOwner) {
        *pOwner = NULL;
    }
    if (lpbOwnerDefaulted) {
        *lpbOwnerDefaulted = FALSE;
    }
    SetLastError(0);
    return TRUE;
}

BOOL WINAPI GetSecurityDescriptorGroup(PVOID pSecurityDescriptor,
                                       PVOID *pGroup,
                                       PBOOL lpbGroupDefaulted)
{
    DebugLog("%p %p %p", pSecurityDescriptor, pGroup, lpbGroupDefaulted);

    if (pGroup) {
        *pGroup = NULL;
    }
    if (lpbGroupDefaulted) {
        *lpbGroupDefaulted = FALSE;
    }
    SetLastError(0);
    return TRUE;
}

DWORD WINAPI GetLengthSid(PVOID pSid)
{
    DebugLog("%p", pSid);

    if (!pSid) {
        return 0;
    }

    PISID sid = (PISID)pSid;
    return (DWORD)(sizeof(SID) + sizeof(DWORD) * (sid->SubAuthorityCount ? (sid->SubAuthorityCount - 1) : 0));
}

BOOL WINAPI CopySid(DWORD nDestinationSidLength, PVOID pDestinationSid, PVOID pSourceSid)
{
    DebugLog("%u %p %p", nDestinationSidLength, pDestinationSid, pSourceSid);

    if (!pDestinationSid || !pSourceSid) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    DWORD needed = GetLengthSid(pSourceSid);
    if (nDestinationSidLength < needed) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    memcpy(pDestinationSid, pSourceSid, needed);
    SetLastError(0);
    return TRUE;
}

DWORD WINAPI SetEntriesInAclW(DWORD cCountOfExplicitEntries,
                              PVOID pListOfExplicitEntries,
                              PVOID OldAcl,
                              PVOID *NewAcl)
{
    DebugLog("%u %p %p %p", cCountOfExplicitEntries, pListOfExplicitEntries, OldAcl, NewAcl);

    if (NewAcl) {
        *NewAcl = NULL;
    }
    SetLastError(0);
    return 0;
}

BOOL WINAPI SetFileSecurityW(PWCHAR lpFileName,
                             DWORD SecurityInformation,
                             PVOID pSecurityDescriptor)
{
    DebugLog("%p %u %p", lpFileName, SecurityInformation, pSecurityDescriptor);
    SetLastError(0);
    return TRUE;
}

LONG WINAPI CreateAppContainerProfile(PWCHAR pszAppContainerName,
                                      PWCHAR pszDisplayName,
                                      PWCHAR pszDescription,
                                      PVOID pCapabilities,
                                      DWORD dwCapabilityCount,
                                      PVOID *ppsidAppContainerSid)
{
    DebugLog("%p, %p, %p, %p, %u, %p",
             pszAppContainerName, pszDisplayName, pszDescription,
             pCapabilities, dwCapabilityCount, ppsidAppContainerSid);

    if (ppsidAppContainerSid) {
        ConvertStringSidToSidW(L"S-1-15-2-1", ppsidAppContainerSid);
    }
    SetLastError(0);
    return 0;
}

LONG WINAPI DeleteAppContainerProfile(PWCHAR pszAppContainerName)
{
    DebugLog("%p", pszAppContainerName);
    SetLastError(0);
    return 0;
}

LONG WINAPI DeriveAppContainerSidFromAppContainerName(PWCHAR pszAppContainerName,
                                                      PVOID *ppsidAppContainerSid)
{
    DebugLog("%p, %p", pszAppContainerName, ppsidAppContainerSid);

    if (ppsidAppContainerSid) {
        ConvertStringSidToSidW(L"S-1-15-2-1", ppsidAppContainerSid);
    }
    SetLastError(0);
    return 0;
}

HANDLE WINAPI OpenSCManagerW(PWCHAR lpMachineName,
                             PWCHAR lpDatabaseName,
                             DWORD dwDesiredAccess)
{
    DebugLog("%p, %p, %#x", lpMachineName, lpDatabaseName, dwDesiredAccess);
    SetLastError(ERROR_ACCESS_DENIED);
    return NULL;
}

HANDLE WINAPI OpenServiceW(HANDLE hSCManager,
                           PWCHAR lpServiceName,
                           DWORD dwDesiredAccess)
{
    DebugLog("%p, %p, %#x", hSCManager, lpServiceName, dwDesiredAccess);
    SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
    return NULL;
}

BOOL WINAPI CloseServiceHandle(HANDLE hSCObject)
{
    DebugLog("%p", hSCObject);
    SetLastError(0);
    return TRUE;
}

BOOL WINAPI QueryServiceStatus(HANDLE hService, LPSERVICE_STATUS lpServiceStatus)
{
    DebugLog("%p, %p", hService, lpServiceStatus);
    if (!hService) {
        SetLastError(ERROR_INVALID_HANDLE);
    } else {
        SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    }
    if (lpServiceStatus) {
        memset(lpServiceStatus, 0, sizeof(*lpServiceStatus));
    }
    return FALSE;
}

BOOL WINAPI QueryServiceStatusEx(HANDLE hService,
                                 DWORD InfoLevel,
                                 PVOID lpBuffer,
                                 DWORD cbBufSize,
                                 PDWORD pcbBytesNeeded)
{
    DebugLog("%p, %u, %p, %u, %p", hService, InfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);
    if (pcbBytesNeeded) {
        *pcbBytesNeeded = sizeof(SERVICE_STATUS_PROCESS);
    }
    if (lpBuffer && cbBufSize >= sizeof(SERVICE_STATUS_PROCESS)) {
        memset(lpBuffer, 0, sizeof(SERVICE_STATUS_PROCESS));
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI QueryServiceConfigW(HANDLE hService,
                                PVOID lpServiceConfig,
                                DWORD cbBufSize,
                                PDWORD pcbBytesNeeded)
{
    DebugLog("%p, %p, %u, %p", hService, lpServiceConfig, cbBufSize, pcbBytesNeeded);
    if (pcbBytesNeeded) {
        *pcbBytesNeeded = 0;
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI QueryServiceConfig2W(HANDLE hService,
                                 DWORD dwInfoLevel,
                                 PVOID lpBuffer,
                                 DWORD cbBufSize,
                                 PDWORD pcbBytesNeeded)
{
    DebugLog("%p, %#x, %p, %u, %p", hService, dwInfoLevel, lpBuffer, cbBufSize, pcbBytesNeeded);
    if (pcbBytesNeeded) {
        *pcbBytesNeeded = 0;
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI EnumServicesStatusExW(HANDLE hSCManager,
                                  DWORD InfoLevel,
                                  DWORD dwServiceType,
                                  DWORD dwServiceState,
                                  PVOID lpServices,
                                  DWORD cbBufSize,
                                  PDWORD pcbBytesNeeded,
                                  PDWORD lpServicesReturned,
                                  PDWORD lpResumeHandle,
                                  PWCHAR pszGroupName)
{
    DebugLog("%p, %#x, %#x, %#x, %p, %u, %p, %p, %p, %p",
             hSCManager, InfoLevel, dwServiceType, dwServiceState, lpServices,
             cbBufSize, pcbBytesNeeded, lpServicesReturned, lpResumeHandle, pszGroupName);
    if (pcbBytesNeeded) {
        *pcbBytesNeeded = 0;
    }
    if (lpServicesReturned) {
        *lpServicesReturned = 0;
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI EnumDependentServicesW(HANDLE hService,
                                   DWORD dwServiceState,
                                   PVOID lpServices,
                                   DWORD cbBufSize,
                                   PDWORD pcbBytesNeeded,
                                   PDWORD lpServicesReturned)
{
    DebugLog("%p, %#x, %p, %u, %p, %p",
             hService, dwServiceState, lpServices, cbBufSize, pcbBytesNeeded, lpServicesReturned);
    if (pcbBytesNeeded) {
        *pcbBytesNeeded = 0;
    }
    if (lpServicesReturned) {
        *lpServicesReturned = 0;
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ControlService(HANDLE hService, DWORD dwControl, PVOID lpServiceStatus)
{
    DebugLog("%p, %#x, %p", hService, dwControl, lpServiceStatus);
    if (lpServiceStatus) {
        memset(lpServiceStatus, 0, sizeof(SERVICE_STATUS));
    }
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI StartServiceW(HANDLE hService, DWORD dwNumServiceArgs, PWCHAR *lpServiceArgVectors)
{
    DebugLog("%p, %u, %p", hService, dwNumServiceArgs, lpServiceArgVectors);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

HANDLE WINAPI CreateServiceW(HANDLE hSCManager,
                             PWCHAR lpServiceName,
                             PWCHAR lpDisplayName,
                             DWORD dwDesiredAccess,
                             DWORD dwServiceType,
                             DWORD dwStartType,
                             DWORD dwErrorControl,
                             PWCHAR lpBinaryPathName,
                             PWCHAR lpLoadOrderGroup,
                             PDWORD lpdwTagId,
                             PWCHAR lpDependencies,
                             PWCHAR lpServiceStartName,
                             PWCHAR lpPassword)
{
    DebugLog("%p, %p, %p, %#x", hSCManager, lpServiceName, lpDisplayName, dwDesiredAccess);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return NULL;
}

BOOL WINAPI DeleteService(HANDLE hService)
{
    DebugLog("%p", hService);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

BOOL WINAPI ChangeServiceConfig2W(HANDLE hService, DWORD dwInfoLevel, PVOID lpInfo)
{
    DebugLog("%p, %#x, %p", hService, dwInfoLevel, lpInfo);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return FALSE;
}

DECLARE_CRT_EXPORT("LookupPrivilegeValueW", LookupPrivilegeValueW);
DECLARE_CRT_EXPORT("GetTokenInformation", GetTokenInformation);
DECLARE_CRT_EXPORT("OpenProcessToken", OpenProcessToken);
DECLARE_CRT_EXPORT("CheckTokenMembership", CheckTokenMembership);
DECLARE_CRT_EXPORT("CreateRestrictedToken", CreateRestrictedToken);
DECLARE_CRT_EXPORT("DuplicateToken", DuplicateToken);
DECLARE_CRT_EXPORT("AllocateAndInitializeSid", AllocateAndInitializeSid);
DECLARE_CRT_EXPORT("AdjustTokenPrivileges", AdjustTokenPrivileges);
DECLARE_CRT_EXPORT("CreateProcessAsUserW", CreateProcessAsUserW);
DECLARE_CRT_EXPORT("ConvertStringSecurityDescriptorToSecurityDescriptorW", ConvertStringSecurityDescriptorToSecurityDescriptorW);
DECLARE_CRT_EXPORT("ConvertStringSidToSidW", ConvertStringSidToSidW);
DECLARE_CRT_EXPORT("ConvertSidToStringSidW", ConvertSidToStringSidW);
DECLARE_CRT_EXPORT("FreeSid", FreeSid);
DECLARE_CRT_EXPORT("GetFileSecurityW", GetFileSecurityW);
DECLARE_CRT_EXPORT("GetSecurityInfo", GetSecurityInfo);
DECLARE_CRT_EXPORT("GetSecurityDescriptorDacl", GetSecurityDescriptorDacl);
DECLARE_CRT_EXPORT("GetSecurityDescriptorOwner", GetSecurityDescriptorOwner);
DECLARE_CRT_EXPORT("GetSecurityDescriptorGroup", GetSecurityDescriptorGroup);
DECLARE_CRT_EXPORT("GetLengthSid", GetLengthSid);
DECLARE_CRT_EXPORT("CopySid", CopySid);
DECLARE_CRT_EXPORT("SetEntriesInAclW", SetEntriesInAclW);
DECLARE_CRT_EXPORT("SetSecurityInfo", SetSecurityInfo);
DECLARE_CRT_EXPORT("SetFileSecurityW", SetFileSecurityW);
DECLARE_CRT_EXPORT("CreateAppContainerProfile", CreateAppContainerProfile);
DECLARE_CRT_EXPORT("DeleteAppContainerProfile", DeleteAppContainerProfile);
DECLARE_CRT_EXPORT("DeriveAppContainerSidFromAppContainerName", DeriveAppContainerSidFromAppContainerName);
DECLARE_CRT_EXPORT("OpenSCManagerW", OpenSCManagerW);
DECLARE_CRT_EXPORT("OpenServiceW", OpenServiceW);
DECLARE_CRT_EXPORT("CloseServiceHandle", CloseServiceHandle);
DECLARE_CRT_EXPORT("QueryServiceStatus", QueryServiceStatus);
DECLARE_CRT_EXPORT("QueryServiceStatusEx", QueryServiceStatusEx);
DECLARE_CRT_EXPORT("QueryServiceConfigW", QueryServiceConfigW);
DECLARE_CRT_EXPORT("QueryServiceConfig2W", QueryServiceConfig2W);
DECLARE_CRT_EXPORT("EnumServicesStatusExW", EnumServicesStatusExW);
DECLARE_CRT_EXPORT("EnumDependentServicesW", EnumDependentServicesW);
DECLARE_CRT_EXPORT("ControlService", ControlService);
DECLARE_CRT_EXPORT("StartServiceW", StartServiceW);
DECLARE_CRT_EXPORT("CreateServiceW", CreateServiceW);
DECLARE_CRT_EXPORT("DeleteService", DeleteService);
DECLARE_CRT_EXPORT("ChangeServiceConfig2W", ChangeServiceConfig2W);
