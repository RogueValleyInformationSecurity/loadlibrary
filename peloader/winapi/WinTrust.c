#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <wchar.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

typedef struct _CATALOG_INFO {
    DWORD cbStruct;
    WCHAR wszCatalogFile[MAX_PATH];
} CATALOG_INFO, *PCATALOG_INFO;

typedef struct _CRYPT_PROVIDER_DATA {
    DWORD cbStruct;
} CRYPT_PROVIDER_DATA, *PCRYPT_PROVIDER_DATA;

typedef struct _CRYPT_PROVIDER_SGNR {
    DWORD cbStruct;
} CRYPT_PROVIDER_SGNR, *PCRYPT_PROVIDER_SGNR;

typedef struct _CRYPT_PROVIDER_CERT {
    DWORD cbStruct;
} CRYPT_PROVIDER_CERT, *PCRYPT_PROVIDER_CERT;

typedef struct _CRYPTCATATTRIBUTE {
    DWORD cbStruct;
} CRYPTCATATTRIBUTE, *PCRYPTCATATTRIBUTE;

typedef struct _CRYPTCATMEMBER {
    DWORD cbStruct;
} CRYPTCATMEMBER, *PCRYPTCATMEMBER;

STATIC WINAPI BOOL CryptCATAdminAcquireContext(HANDLE *phCatAdmin, PVOID pgSubsystem, DWORD dwFlags)
{
    DebugLog("%p, %p, %#x", phCatAdmin, pgSubsystem, dwFlags);
    if (phCatAdmin) {
        *phCatAdmin = (HANDLE) 'CAT0';
    }
    return TRUE;
}

STATIC WINAPI HANDLE CryptCATAdminEnumCatalogFromHash(HANDLE hCatAdmin, BYTE *pbHash, DWORD cbHash, DWORD dwFlags, HANDLE *phPrevCatInfo)
{
    DebugLog("%p, %p, %u, %#x, %p", hCatAdmin, pbHash, cbHash, dwFlags, phPrevCatInfo);
    if (phPrevCatInfo && *phPrevCatInfo) {
        return NULL;
    }
    return (HANDLE) 'CATI';
}

STATIC WINAPI BOOL CryptCATAdminCalcHashFromFileHandle(HANDLE hFile, DWORD *pcbHash, BYTE *pbHash, DWORD dwFlags)
{
    DebugLog("%p, %p, %p, %#x", hFile, pcbHash, pbHash, dwFlags);
    if (pcbHash) {
        *pcbHash = 32;
        if (pbHash) {
            memset(pbHash, 0, *pcbHash);
        }
    }
    return TRUE;
}

STATIC WINAPI BOOL CryptCATAdminReleaseCatalogContext(HANDLE hCatAdmin, HANDLE hCatInfo, DWORD dwFlags)
{
    DebugLog("%p, %p, %#x", hCatAdmin, hCatInfo, dwFlags);
    return TRUE;
}

STATIC WINAPI BOOL CryptCATAdminReleaseContext(HANDLE hCatAdmin, DWORD dwFlags)
{
    DebugLog("%p, %#x", hCatAdmin, dwFlags);
    return TRUE;
}

STATIC WINAPI BOOL CryptCATCatalogInfoFromContext(HANDLE hCatInfo, PCATALOG_INFO psCatInfo, DWORD dwFlags)
{
    DebugLog("%p, %p, %#x", hCatInfo, psCatInfo, dwFlags);
    if (psCatInfo) {
        psCatInfo->cbStruct = sizeof(*psCatInfo);
        psCatInfo->wszCatalogFile[0] = L'\0';
    }
    return TRUE;
}

STATIC WINAPI PCRYPT_PROVIDER_CERT WTHelperGetProvCertFromChain(PCRYPT_PROVIDER_SGNR pSgnr, DWORD idxCert)
{
    static CRYPT_PROVIDER_CERT dummy_cert = {0};
    DebugLog("%p, %u", pSgnr, idxCert);
    dummy_cert.cbStruct = sizeof(dummy_cert);
    return &dummy_cert;
}

STATIC WINAPI PCRYPT_PROVIDER_SGNR WTHelperGetProvSignerFromChain(PCRYPT_PROVIDER_DATA pProvData, DWORD idxSigner, BOOL fCounterSigner, DWORD idxCounterSigner)
{
    static CRYPT_PROVIDER_SGNR dummy_signer = {0};
    DebugLog("%p, %u, %u, %u", pProvData, idxSigner, fCounterSigner, idxCounterSigner);
    dummy_signer.cbStruct = sizeof(dummy_signer);
    return &dummy_signer;
}

STATIC WINAPI PCRYPT_PROVIDER_DATA WTHelperProvDataFromStateData(HANDLE hStateData)
{
    static CRYPT_PROVIDER_DATA dummy_data = {0};
    DebugLog("%p", hStateData);
    dummy_data.cbStruct = sizeof(dummy_data);
    return &dummy_data;
}

STATIC WINAPI LONG WinVerifyTrust(HANDLE hwnd, PVOID pgActionID, PVOID pWVTData)
{
    DebugLog("%p, %p, %p", hwnd, pgActionID, pWVTData);
    return 0;
}

STATIC WINAPI BOOL CryptCATAdminAcquireContext2(HANDLE *phCatAdmin,
                                                PVOID pgSubsystem,
                                                PWCHAR pwszHashAlgorithm,
                                                PVOID pStrongHashPolicy,
                                                DWORD dwFlags)
{
    DebugLog("%p, %p, %p, %p, %#x", phCatAdmin, pgSubsystem, pwszHashAlgorithm, pStrongHashPolicy, dwFlags);
    if (phCatAdmin) {
        *phCatAdmin = (HANDLE) 'CAT2';
    }
    return TRUE;
}

STATIC WINAPI HANDLE CryptCATOpen(PWCHAR pwszFileName,
                                  DWORD fdwOpenFlags,
                                  HANDLE hCatAdmin,
                                  HANDLE hCatalogFile,
                                  DWORD dwReserved)
{
    DebugLog("%p, %#x, %p, %p, %#x", pwszFileName, fdwOpenFlags, hCatAdmin, hCatalogFile, dwReserved);
    return (HANDLE) 'CATO';
}

STATIC WINAPI BOOL CryptCATClose(HANDLE hCatalog)
{
    DebugLog("%p", hCatalog);
    return TRUE;
}

STATIC WINAPI PCRYPTCATATTRIBUTE CryptCATGetAttrInfo(HANDLE hCatalog,
                                                     PVOID pCatMember,
                                                     PWCHAR pwszReferenceTag)
{
    static CRYPTCATATTRIBUTE dummy_attr = {0};
    DebugLog("%p, %p, %p", hCatalog, pCatMember, pwszReferenceTag);
    dummy_attr.cbStruct = sizeof(dummy_attr);
    return &dummy_attr;
}

STATIC WINAPI PCRYPTCATMEMBER CryptCATGetMemberInfo(HANDLE hCatalog,
                                                    PWCHAR pwszReferenceTag)
{
    static CRYPTCATMEMBER dummy_member = {0};
    DebugLog("%p, %p", hCatalog, pwszReferenceTag);
    dummy_member.cbStruct = sizeof(dummy_member);
    return &dummy_member;
}

DECLARE_CRT_EXPORT("CryptCATAdminAcquireContext", CryptCATAdminAcquireContext);
DECLARE_CRT_EXPORT("CryptCATAdminCalcHashFromFileHandle", CryptCATAdminCalcHashFromFileHandle);
DECLARE_CRT_EXPORT("CryptCATAdminEnumCatalogFromHash", CryptCATAdminEnumCatalogFromHash);
DECLARE_CRT_EXPORT("CryptCATAdminReleaseCatalogContext", CryptCATAdminReleaseCatalogContext);
DECLARE_CRT_EXPORT("CryptCATAdminReleaseContext", CryptCATAdminReleaseContext);
DECLARE_CRT_EXPORT("CryptCATCatalogInfoFromContext", CryptCATCatalogInfoFromContext);
DECLARE_CRT_EXPORT("WTHelperGetProvCertFromChain", WTHelperGetProvCertFromChain);
DECLARE_CRT_EXPORT("WTHelperGetProvSignerFromChain", WTHelperGetProvSignerFromChain);
DECLARE_CRT_EXPORT("WTHelperProvDataFromStateData", WTHelperProvDataFromStateData);
DECLARE_CRT_EXPORT("WinVerifyTrust", WinVerifyTrust);
DECLARE_CRT_EXPORT("CryptCATAdminAcquireContext2", CryptCATAdminAcquireContext2);
DECLARE_CRT_EXPORT("CryptCATOpen", CryptCATOpen);
DECLARE_CRT_EXPORT("CryptCATClose", CryptCATClose);
DECLARE_CRT_EXPORT("CryptCATGetAttrInfo", CryptCATGetAttrInfo);
DECLARE_CRT_EXPORT("CryptCATGetMemberInfo", CryptCATGetMemberInfo);
