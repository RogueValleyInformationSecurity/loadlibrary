#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

static int randomfd = -1;

static void __attribute__((constructor)) crypt_random_init(void)
{
    randomfd = open("/dev/urandom", O_RDONLY);
}

static void __attribute__((destructor)) crypt_random_fini(void)
{
    if (randomfd >= 0) {
        close(randomfd);
        randomfd = -1;
    }
}

typedef struct _CRYPT_BIT_BLOB {
  DWORD cbData;
  BYTE  *pbData;
  DWORD cUnusedBits;
} CRYPT_BIT_BLOB, *PCRYPT_BIT_BLOB;

typedef struct _CRYPTOAPI_BLOB {
  DWORD cbData;
  BYTE  *pbData;
} CRYPT_INTEGER_BLOB, *PCRYPT_INTEGER_BLOB,
  CRYPT_UINT_BLOB, *PCRYPT_UINT_BLOB,
  CRYPT_OBJID_BLOB, *PCRYPT_OBJID_BLOB,
  CERT_NAME_BLOB, CERT_RDN_VALUE_BLOB,
  *PCERT_NAME_BLOB, *PCERT_RDN_VALUE_BLOB,
  CERT_BLOB, *PCERT_BLOB,
  CRL_BLOB, *PCRL_BLOB,
  DATA_BLOB, *PDATA_BLOB,
  CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB,
  CRYPT_HASH_BLOB, *PCRYPT_HASH_BLOB,
  CRYPT_DIGEST_BLOB, *PCRYPT_DIGEST_BLOB,
  CRYPT_DER_BLOB, PCRYPT_DER_BLOB,
  CRYPT_ATTR_BLOB, *PCRYPT_ATTR_BLOB;

typedef struct _CRYPT_ALGORITHM_IDENTIFIER {
  PVOID            pszObjId;
  CRYPT_OBJID_BLOB Parameters;
} CRYPT_ALGORITHM_IDENTIFIER, *PCRYPT_ALGORITHM_IDENTIFIER;

typedef struct _CERT_PUBLIC_KEY_INFO {
  CRYPT_ALGORITHM_IDENTIFIER Algorithm;
  CRYPT_BIT_BLOB             PublicKey;
} CERT_PUBLIC_KEY_INFO, *PCERT_PUBLIC_KEY_INFO;

typedef struct _CERT_EXTENSION {
  PVOID            pszObjId;
  BOOL             fCritical;
  CRYPT_OBJID_BLOB Value;
} CERT_EXTENSION, *PCERT_EXTENSION;

typedef struct _CERT_INFO {
  DWORD                      dwVersion;
  CRYPT_INTEGER_BLOB         SerialNumber;
  CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
  CERT_NAME_BLOB             Issuer;
  FILETIME                   NotBefore;
  FILETIME                   NotAfter;
  CERT_NAME_BLOB             Subject;
  CERT_PUBLIC_KEY_INFO       SubjectPublicKeyInfo;
  CRYPT_BIT_BLOB             IssuerUniqueId;
  CRYPT_BIT_BLOB             SubjectUniqueId;
  DWORD                      cExtension;
  PCERT_EXTENSION            rgExtension;
} CERT_INFO, *PCERT_INFO;

typedef struct _CERT_CONTEXT {
  DWORD      dwCertEncodingType;
  BYTE       *pbCertEncoded;
  DWORD      cbCertEncoded;
  PCERT_INFO pCertInfo;
  HANDLE     hCertStore;
} CERT_CONTEXT, *PCERT_CONTEXT;

static NTSTATUS WINAPI BCryptOpenAlgorithmProvider(PVOID phAlgorithm, PWCHAR pszAlgId, PWCHAR pszImplementation, DWORD dwFlags)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI BCryptCloseAlgorithmProvider(HANDLE hAlgorithm, ULONG dwFlags)
{
    return STATUS_SUCCESS;
}

static NTSTATUS WINAPI BCryptGenRandom(PVOID phAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags)
{
    DebugLog("%p, %p, %lu, %#x [fd=%d]", phAlgorithm, pbBuffer, cbBuffer, dwFlags, randomfd);

    if (randomfd < 0) {
        randomfd = open("/dev/urandom", O_RDONLY);
    }

    if (randomfd >= 0 && read(randomfd, pbBuffer, cbBuffer) != (ssize_t)cbBuffer) {
        DebugLog("failed to generate random data, %m");
    } else if (randomfd < 0) {
        memset(pbBuffer, 0, cbBuffer);
    }

    return STATUS_SUCCESS;
}

static BOOL WINAPI CryptEncrypt(HANDLE hKey,
                                HANDLE hHash,
                                BOOL Final,
                                DWORD dwFlags,
                                BYTE *pbData,
                                DWORD *pdwDataLen,
                                DWORD dwBufLen)
{
    DebugLog("%p, %p, %d, %#x, %p, %p, %u",
             hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

    if (pdwDataLen && *pdwDataLen > dwBufLen) {
        *pdwDataLen = dwBufLen;
    }

    return TRUE;
}

static BOOL WINAPI CryptDecrypt(HANDLE hKey,
                                HANDLE hHash,
                                BOOL Final,
                                DWORD dwFlags,
                                BYTE *pbData,
                                DWORD *pdwDataLen)
{
    DebugLog("%p, %p, %d, %#x, %p, %p", hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    return TRUE;
}

static BOOL WINAPI CryptDestroyKey(HANDLE hKey)
{
    DebugLog("%p", hKey);
    return TRUE;
}

static BOOL WINAPI CryptReleaseContext(HANDLE hProv, DWORD dwFlags)
{
    DebugLog("%p, %#x", hProv, dwFlags);
    return TRUE;
}

static BOOL WINAPI CryptImportKey(HANDLE hProv,
                                  const BYTE *pbData,
                                  DWORD dwDataLen,
                                  HANDLE hPubKey,
                                  DWORD dwFlags,
                                  HANDLE *phKey)
{
    DebugLog("%p, %p, %u, %p, %#x, %p", hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
    if (phKey) {
        *phKey = (HANDLE) 'KEY1';
    }
    return TRUE;
}

static BOOL WINAPI CryptSetKeyParam(HANDLE hKey,
                                    DWORD dwParam,
                                    const BYTE *pbData,
                                    DWORD dwFlags)
{
    DebugLog("%p, %#x, %p, %#x", hKey, dwParam, pbData, dwFlags);
    return TRUE;
}

static BOOL WINAPI CryptHashData(HANDLE hHash,
                                 const BYTE *pbData,
                                 DWORD dwDataLen,
                                 DWORD dwFlags)
{
    DebugLog("%p, %p, %u, %#x", hHash, pbData, dwDataLen, dwFlags);
    return TRUE;
}

static BOOL WINAPI CryptDeriveKey(HANDLE hProv,
                                  DWORD Algid,
                                  HANDLE hBaseData,
                                  DWORD dwFlags,
                                  HANDLE *phKey)
{
    DebugLog("%p, %#x, %p, %#x, %p", hProv, Algid, hBaseData, dwFlags, phKey);
    if (phKey) {
        *phKey = (HANDLE) 'KEY1';
    }
    return TRUE;
}
static BOOL WINAPI CertStrToNameW(DWORD dwCertEncodingType,
                                  PVOID pszX500,
                                  DWORD dwStrType,
                                  void *pvReserved,
                                  BYTE *pbEncoded,
                                  DWORD *pcbEncoded,
                                  PVOID ppszError)
{
    uint16_t CertName[] = L"Totally Legitimate Certificate Name";
    char *name = CreateAnsiFromWide(pszX500);

    DebugLog("%u, %p [%s], %u, %p, %p, %p, %p", dwCertEncodingType,
                                                pszX500,
                                                name,
                                                dwStrType,
                                                pvReserved,
                                                pbEncoded,
                                                pcbEncoded,
                                                ppszError);
    free(name);

    *pcbEncoded = sizeof(CertName);

    if (pbEncoded) {
        memcpy(pbEncoded, CertName, sizeof(CertName));
    }

    return TRUE;
}

static HANDLE WINAPI CertOpenStore(PCHAR lpszStoreProvider,
                                   DWORD dwMsgAndCertEncodingType,
                                   PVOID hCryptProv,
                                   DWORD dwFlags,
                                   PVOID pvPara)
{
    return (HANDLE) 'STOR';
}

enum {
    CERT_FIND_SUBJECT_NAME = 131079,
};



#include "rootcert.h"
#include "signingcert.h"

static PVOID WINAPI CertFindCertificateInStore(HANDLE hCertStore,
                                               DWORD dwCertEncodingType,
                                               DWORD dwFindFlags,
                                               DWORD dwFindType,
                                               PVOID pvFindPara,
                                               PVOID pPrevCertContext)
{
    static CERT_INFO FakeInfo = {0};
    static CERT_CONTEXT FakeCert = {0};

    DebugLog("%p, %u, %#x, %#x, %p, %p", hCertStore,
                                         dwCertEncodingType,
                                         dwFindFlags,
                                         dwFindType,
                                         pvFindPara,
                                         pPrevCertContext);

    switch  (dwFindType) {
        case CERT_FIND_SUBJECT_NAME: {
            DebugLog("\tCERT_FIND_SUBJECT_NAME");
            break;
        }
    }

    DebugLog("FakeCert: %p", &FakeCert);

    FakeCert.dwCertEncodingType = 1;
    if (pvFindPara &&
        ((PCERT_NAME_BLOB) pvFindPara)->pbData &&
        ((PCERT_NAME_BLOB) pvFindPara)->cbData) {
        const CERT_NAME_BLOB *subject = (PCERT_NAME_BLOB) pvFindPara;

        if (subject->cbData <= sizeof(SigningCertificate2010) &&
            memcmp(subject->pbData,
                   SigningCertificate2010 + 211,
                   subject->cbData) == 0) {
            FakeCert.pbCertEncoded = SigningCertificate2010;
            FakeCert.cbCertEncoded = sizeof(SigningCertificate2010);
            DebugLog("Microsoft Code Signing PCA 2010");
        } else if (subject->cbData <= sizeof(SigningCertificate2024) &&
                   memcmp(subject->pbData,
                          SigningCertificate2024 + 220,
                          subject->cbData) == 0) {
            FakeCert.pbCertEncoded = SigningCertificate2024;
            FakeCert.cbCertEncoded = sizeof(SigningCertificate2024);
            DebugLog("Microsoft Code Signing PCA 2024");
        } else {
            FakeCert.pbCertEncoded = RootCertificate;
            FakeCert.cbCertEncoded = sizeof(RootCertificate);
            DebugLog("Microsoft Root Certificate Authority 2010");
        }
    } else {
        FakeCert.pbCertEncoded = RootCertificate;
        FakeCert.cbCertEncoded = sizeof(RootCertificate);
        DebugLog("Microsoft Root Certificate Authority 2010");
    }
    FakeCert.pCertInfo = &FakeInfo;
    FakeCert.pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId = "1.2.840.113549.1.1.1";

    return &FakeCert;
}

static BOOL WINAPI CertCloseStore(HANDLE hCertStore, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CertAddEncodedCertificateToStore(HANDLE hCertStore,
                                                    DWORD dwCertEncodingType,
                                                    const BYTE *pbCertEncoded,
                                                    DWORD cbCertEncoded,
                                                    DWORD dwAddDisposition,
                                                    PCERT_CONTEXT *ppCertContext)
{
    DebugLog("%p, %u, %p, %u, %#x, %p", hCertStore, dwCertEncodingType, pbCertEncoded, cbCertEncoded, dwAddDisposition, ppCertContext);
    if (ppCertContext) {
        *ppCertContext = NULL;
    }
    return TRUE;
}

static PCERT_CONTEXT WINAPI CertCreateCertificateContext(DWORD dwCertEncodingType,
                                                         const BYTE *pbCertEncoded,
                                                         DWORD cbCertEncoded)
{
    static CERT_CONTEXT dummy_cert = {0};
    DebugLog("%u, %p, %u", dwCertEncodingType, pbCertEncoded, cbCertEncoded);
    return &dummy_cert;
}

static BOOL WINAPI CertDeleteCertificateFromStore(PCERT_CONTEXT pCertContext)
{
    DebugLog("%p", pCertContext);
    return TRUE;
}

static PCERT_CONTEXT WINAPI CertEnumCertificatesInStore(HANDLE hCertStore, PCERT_CONTEXT pPrevCertContext)
{
    DebugLog("%p, %p", hCertStore, pPrevCertContext);
    return NULL;
}

static void WINAPI CertFreeCertificateChain(PVOID pChainContext)
{
    DebugLog("%p", pChainContext);
}

static BOOL WINAPI CertGetCertificateChain(PVOID hChainEngine,
                                           PCERT_CONTEXT pCertContext,
                                           PVOID pTime,
                                           HANDLE hAdditionalStore,
                                           PVOID pChainPara,
                                           DWORD dwFlags,
                                           PVOID pvReserved,
                                           PVOID *ppChainContext)
{
    DebugLog("%p, %p, %p, %p, %p, %#x, %p, %p", hChainEngine, pCertContext, pTime, hAdditionalStore, pChainPara, dwFlags, pvReserved, ppChainContext);
    if (ppChainContext) {
        *ppChainContext = NULL;
    }
    return TRUE;
}

static BOOL WINAPI CertGetCertificateContextProperty(PCERT_CONTEXT pCertContext,
                                                     DWORD dwPropId,
                                                     PVOID pvData,
                                                     PDWORD pcbData)
{
    DebugLog("%p, %#x, %p, %p", pCertContext, dwPropId, pvData, pcbData);
    if (pcbData) {
        *pcbData = 0;
    }
    return TRUE;
}

static DWORD WINAPI CertGetNameStringW(PCERT_CONTEXT pCertContext,
                                       DWORD dwType,
                                       DWORD dwFlags,
                                       PVOID pvTypePara,
                                       PWCHAR pszNameString,
                                       DWORD cchNameString)
{
    DebugLog("%p, %u, %#x, %p, %p, %u", pCertContext, dwType, dwFlags, pvTypePara, pszNameString, cchNameString);
    if (pszNameString && cchNameString > 0) {
        pszNameString[0] = L'\0';
    }
    return 0;
}

static DWORD WINAPI CertNameToStrW(DWORD dwCertEncodingType,
                                   PCERT_NAME_BLOB pName,
                                   DWORD dwStrType,
                                   PWCHAR psz,
                                   DWORD csz)
{
    DebugLog("%u, %p, %#x, %p, %u", dwCertEncodingType, pName, dwStrType, psz, csz);
    if (psz && csz > 0) {
        psz[0] = L'\0';
    }
    return 0;
}

static BOOL WINAPI CryptDecodeObject(DWORD dwCertEncodingType,
                                     PVOID lpszStructType,
                                     const BYTE *pbEncoded,
                                     DWORD cbEncoded,
                                     DWORD dwFlags,
                                     PVOID pvStructInfo,
                                     PDWORD pcbStructInfo)
{
    DebugLog("%u, %p, %p, %u, %#x, %p, %p", dwCertEncodingType, lpszStructType, pbEncoded, cbEncoded, dwFlags, pvStructInfo, pcbStructInfo);
    if (pcbStructInfo) {
        *pcbStructInfo = 0;
    }
    return TRUE;
}

static BOOL WINAPI CryptMsgClose(HANDLE hCryptMsg)
{
    DebugLog("%p", hCryptMsg);
    return TRUE;
}

static BOOL WINAPI CryptMsgGetParam(HANDLE hCryptMsg,
                                    DWORD dwParamType,
                                    DWORD dwIndex,
                                    PVOID pvData,
                                    PDWORD pcbData)
{
    DebugLog("%p, %#x, %u, %p, %p", hCryptMsg, dwParamType, dwIndex, pvData, pcbData);
    if (pcbData) {
        *pcbData = 0;
    }
    return TRUE;
}

static HANDLE WINAPI CryptMsgOpenToDecode(DWORD dwMsgEncodingType,
                                         DWORD dwFlags,
                                         DWORD dwMsgType,
                                         PVOID hCryptProv,
                                         PCERT_INFO pRecipientInfo,
                                         PVOID pStreamInfo)
{
    DebugLog("%u, %#x, %#x, %p, %p, %p", dwMsgEncodingType, dwFlags, dwMsgType, hCryptProv, pRecipientInfo, pStreamInfo);
    return (HANDLE) 'CMOD';
}

static BOOL WINAPI CryptMsgUpdate(HANDLE hCryptMsg,
                                  const BYTE *pbData,
                                  DWORD cbData,
                                  BOOL fFinal)
{
    DebugLog("%p, %p, %u, %u", hCryptMsg, pbData, cbData, fFinal);
    return TRUE;
}

static BOOL WINAPI CryptQueryObject(DWORD dwObjectType,
                                    PVOID pvObject,
                                    DWORD dwExpectedContentTypeFlags,
                                    DWORD dwExpectedFormatTypeFlags,
                                    DWORD dwFlags,
                                    PDWORD pdwMsgAndCertEncodingType,
                                    PDWORD pdwContentType,
                                    PDWORD pdwFormatType,
                                    HANDLE *phCertStore,
                                    HANDLE *phMsg,
                                    PVOID *ppvContext)
{
    DebugLog("%#x, %p, %#x, %#x, %#x, %p, %p, %p, %p, %p, %p",
             dwObjectType, pvObject, dwExpectedContentTypeFlags, dwExpectedFormatTypeFlags,
             dwFlags, pdwMsgAndCertEncodingType, pdwContentType, pdwFormatType,
             phCertStore, phMsg, ppvContext);
    if (pdwMsgAndCertEncodingType) {
        *pdwMsgAndCertEncodingType = 0;
    }
    if (pdwContentType) {
        *pdwContentType = 0;
    }
    if (pdwFormatType) {
        *pdwFormatType = 0;
    }
    if (phCertStore) {
        *phCertStore = (HANDLE) 'STOR';
    }
    if (phMsg) {
        *phMsg = (HANDLE) 'CMOD';
    }
    if (ppvContext) {
        *ppvContext = NULL;
    }
    return TRUE;
}

static BOOL WINAPI CryptStringToBinaryW(PWCHAR pszString,
                                        DWORD cchString,
                                        DWORD dwFlags,
                                        BYTE *pbBinary,
                                        PDWORD pcbBinary,
                                        PDWORD pdwSkip,
                                        PDWORD pdwFlags)
{
    DebugLog("%p, %u, %#x, %p, %p, %p, %p", pszString, cchString, dwFlags, pbBinary, pcbBinary, pdwSkip, pdwFlags);
    if (pcbBinary) {
        *pcbBinary = 0;
    }
    if (pdwSkip) {
        *pdwSkip = 0;
    }
    if (pdwFlags) {
        *pdwFlags = 0;
    }
    return TRUE;
}
static BOOL WINAPI CryptAcquireContextW(PVOID phProv, PWCHAR pszContainer, PWCHAR pszProvider, DWORD dwProvType, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CertFreeCertificateContext(PVOID pCertContext)
{
    return TRUE;
}

enum {
    CALG_SHA_256 = 0x800c,
    CALG_SHA1 = 0x8004,
};

static BOOL WINAPI CryptCreateHash(PVOID hProv, DWORD Algid, HANDLE hKey, DWORD dwFlags, PDWORD phHash)
{
    DebugLog("%p, %#x, %p, %#x, %p", hProv, Algid, hKey, dwFlags, phHash);

    switch (Algid) {
        case CALG_SHA_256:
            *phHash = 'SHA2';
            break;
        case CALG_SHA1:
            *phHash = 'SHA1';
            break;
        default:
            DebugLog("unexpected Algid value, code update might be required.");
    }

    return TRUE;
}

enum HashParameters
{
    HP_ALGID = 0x0001,   // Hash algorithm
    HP_HASHVAL = 0x0002, // Hash value
    HP_HASHSIZE = 0x0004 // Hash value size
};

static BOOL WINAPI CryptGetHashParam(DWORD hHash, DWORD dwParam, PDWORD pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    DebugLog("%#x, %u, %p, %p, %#x", hHash, dwParam, pbData, pdwDataLen, dwFlags);

    switch (dwParam) {
        case HP_ALGID:
            if (pdwDataLen) {
                *pdwDataLen = sizeof(DWORD);
            }
            if (pbData) {
                switch (hHash) {
                    case 'SHA2': *pbData = CALG_SHA_256; break;
                    case 'SHA1': *pbData = CALG_SHA1; break;
                    default: *pbData = 0; break;
                }
            }
            break;
        case HP_HASHVAL: {
            DWORD size = 0;
            switch (hHash) {
                case 'SHA2': size = 32; break;
                case 'SHA1': size = 20; break;
                default: size = 0; break;
            }
            if (pdwDataLen) {
                *pdwDataLen = size;
            }
            if (pbData && size) {
                memset(pbData, 0, size);
            }
            break;
        }
        case HP_HASHSIZE:
            if (pdwDataLen) {
                *pdwDataLen = sizeof(DWORD);
            }
            if (!pbData) {
                break;
            }
            switch (hHash) {
                case 'SHA2': *pbData = 32; break;
                case 'SHA1': *pbData = 20; break;
                default:
                    DebugLog("unknown hHash, this might fail.");
            }
            break;
    }

    return TRUE;
}

static BOOL WINAPI CryptSetHashParam(PVOID hHash, DWORD dwParam, PVOID pbData, DWORD dwFlags)
{
    return TRUE;
}

static BOOL WINAPI CryptImportPublicKeyInfo(HANDLE hCryptProv, DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, HANDLE *phKey)
{
    return TRUE;
}

static BOOL WINAPI CryptVerifySignatureW(DWORD hHash, PVOID pbSignature, DWORD dwSigLen, HANDLE hPubKey, PVOID sDescription, DWORD dwFlags)
{
    switch (hHash) {
        case 'SHA2': {
            if (dwSigLen != 256) {
                DebugLog("unexpected Signature Size");
            }
            break;
        }
        case 'SHA1': {
            if (dwSigLen != 160) {
                DebugLog("unexpected Signature Size");
            }
            break;
        }
        default: DebugLog("unrecognized hHash %#x, something went wrong", hHash);
    }
    DebugLog("Signature verification is not implemented #YOLO");
    return TRUE;
}

static BOOL WINAPI CertVerifyCertificateChainPolicy(PVOID pszPolicyOID, PVOID pChainContext, PVOID pPolicyPara, PVOID pPolicyStatus)
{
    DebugLog("Certificate policy verification is not implemented #YOLO");
    return TRUE;
}

static BOOL WINAPI CryptDestroyHash(DWORD hHash)
{
    DebugLog("%p", hHash);

    assert(hHash == 'SHA2' || hHash == 'SHA1');

    return TRUE;
}

DECLARE_CRT_EXPORT("CertCloseStore", CertCloseStore);
DECLARE_CRT_EXPORT("CertFindCertificateInStore", CertFindCertificateInStore);
DECLARE_CRT_EXPORT("CertFreeCertificateContext", CertFreeCertificateContext);
DECLARE_CRT_EXPORT("CertAddEncodedCertificateToStore", CertAddEncodedCertificateToStore);
DECLARE_CRT_EXPORT("CertCreateCertificateContext", CertCreateCertificateContext);
DECLARE_CRT_EXPORT("CertDeleteCertificateFromStore", CertDeleteCertificateFromStore);
DECLARE_CRT_EXPORT("CertEnumCertificatesInStore", CertEnumCertificatesInStore);
DECLARE_CRT_EXPORT("CertFreeCertificateChain", CertFreeCertificateChain);
DECLARE_CRT_EXPORT("CertGetCertificateChain", CertGetCertificateChain);
DECLARE_CRT_EXPORT("CertGetCertificateContextProperty", CertGetCertificateContextProperty);
DECLARE_CRT_EXPORT("CertGetNameStringW", CertGetNameStringW);
DECLARE_CRT_EXPORT("CertNameToStrW", CertNameToStrW);
DECLARE_CRT_EXPORT("CryptDecodeObject", CryptDecodeObject);
DECLARE_CRT_EXPORT("CryptMsgClose", CryptMsgClose);
DECLARE_CRT_EXPORT("CryptMsgGetParam", CryptMsgGetParam);
DECLARE_CRT_EXPORT("CryptMsgOpenToDecode", CryptMsgOpenToDecode);
DECLARE_CRT_EXPORT("CryptMsgUpdate", CryptMsgUpdate);
DECLARE_CRT_EXPORT("CryptQueryObject", CryptQueryObject);
DECLARE_CRT_EXPORT("CryptStringToBinaryW", CryptStringToBinaryW);
DECLARE_CRT_EXPORT("CertOpenStore", CertOpenStore);
DECLARE_CRT_EXPORT("CertStrToNameW", CertStrToNameW);
DECLARE_CRT_EXPORT("CertVerifyCertificateChainPolicy", CertVerifyCertificateChainPolicy);
DECLARE_CRT_EXPORT("CryptImportPublicKeyInfo", CryptImportPublicKeyInfo);
DECLARE_CRT_EXPORT("CryptDestroyKey", CryptDestroyKey);
DECLARE_CRT_EXPORT("CryptReleaseContext", CryptReleaseContext);
DECLARE_CRT_EXPORT("CryptImportKey", CryptImportKey);
DECLARE_CRT_EXPORT("CryptSetKeyParam", CryptSetKeyParam);
DECLARE_CRT_EXPORT("CryptCreateHash", CryptCreateHash);
DECLARE_CRT_EXPORT("BCryptOpenAlgorithmProvider", BCryptOpenAlgorithmProvider);
DECLARE_CRT_EXPORT("BCryptCloseAlgorithmProvider", BCryptCloseAlgorithmProvider);
DECLARE_CRT_EXPORT("BCryptGenRandom", BCryptGenRandom);
DECLARE_CRT_EXPORT("CryptEncrypt", CryptEncrypt);
DECLARE_CRT_EXPORT("CryptDecrypt", CryptDecrypt);
DECLARE_CRT_EXPORT("CryptDeriveKey", CryptDeriveKey);
DECLARE_CRT_EXPORT("CryptAcquireContextW", CryptAcquireContextW);
DECLARE_CRT_EXPORT("CryptGetHashParam", CryptGetHashParam);
DECLARE_CRT_EXPORT("CryptHashData", CryptHashData);
DECLARE_CRT_EXPORT("CryptSetHashParam", CryptSetHashParam);
DECLARE_CRT_EXPORT("CryptVerifySignatureW", CryptVerifySignatureW);
DECLARE_CRT_EXPORT("CryptDestroyHash", CryptDestroyHash);
