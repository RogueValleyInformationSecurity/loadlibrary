// OLEAUT32.dll stubs - OLE Automation functions
// Provides BSTR, VARIANT, and SAFEARRAY support

#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

// BSTR is a length-prefixed wide string
// Layout: [4-byte length][string data][null terminator]
typedef WCHAR *BSTR;
typedef const WCHAR *LPCWSTR;
typedef char *PCHAR;
typedef uint16_t VARTYPE;

// SAFEARRAY structure
typedef struct {
    ULONG cElements;
    LONG lLbound;
} SAFEARRAYBOUND;

typedef struct {
    USHORT cDims;
    USHORT fFeatures;
    ULONG cbElements;
    ULONG cLocks;
    PVOID pvData;
    SAFEARRAYBOUND rgsabound[1];
} SAFEARRAY_LOCAL;

// VARIANT structure (simplified)
typedef struct {
    VARTYPE vt;
    WORD wReserved1;
    WORD wReserved2;
    WORD wReserved3;
    union {
        LONGLONG llVal;
        LONG lVal;
        BYTE bVal;
        SHORT iVal;
        float fltVal;
        double dblVal;
        BSTR bstrVal;
        PVOID punkVal;
        SAFEARRAY_LOCAL *parray;
        PVOID byref;
    };
} VARIANT_LOCAL;

// HRESULT codes
#define S_OK 0
#define E_INVALIDARG 0x80070057
#define E_OUTOFMEMORY 0x8007000E
#define DISP_E_BADVARTYPE 0x80020008

// VARCMP return values
#define VARCMP_LT 0
#define VARCMP_EQ 1
#define VARCMP_GT 2

// VT types
#define VT_EMPTY 0
#define VT_BSTR 8
#define VT_ARRAY 0x2000

//
// BSTR Functions
//

// SysAllocString - ordinal 2
STATIC BSTR WINCALL SysAllocString(LPCWSTR psz)
{
    DebugLog("");
    if (!psz) return NULL;

    // Count characters
    size_t len = 0;
    while (psz[len]) len++;

    DWORD byteLen = len * sizeof(WCHAR);
    DWORD *ptr = malloc(sizeof(DWORD) + byteLen + sizeof(WCHAR));
    if (!ptr) return NULL;

    *ptr = byteLen;
    memcpy(ptr + 1, psz, byteLen);
    // Null terminate
    WCHAR *data = (WCHAR *)(ptr + 1);
    data[len] = 0;

    return (BSTR)(ptr + 1);
}

// SysReAllocString - ordinal 4
STATIC INT WINCALL SysReAllocString(BSTR *pbstr, LPCWSTR psz)
{
    DebugLog("");
    if (!pbstr) return FALSE;

    if (*pbstr) {
        DWORD *ptr = ((DWORD *)*pbstr) - 1;
        free(ptr);
    }

    if (!psz) {
        *pbstr = NULL;
        return TRUE;
    }

    *pbstr = SysAllocString(psz);
    return (*pbstr != NULL);
}

// SysFreeString - ordinal 6
STATIC void WINCALL SysFreeString(BSTR bstr)
{
    DebugLog("");
    if (bstr) {
        DWORD *ptr = ((DWORD *)bstr) - 1;
        free(ptr);
    }
}

// SysStringLen - ordinal 7 (returns length in WCHARs)
STATIC UINT WINCALL SysStringLen(BSTR bstr)
{
    DebugLog("");
    if (!bstr) return 0;
    DWORD *ptr = ((DWORD *)bstr) - 1;
    return *ptr / sizeof(WCHAR);
}

// SysStringByteLen - ordinal 149
STATIC UINT WINCALL SysStringByteLen(BSTR bstr)
{
    DebugLog("");
    if (!bstr) return 0;
    DWORD *ptr = ((DWORD *)bstr) - 1;
    return *ptr;
}

// SysAllocStringByteLen - ordinal 150
STATIC BSTR WINCALL SysAllocStringByteLen(PCHAR psz, UINT len)
{
    DebugLog("");
    DWORD *ptr = malloc(sizeof(DWORD) + len + sizeof(WCHAR));
    if (!ptr) return NULL;

    *ptr = len;
    if (psz) {
        memcpy(ptr + 1, psz, len);
    } else {
        memset(ptr + 1, 0, len);
    }
    // Null terminate
    PCHAR data = (PCHAR)(ptr + 1);
    data[len] = 0;
    data[len + 1] = 0;

    return (BSTR)(ptr + 1);
}

//
// VARIANT Functions
//

// VariantInit - ordinal 8
STATIC void WINCALL VariantInit(VARIANT_LOCAL *pvarg)
{
    DebugLog("%p", pvarg);
    if (pvarg) {
        memset(pvarg, 0, sizeof(*pvarg));
        pvarg->vt = VT_EMPTY;
    }
}

// VariantClear - ordinal 9
STATIC HRESULT WINCALL VariantClear(VARIANT_LOCAL *pvarg)
{
    DebugLog("%p", pvarg);
    if (!pvarg) return E_INVALIDARG;

    if (pvarg->vt == VT_BSTR && pvarg->bstrVal) {
        SysFreeString(pvarg->bstrVal);
    }
    memset(pvarg, 0, sizeof(*pvarg));
    pvarg->vt = VT_EMPTY;
    return S_OK;
}

//
// SAFEARRAY Functions
//

// SafeArrayCreate - ordinal 15
STATIC SAFEARRAY_LOCAL * WINAPI SafeArrayCreate(VARTYPE vt, UINT cDims, SAFEARRAYBOUND *rgsabound)
{
    DebugLog("vt=%u, cDims=%u", vt, cDims);
    if (cDims == 0 || !rgsabound) return NULL;

    size_t totalElements = 1;
    for (UINT i = 0; i < cDims; i++) {
        totalElements *= rgsabound[i].cElements;
    }

    // Determine element size (simplified)
    size_t cbElements = 16; // default size

    size_t headerSize = sizeof(SAFEARRAY_LOCAL) + (cDims - 1) * sizeof(SAFEARRAYBOUND);
    SAFEARRAY_LOCAL *psa = malloc(headerSize);
    if (!psa) return NULL;

    psa->cDims = cDims;
    psa->fFeatures = 0;
    psa->cbElements = cbElements;
    psa->cLocks = 0;
    psa->pvData = calloc(totalElements, cbElements);
    if (!psa->pvData) {
        free(psa);
        return NULL;
    }

    for (UINT i = 0; i < cDims; i++) {
        psa->rgsabound[i] = rgsabound[i];
    }

    return psa;
}

// SafeArrayCreateVector - ordinal 22
STATIC SAFEARRAY_LOCAL * WINAPI SafeArrayCreateVector(VARTYPE vt, LONG lLbound, ULONG cElements)
{
    DebugLog("vt=%u, lLbound=%d, cElements=%u", vt, lLbound, cElements);
    SAFEARRAYBOUND bound = { cElements, lLbound };
    return SafeArrayCreate(vt, 1, &bound);
}

// SafeArrayDestroy - ordinal 16
STATIC HRESULT WINCALL SafeArrayDestroy(SAFEARRAY_LOCAL *psa)
{
    DebugLog("%p", psa);
    if (!psa) return E_INVALIDARG;
    if (psa->cLocks > 0) return E_INVALIDARG;

    if (psa->pvData) {
        free(psa->pvData);
    }
    free(psa);
    return S_OK;
}

// SafeArrayGetDim - ordinal 12
STATIC UINT WINCALL SafeArrayGetDim(SAFEARRAY_LOCAL *psa)
{
    DebugLog("%p", psa);
    if (!psa) return 0;
    return psa->cDims;
}

// SafeArrayGetElement - ordinal 17
STATIC HRESULT WINCALL SafeArrayGetElement(SAFEARRAY_LOCAL *psa, LONG *rgIndices, void *pv)
{
    DebugLog("%p, %p, %p", psa, rgIndices, pv);
    if (!psa || !rgIndices || !pv) return E_INVALIDARG;

    // Calculate offset for 1D array (simplified)
    if (psa->cDims == 1) {
        LONG index = rgIndices[0] - psa->rgsabound[0].lLbound;
        if (index < 0 || (ULONG)index >= psa->rgsabound[0].cElements) {
            return E_INVALIDARG;
        }
        char *src = (char *)psa->pvData + index * psa->cbElements;
        memcpy(pv, src, psa->cbElements);
        return S_OK;
    }

    return E_INVALIDARG;
}

// SafeArrayPutElement - ordinal 18
STATIC HRESULT WINCALL SafeArrayPutElement(SAFEARRAY_LOCAL *psa, LONG *rgIndices, void *pv)
{
    DebugLog("%p, %p, %p", psa, rgIndices, pv);
    if (!psa || !rgIndices || !pv) return E_INVALIDARG;

    // Calculate offset for 1D array (simplified)
    if (psa->cDims == 1) {
        LONG index = rgIndices[0] - psa->rgsabound[0].lLbound;
        if (index < 0 || (ULONG)index >= psa->rgsabound[0].cElements) {
            return E_INVALIDARG;
        }
        char *dst = (char *)psa->pvData + index * psa->cbElements;
        memcpy(dst, pv, psa->cbElements);
        return S_OK;
    }

    return E_INVALIDARG;
}

// SafeArrayGetVartype - ordinal 77
STATIC HRESULT WINCALL SafeArrayGetVartype(SAFEARRAY_LOCAL *psa, VARTYPE *pvt)
{
    DebugLog("%p, %p", psa, pvt);
    if (!psa || !pvt) return E_INVALIDARG;
    *pvt = VT_EMPTY; // We don't track vartype in our simplified implementation
    return S_OK;
}

//
// String Comparison Functions
//

// VarBstrCat - ordinal 184
STATIC HRESULT WINCALL VarBstrCat(BSTR bstrLeft, BSTR bstrRight, BSTR *pbstrResult)
{
    DebugLog("");
    if (!pbstrResult) return E_INVALIDARG;

    UINT lenLeft = bstrLeft ? SysStringLen(bstrLeft) : 0;
    UINT lenRight = bstrRight ? SysStringLen(bstrRight) : 0;
    UINT totalLen = lenLeft + lenRight;

    DWORD byteLen = totalLen * sizeof(WCHAR);
    DWORD *ptr = malloc(sizeof(DWORD) + byteLen + sizeof(WCHAR));
    if (!ptr) return E_OUTOFMEMORY;

    *ptr = byteLen;
    WCHAR *data = (WCHAR *)(ptr + 1);

    if (lenLeft > 0) {
        memcpy(data, bstrLeft, lenLeft * sizeof(WCHAR));
    }
    if (lenRight > 0) {
        memcpy(data + lenLeft, bstrRight, lenRight * sizeof(WCHAR));
    }
    data[totalLen] = 0;

    *pbstrResult = (BSTR)(ptr + 1);
    return S_OK;
}

// VarBstrCmp - ordinal 314
STATIC HRESULT WINCALL VarBstrCmp(BSTR bstrLeft, BSTR bstrRight, DWORD lcid, DWORD dwFlags)
{
    DebugLog("");
    (void)lcid;
    (void)dwFlags;

    if (!bstrLeft && !bstrRight) return VARCMP_EQ;
    if (!bstrLeft) return VARCMP_LT;
    if (!bstrRight) return VARCMP_GT;

    UINT lenLeft = SysStringLen(bstrLeft);
    UINT lenRight = SysStringLen(bstrRight);
    UINT minLen = lenLeft < lenRight ? lenLeft : lenRight;

    for (UINT i = 0; i < minLen; i++) {
        if (bstrLeft[i] < bstrRight[i]) return VARCMP_LT;
        if (bstrLeft[i] > bstrRight[i]) return VARCMP_GT;
    }

    if (lenLeft < lenRight) return VARCMP_LT;
    if (lenLeft > lenRight) return VARCMP_GT;
    return VARCMP_EQ;
}

//
// Export Declarations
//

DECLARE_CRT_EXPORT("SysAllocString", SysAllocString);
DECLARE_CRT_EXPORT("SysReAllocString", SysReAllocString);
DECLARE_CRT_EXPORT("SysFreeString", SysFreeString);
DECLARE_CRT_EXPORT("SysStringLen", SysStringLen);
DECLARE_CRT_EXPORT("SysStringByteLen", SysStringByteLen);
DECLARE_CRT_EXPORT("SysAllocStringByteLen", SysAllocStringByteLen);
DECLARE_CRT_EXPORT("VariantInit", VariantInit);
DECLARE_CRT_EXPORT("VariantClear", VariantClear);
DECLARE_CRT_EXPORT("SafeArrayCreate", SafeArrayCreate);
DECLARE_CRT_EXPORT("SafeArrayCreateVector", SafeArrayCreateVector);
DECLARE_CRT_EXPORT("SafeArrayDestroy", SafeArrayDestroy);
DECLARE_CRT_EXPORT("SafeArrayGetDim", SafeArrayGetDim);
DECLARE_CRT_EXPORT("SafeArrayGetElement", SafeArrayGetElement);
DECLARE_CRT_EXPORT("SafeArrayPutElement", SafeArrayPutElement);
DECLARE_CRT_EXPORT("SafeArrayGetVartype", SafeArrayGetVartype);
DECLARE_CRT_EXPORT("VarBstrCat", VarBstrCat);
DECLARE_CRT_EXPORT("VarBstrCmp", VarBstrCmp);
