#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>
#include <assert.h>
#include <wchar.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define MAX_DEFAULTCHAR 2
#define MAX_LEADBYTES 12

typedef struct _cpinfo {
  UINT MaxCharSize;
  BYTE DefaultChar[MAX_DEFAULTCHAR];
  BYTE LeadByte[MAX_LEADBYTES];
} CPINFO, *LPCPINFO;

STATIC UINT WINAPI GetACP(void)
{
    DebugLog("");

    return 65001;   // UTF-8
}

STATIC WINAPI BOOL IsValidCodePage(UINT CodePage)
{
    DebugLog("%u", CodePage);

    return TRUE;
}

STATIC WINAPI BOOL GetCPInfo(UINT CodePage, LPCPINFO lpCPInfo)
{
    DebugLog("%u, %p", CodePage, lpCPInfo);

    memset(lpCPInfo, 0, sizeof *lpCPInfo);

    lpCPInfo->MaxCharSize       = 1;
    lpCPInfo->DefaultChar[0]    = '?';

    return TRUE;
}

STATIC DWORD WINAPI LocaleNameToLCID(PVOID lpName, DWORD dwFlags)
{
    DebugLog("%p, %#x", lpName, dwFlags);
    return 0;
}

STATIC WINAPI int LCMapStringW(DWORD Locale, DWORD dwMapFlags, PVOID lpSrcStr, int cchSrc, PVOID lpDestStr, int cchDest)
{
    DebugLog("%u, %#x, %p, %d, %p, %d", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);
    return 1;
}

STATIC WINAPI int LCMapStringA(DWORD Locale, DWORD dwMapFlags, LPCSTR lpSrcStr, int cchSrc, LPSTR lpDestStr, int cchDest)
{
    DebugLog("%u, %#x, %p, %d, %p, %d", Locale, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest);

    if (!lpDestStr) {
        return cchSrc;
    }

    if (cchSrc < 0 && lpSrcStr) {
        cchSrc = (int)strlen(lpSrcStr);
    }

    int copy_len = cchDest > cchSrc ? cchSrc : cchDest;
    if (copy_len > 0 && lpSrcStr) {
        memcpy(lpDestStr, lpSrcStr, copy_len);
    }

    return copy_len;
}

#define LOCALE_NAME_USER_DEFAULT NULL
#define NORM_IGNORENONSPACE 1
#define LCMAP_UPPERCASE 512
STATIC WINAPI int LCMapStringEx(PVOID lpLocaleName, DWORD dwMapFlags, PVOID lpSrcStr, int cchSrc, PVOID lpDestStr, int cchDest, PVOID lpVersionInformation, PVOID lpReserved, PVOID sortHandle)
{
    DebugLog("%p, %#x, %p, %d, %p, %d, %p, %p, %p", lpLocaleName, dwMapFlags, lpSrcStr, cchSrc, lpDestStr, cchDest, lpVersionInformation, lpReserved, sortHandle);

    assert(lpLocaleName == LOCALE_NAME_USER_DEFAULT);

    if (lpDestStr == NULL) {
        return cchSrc;
    }

    memcpy(lpDestStr, lpSrcStr, cchDest > cchSrc ? cchSrc : cchDest);

    return cchDest > cchSrc ? cchSrc : cchDest;
}

STATIC WINAPI int GetLocaleInfoEx(LPCWSTR lpLocaleName, DWORD LCType, LPWSTR lpLCData, int cchData)
{
    DebugLog("%S, %d, %S, %d", lpLocaleName, LCType, lpLCData, cchData);
    return 0;
}

STATIC DWORD WINAPI GetUserDefaultLCID(void)
{
    DebugLog("");
    return 0x0409;
}

STATIC WINAPI BOOL GetStringTypeExA(DWORD Locale, DWORD dwInfoType, LPCSTR lpSrcStr, int cchSrc, WORD *lpCharType)
{
    DebugLog("%#x, %#x, %p, %d, %p", Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType);

    if (!lpCharType) {
        return FALSE;
    }

    if (cchSrc < 0 && lpSrcStr) {
        cchSrc = (int)strlen(lpSrcStr);
    }

    for (int i = 0; i < cchSrc; i++) {
        lpCharType[i] = 0;
    }

    return TRUE;
}

STATIC WINAPI BOOL GetStringTypeExW(DWORD Locale, DWORD dwInfoType, LPCWSTR lpSrcStr, int cchSrc, WORD *lpCharType)
{
    DebugLog("%#x, %#x, %p, %d, %p", Locale, dwInfoType, lpSrcStr, cchSrc, lpCharType);

    if (!lpCharType) {
        return FALSE;
    }

    if (cchSrc < 0 && lpSrcStr) {
        cchSrc = (int)wcslen(lpSrcStr);
    }

    for (int i = 0; i < cchSrc; i++) {
        lpCharType[i] = 0;
    }

    return TRUE;
}

DECLARE_CRT_EXPORT("GetACP", GetACP);
DECLARE_CRT_EXPORT("IsValidCodePage", IsValidCodePage);
DECLARE_CRT_EXPORT("GetCPInfo", GetCPInfo);
DECLARE_CRT_EXPORT("LocaleNameToLCID", LocaleNameToLCID);
DECLARE_CRT_EXPORT("LCMapStringA", LCMapStringA);
DECLARE_CRT_EXPORT("LCMapStringW", LCMapStringW);
DECLARE_CRT_EXPORT("LCMapStringEx", LCMapStringEx);
DECLARE_CRT_EXPORT("GetLocaleInfoEx", GetLocaleInfoEx);
DECLARE_CRT_EXPORT("GetUserDefaultLCID", GetUserDefaultLCID);
DECLARE_CRT_EXPORT("GetStringTypeExA", GetStringTypeExA);
DECLARE_CRT_EXPORT("GetStringTypeExW", GetStringTypeExW);
