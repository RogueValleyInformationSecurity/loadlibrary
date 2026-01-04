#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>
#include <search.h>
#include <assert.h>
#include <ctype.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"
#include "winstrings.h"

#define ERROR_ENVVAR_NOT_FOUND 203

extern void WINAPI SetLastError(DWORD dwErrCode);

WCHAR EnvironmentStrings[] =
    L"ALLUSERSPROFILE=AllUsersProfile\0"
    L"ALLUSERSAPPDATA=AllUsersAppdata\0"
;

STATIC PVOID WINAPI GetEnvironmentStringsW(void)
{
    DebugLog("");

    return EnvironmentStrings;
}

STATIC BOOL WINAPI FreeEnvironmentStringsW(PVOID lpszEnvironmentBlock)
{
    DebugLog("%p", lpszEnvironmentBlock);

    return TRUE;
}

static DWORD WriteWideEnvValue(PVOID lpBuffer, DWORD nSize, const char *value)
{
    size_t len;
    PWCHAR out;

    if (!value) {
        return 0;
    }

    len = strlen(value);
    if (!lpBuffer || nSize == 0) {
        return (DWORD)(len + 1);
    }

    if (nSize <= len) {
        return (DWORD)(len + 1);
    }

    out = (PWCHAR) lpBuffer;
    for (size_t i = 0; i < len; ++i) {
        out[i] = (unsigned char) value[i];
    }
    out[len] = L'\0';
    return (DWORD) len;
}

STATIC DWORD WINAPI GetEnvironmentVariableW(PWCHAR lpName, PVOID lpBuffer, DWORD nSize)
{
    char *AnsiName = CreateAnsiFromWide(lpName);
    const struct {
        const char *name;
        const char *value;
    } KnownValues[] = {
        { "MpAsyncWorkMaxThreads", "1" },
        { "MP_FOLDERSCAN_THREAD_COUNT", "1" },
        { "MP_PERSISTEDSTORE_DISABLE", "1" },
        { "MP_METASTORE_DISABLE", "1" },
        { "MpDumpUnpackedObjects", "0" },
        { "MpArchivePasswords", "0" },
        { "MpDisableVhdScanning", "0" },
        { "MpDisableExclusionScanDuringQuickScan", "0" },
        { "MPGEAR_SKIP_PERSISTENCE", "0" },
        { "UNPLIB_OVERRIDE_SIGNATURE", "0" },
        { "VFO::MaxBlockCount", "0" },
        { "ALLUSERSPROFILE", "C:\\ProgramData" },
        { "ALLUSERSAPPDATA", "C:\\ProgramData" },
        { "ProgramData", "C:\\ProgramData" },
        { "ProgramFiles", "C:\\Program Files" },
        { "ProgramW6432", "C:\\Program Files" },
        { "ProgramFiles(x86)", "C:\\Program Files (x86)" },
        { "Program_Files", "C:\\Program Files" },
        { "CommonProgramFiles", "C:\\Program Files\\Common Files" },
        { "CommonProgramFiles(x86)", "C:\\Program Files (x86)\\Common Files" },
        { "TEMP", "C:\\Windows\\Temp" },
        { "TMP", "C:\\Windows\\Temp" },
        { "windir", "C:\\Windows" },
        { "SystemRoot", "C:\\Windows" },
        { "SystemDrive", "C:" },
        { "Path", "C:\\Path" },
        { "ComSpec", "C:\\Windows\\System32\\cmd.exe" },
        { "USERPROFILE", "C:\\Users\\Default" },
        { "PUBLIC", "C:\\Users\\Public" },
        { "LOCALAPPDATA", "C:\\Users\\Default\\AppData\\Local" },
        { "APPDATA", "C:\\Users\\Default\\AppData\\Roaming" },
        { NULL, NULL },
    };
    DWORD result = 0;

    DebugLog("%p [%s], %p, %u", lpName, AnsiName, lpBuffer, nSize);

    if (lpBuffer && nSize) {
        memset(lpBuffer, 0, nSize * sizeof(WCHAR));
    }

    for (int i = 0; KnownValues[i].name; ++i) {
        if (strcasecmp(AnsiName, KnownValues[i].name) == 0) {
            result = WriteWideEnvValue(lpBuffer, nSize, KnownValues[i].value);
            SetLastError(0);
            free(AnsiName);
            return result;
        }
    }

    if (strncasecmp(AnsiName, "MP_", 3) == 0) {
        result = WriteWideEnvValue(lpBuffer, nSize, "1");
        SetLastError(0);
        free(AnsiName);
        return result;
    }

    if (strncasecmp(AnsiName, "VFO::", 5) == 0) {
        result = WriteWideEnvValue(lpBuffer, nSize, "0");
        SetLastError(0);
        free(AnsiName);
        return result;
    }

    const char *host_env = getenv(AnsiName);
    if (!host_env) {
        char *upper = strdup(AnsiName);
        if (upper) {
            for (char *p = upper; *p; ++p) {
                *p = (char) toupper((unsigned char) *p);
            }
            host_env = getenv(upper);
            free(upper);
        }
    }

    if (host_env) {
        result = WriteWideEnvValue(lpBuffer, nSize, host_env);
        SetLastError(0);
        free(AnsiName);
        return result;
    }

    LogMessage("GetEnvironmentVariableW: missing %s, defaulting to empty", AnsiName);
    result = WriteWideEnvValue(lpBuffer, nSize, "");
    SetLastError(0);

    free(AnsiName);
    return result;
}

// MPENGINE is very fussy about what ExpandEnvironmentStringsW returns.
STATIC DWORD WINAPI ExpandEnvironmentStringsW(PWCHAR lpSrc, PWCHAR lpDst, DWORD nSize)
{
    PCHAR AnsiString = CreateAnsiFromWide(lpSrc);
    DWORD Result;
    const char *programdata_token = "%ProgramData%";
    const PWCHAR programdata_replacement = L"C:\\ProgramData";
    struct {
        PCHAR   Src;
        PWCHAR  Dst;
    } KnownPaths[] = {
        { "%ProgramFiles%", L"C:\\Program Files" },
        { "%AllUsersProfile%", L"C:\\ProgramData" },
        { "%PATH%", L"C:\\Path" },
        { "%windir%", L"C:\\Windows" },
        { "%ProgramFiles(x86)%", L"C:\\Program Files" },
        { "%WINDIR%\\system32\\drivers", L"C:\\WINDOWS\\system32\\drivers" },
        { "%windir%\\temp", L"C:\\WINDOWS\\temp" },
        { "%CommonProgramFiles%", L"C:\\CommonProgramFiles" },
        { NULL },
    };

    DebugLog("%p [%s], %p, %u", lpSrc, AnsiString ? AnsiString : "(null)", lpDst, nSize);
    if (!lpSrc || !AnsiString) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        free(AnsiString);
        return 0;
    }

    if (AnsiString && AnsiString[0] == '%') {
        char *end = strchr(AnsiString + 1, '%');
        if (end) {
            size_t var_len = (size_t)(end - (AnsiString + 1));
            size_t suffix_len = CountWideChars(lpSrc + var_len + 2);
            WCHAR *var_name = calloc(var_len + 1, sizeof(WCHAR));
            if (var_name) {
                for (size_t i = 0; i < var_len; ++i) {
                    var_name[i] = (unsigned char)AnsiString[i + 1];
                }
                DWORD needed = GetEnvironmentVariableW(var_name, NULL, 0);
                size_t value_len = needed ? (size_t)(needed - 1) : 0;
                Result = (DWORD)(value_len + suffix_len + 1);
                if (!lpDst || nSize < Result) {
                    free(var_name);
                    goto finish;
                }
                DWORD copied = GetEnvironmentVariableW(var_name, lpDst, nSize);
                size_t used = copied;
                memcpy(lpDst + used,
                       lpSrc + var_len + 2,
                       (suffix_len + 1) * sizeof(WCHAR));
                free(var_name);
                goto finish;
            }
        }
    }

    for (int i = 0; KnownPaths[i].Src; i++) {
        if (strcmp(AnsiString, KnownPaths[i].Src) == 0) {
            Result = CountWideChars(KnownPaths[i].Dst) + 1;
            if (nSize < Result) {
                goto finish;
            }
            memcpy(lpDst, KnownPaths[i].Dst, Result * 2);
            goto finish;
        }
    }

    {
        char *match = AnsiString ? strcasestr(AnsiString, programdata_token) : NULL;
        if (match) {
            DebugLog("ExpandEnvironmentStringsW: expanding %s", AnsiString);
            size_t token_len = strlen(programdata_token);
            size_t prefix_len = (size_t)(match - AnsiString);
            size_t replacement_len = CountWideChars(programdata_replacement);
            size_t suffix_len = CountWideChars(lpSrc + prefix_len + token_len);
            Result = (DWORD)(prefix_len + replacement_len + suffix_len + 1);
            if (nSize < Result) {
                goto finish;
            }
            if (prefix_len > 0) {
                memcpy(lpDst, lpSrc, prefix_len * sizeof(WCHAR));
            }
            memcpy(lpDst + prefix_len,
                   programdata_replacement,
                   replacement_len * sizeof(WCHAR));
            memcpy(lpDst + prefix_len + replacement_len,
                   lpSrc + prefix_len + token_len,
                   (suffix_len + 1) * sizeof(WCHAR));
            goto finish;
        }
    }

    free(AnsiString);

    if (nSize < CountWideChars(lpSrc) + 1) {
        return CountWideChars(lpSrc) + 1;
    }

    memcpy(lpDst, lpSrc, (1 + CountWideChars(lpSrc)) * 2);

    return CountWideChars(lpSrc) + 1;

finish:
    free(AnsiString);
    return Result;
}

STATIC DWORD WINAPI ExpandEnvironmentStringsA(PCHAR lpSrc, PCHAR lpDst, DWORD nSize)
{
    const char *token = "%ProgramData%";
    const char *replacement = "C:\\ProgramData";
    size_t src_len;
    DWORD result;

    DebugLog("%p [%s], %p, %u", lpSrc, lpSrc ? lpSrc : "(null)", lpDst, nSize);

    if (!lpSrc) {
        return 0;
    }

    src_len = strlen(lpSrc);

    if (strcasestr(lpSrc, token)) {
        const char *match = strcasestr(lpSrc, token);
        DebugLog("ExpandEnvironmentStringsA: expanding %s", lpSrc);
        size_t token_len = strlen(token);
        size_t prefix_len = (size_t)(match - lpSrc);
        size_t replacement_len = strlen(replacement);
        size_t suffix_len = strlen(match + token_len);
        result = (DWORD)(prefix_len + replacement_len + suffix_len + 1);
        if (!lpDst || nSize < result) {
            return result;
        }
        if (prefix_len > 0) {
            memcpy(lpDst, lpSrc, prefix_len);
        }
        memcpy(lpDst + prefix_len, replacement, replacement_len);
        memcpy(lpDst + prefix_len + replacement_len,
               match + token_len,
               suffix_len + 1);
        return result;
    }

    result = (DWORD)(src_len + 1);
    if (!lpDst || nSize < result) {
        return result;
    }

    memcpy(lpDst, lpSrc, src_len + 1);
    return result;
}

STATIC BOOL WINAPI ExpandEnvironmentStringsForUserW(HANDLE hToken,
                                                    PWCHAR lpSrc,
                                                    PWCHAR lpDst,
                                                    DWORD nSize)
{
    DebugLog("%p, %p, %p, %u", hToken, lpSrc, lpDst, nSize);

    if (!lpSrc) {
        SetLastError(ERROR_ENVVAR_NOT_FOUND);
        return FALSE;
    }

    return ExpandEnvironmentStringsW(lpSrc, lpDst, nSize) != 0;
}

static DWORD WINAPI GetEnvironmentVariableA(PCHAR lpName, PVOID lpBuffer, DWORD nSize)
{
    DebugLog("%s, %p, %u", lpName, lpBuffer, nSize);
    return 0;
}

DECLARE_CRT_EXPORT("GetEnvironmentStringsW", GetEnvironmentStringsW);
DECLARE_CRT_EXPORT("FreeEnvironmentStringsW", FreeEnvironmentStringsW);
DECLARE_CRT_EXPORT("GetEnvironmentVariableW", GetEnvironmentVariableW);
DECLARE_CRT_EXPORT("ExpandEnvironmentStringsW", ExpandEnvironmentStringsW);
DECLARE_CRT_EXPORT("ExpandEnvironmentStringsA", ExpandEnvironmentStringsA);
DECLARE_CRT_EXPORT("ExpandEnvironmentStringsForUserW", ExpandEnvironmentStringsForUserW);
DECLARE_CRT_EXPORT("GetEnvironmentVariableA", GetEnvironmentVariableA);
