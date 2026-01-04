#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
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

typedef PVOID LPINIT_ONCE;
typedef BOOL *PBOOL;

static void *init_once_sentinel = (void *)1;

STATIC WINAPI BOOL InitOnceBeginInitialize(LPINIT_ONCE lpInitOnce,
                                           DWORD dwFlags,
                                           PBOOL fPending,
                                           PVOID *lpContext)
{
    void **slot = (void **)lpInitOnce;

    DebugLog("%p %hhx %p %p", lpInitOnce, dwFlags, fPending, lpContext);

    if (!slot || !fPending) {
        return FALSE;
    }

    if (*slot && *slot != init_once_sentinel) {
        *fPending = FALSE;
        if (lpContext) {
            *lpContext = *slot;
        }
        return TRUE;
    }

    if (*slot == init_once_sentinel) {
        *fPending = FALSE;
        if (lpContext) {
            *lpContext = NULL;
        }
        return TRUE;
    }

    *fPending = TRUE;
    if (lpContext) {
        *lpContext = NULL;
    }
    return TRUE;
}

STATIC WINAPI BOOL InitOnceComplete(LPINIT_ONCE lpInitOnce,
                                    DWORD dwFlags,
                                    PVOID lpContext)
{
    void **slot = (void **)lpInitOnce;

    DebugLog("%p %hhx %p", lpInitOnce, dwFlags, lpContext);

    if (!slot) {
        return FALSE;
    }

    if (lpContext) {
        *slot = lpContext;
    } else {
        *slot = init_once_sentinel;
    }

    return TRUE;
}

DECLARE_CRT_EXPORT("InitOnceBeginInitialize", InitOnceBeginInitialize);
DECLARE_CRT_EXPORT("InitOnceComplete", InitOnceComplete);
