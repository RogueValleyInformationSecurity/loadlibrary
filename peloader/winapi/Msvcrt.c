//
// MSVCRT stubs for libargon2.dll and similar DLLs
//
// This provides common C runtime functions needed by Windows DLLs
//

#include <sys/types.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "util.h"
#include "winexports.h"

// Fake FILE structures for stdin/stdout/stderr
static struct {
    int fd;
    char padding[64];
} fake_iob[3] = {
    { .fd = 0 },  // stdin
    { .fd = 1 },  // stdout
    { .fd = 2 },  // stderr
};

// __iob_func - returns array of FILE* for stdin/stdout/stderr
static PVOID WINAPI MsvcrtIobFunc(void)
{
    return fake_iob;
}

// Thread wrapper for _beginthreadex
// The start_address is a Windows function, so we need to call it using ms_abi
// The wrapper itself is called by pthread (sysv_abi), so we need to convert
typedef unsigned (WINCALL *thread_start_fn)(void*);

struct thread_params {
    thread_start_fn start_address;  // Windows ABI function
    void *arglist;
};

static void* thread_wrapper(void *arg)
{
    struct thread_params *params = (struct thread_params*)arg;
    // Call the Windows function using ms_abi (WINCALL)
    unsigned result = params->start_address(params->arglist);
    free(params);
    return (void*)(uintptr_t)result;
}

// _beginthreadex - create a thread
static uintptr_t WINAPI MsvcrtBeginthreadex(
    void *security,
    unsigned stack_size,
    thread_start_fn start_address,  // Windows ABI function
    void *arglist,
    unsigned initflag,
    unsigned *thrdaddr)
{
    (void)security;
    (void)stack_size;
    (void)initflag;

    DebugLog("start=%p arg=%p", start_address, arglist);

    struct thread_params *params = malloc(sizeof(*params));
    if (!params) return 0;

    params->start_address = start_address;
    params->arglist = arglist;

    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_wrapper, params) != 0) {
        free(params);
        return 0;
    }

    if (thrdaddr) {
        *thrdaddr = (unsigned)(uintptr_t)thread;
    }

    return (uintptr_t)thread;
}

// _endthreadex - terminate thread
static void WINAPI MsvcrtEndthreadex(unsigned retval)
{
    DebugLog("retval=%u", retval);
    pthread_exit((void*)(uintptr_t)retval);
}

// _amsg_exit - runtime error exit
static void WINAPI MsvcrtAmsgExit(int errnum)
{
    DebugLog("errnum=%d", errnum);
    _exit(errnum);
}

// _initterm - call array of initializers
// NOTE: Disabled for fuzzing - the initializer table pointers may not be
// properly relocated by the PE loader, causing crashes. For libargon2.dll
// this is safe to skip as the library works without CRT initializers.
static void WINAPI MsvcrtInitterm(void (**pfbegin)(void), void (**pfend)(void))
{
    DebugLog("pfbegin=%p pfend=%p (SKIPPED - initializers disabled for fuzzing)", pfbegin, pfend);
    // Skip calling initializers - they may have bad relocations
    (void)pfbegin;
    (void)pfend;
}

// _initterm_e - call array of initializers with error checking
// NOTE: Disabled for fuzzing - same reason as _initterm above
static int WINAPI MsvcrtInittermE(int (**pfbegin)(void), int (**pfend)(void))
{
    DebugLog("pfbegin=%p pfend=%p (SKIPPED - initializers disabled for fuzzing)", pfbegin, pfend);
    (void)pfbegin;
    (void)pfend;
    return 0;
}

// Lock stubs - single-threaded fuzzing doesn't need real locking
static pthread_mutex_t crt_lock = PTHREAD_MUTEX_INITIALIZER;

static void WINAPI MsvcrtLock(int locknum)
{
    (void)locknum;
    pthread_mutex_lock(&crt_lock);
}

static void WINAPI MsvcrtUnlock(int locknum)
{
    (void)locknum;
    pthread_mutex_unlock(&crt_lock);
}

// _vscprintf - calculate length needed for vsprintf
static int WINAPI MsvcrtVscprintf(const char *format, va_list argptr)
{
    return vsnprintf(NULL, 0, format, argptr);
}

// _write - write to file descriptor
static int WINAPI MsvcrtWrite(int fd, const void *buffer, unsigned count)
{
    return write(fd, buffer, count);
}

// abort - terminate program
static void WINAPI MsvcrtAbort(void)
{
    DebugLog("abort() called");
    abort();
}

// Memory allocation - forward to native libc
static PVOID WINAPI MsvcrtCalloc(size_t num, size_t size)
{
    return calloc(num, size);
}

static PVOID WINAPI MsvcrtMalloc(size_t size)
{
    return malloc(size);
}

static void WINAPI MsvcrtFree(void *ptr)
{
    free(ptr);
}

static PVOID WINAPI MsvcrtRealloc(void *ptr, size_t size)
{
    return realloc(ptr, size);
}

// File I/O
static size_t WINAPI MsvcrtFwrite(const void *ptr, size_t size, size_t nmemb, void *stream)
{
    // stream is a fake FILE*, extract fd
    if (!stream) return 0;
    int fd = *(int*)stream;
    if (fd < 0 || fd > 2) fd = 1; // default to stdout

    ssize_t written = write(fd, ptr, size * nmemb);
    return written > 0 ? (size_t)written / size : 0;
}

static int WINAPI MsvcrtVfprintf(void *stream, const char *format, va_list argptr)
{
    char buf[4096];
    int len = vsnprintf(buf, sizeof(buf), format, argptr);
    if (len > 0) {
        int fd = stream ? *(int*)stream : 1;
        if (fd < 0 || fd > 2) fd = 1;
        ssize_t w = write(fd, buf, len);
        (void)w;
    }
    return len;
}

static int WINAPI MsvcrtFprintf(void *stream, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    int result = MsvcrtVfprintf(stream, format, args);
    va_end(args);
    return result;
}

// Memory/string functions with ms_abi (required for 64-bit)
static PVOID WINAPI MsvcrtMemcpy(void *dest, const void *src, size_t n)
{
    return memcpy(dest, src, n);
}

static PVOID WINAPI MsvcrtMemset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

static size_t WINAPI MsvcrtStrlen(const char *s)
{
    return strlen(s);
}

static int WINAPI MsvcrtStrncmp(const char *s1, const char *s2, size_t n)
{
    return strncmp(s1, s2, n);
}

// NOTE: _vsnprintf with va_list is problematic because va_list types differ
// between MS ABI (char*) and System V ABI (struct). We stub this out safely.
static int WINAPI MsvcrtVsnprintf(char *str, size_t size, const char *format, void *ap)
{
    (void)format;
    (void)ap;
    // Just return the format string without expansion
    if (str && size > 0 && format) {
        size_t len = strlen(format);
        if (len >= size) len = size - 1;
        memcpy(str, format, len);
        str[len] = '\0';
        return (int)len;
    }
    return 0;
}

// Export table
DECLARE_CRT_EXPORT("__iob_func", MsvcrtIobFunc);
DECLARE_CRT_EXPORT("_beginthreadex", MsvcrtBeginthreadex);
DECLARE_CRT_EXPORT("_endthreadex", MsvcrtEndthreadex);
DECLARE_CRT_EXPORT("_amsg_exit", MsvcrtAmsgExit);
DECLARE_CRT_EXPORT("_initterm", MsvcrtInitterm);
DECLARE_CRT_EXPORT("_initterm_e", MsvcrtInittermE);
DECLARE_CRT_EXPORT("_lock", MsvcrtLock);
DECLARE_CRT_EXPORT("_unlock", MsvcrtUnlock);
DECLARE_CRT_EXPORT("_vscprintf", MsvcrtVscprintf);
DECLARE_CRT_EXPORT("_write", MsvcrtWrite);
DECLARE_CRT_EXPORT("abort", MsvcrtAbort);
DECLARE_CRT_EXPORT("calloc", MsvcrtCalloc);
DECLARE_CRT_EXPORT("malloc", MsvcrtMalloc);
DECLARE_CRT_EXPORT("free", MsvcrtFree);
DECLARE_CRT_EXPORT("realloc", MsvcrtRealloc);
DECLARE_CRT_EXPORT("fwrite", MsvcrtFwrite);
DECLARE_CRT_EXPORT("vfprintf", MsvcrtVfprintf);
DECLARE_CRT_EXPORT("fprintf", MsvcrtFprintf);
DECLARE_CRT_EXPORT("memcpy", MsvcrtMemcpy);
DECLARE_CRT_EXPORT("memset", MsvcrtMemset);
DECLARE_CRT_EXPORT("strlen", MsvcrtStrlen);
DECLARE_CRT_EXPORT("strncmp", MsvcrtStrncmp);
DECLARE_CRT_EXPORT("_vsnprintf", MsvcrtVsnprintf);
