//
// Copyright (C) 2017 Tavis Ormandy
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <assert.h>
#include <string.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/unistd.h>
#include <asm/unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>
#include <fenv.h>
#include <ucontext.h>
#include <fcntl.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>
#include <limits.h>
#include <strings.h>
#include <wchar.h>
#include <xmmintrin.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"
#include "hook.h"
#include "mpclient.h"

struct pe_image image = {
        .entry  = NULL,
        .name   = "engine/x64/mpengine.dll",
};

static wchar_t g_stream_name[PATH_MAX * 2];
static char g_stream_path[PATH_MAX];
static const wchar_t k_default_stream_name[] = L"C:\\mpclient.input";

static void patch_mpengine_global_writes(void *image_base, size_t image_size)
{
    static const struct {
        size_t rva;
        size_t len;
    } patches[] = {
        { 0x557bec, 7 },
        { 0x557bf3, 7 },
        { 0x557bfa, 7 },
        { 0x557c01, 7 },
        { 0x938063, 3 },
        { 0x938093, 3 },
    };
    uint8_t *base = (uint8_t *)image_base;

    if (!base) {
        return;
    }

    for (size_t i = 0; i < (sizeof(patches) / sizeof(patches[0])); ++i) {
        if (image_size < (patches[i].rva + patches[i].len)) {
            continue;
        }
        memset(base + patches[i].rva, 0x90, patches[i].len);
    }
}

static void patch_throw_call_sites(uint8_t *base, size_t image_size, size_t throw_rva)
{
    if (!base || image_size < sizeof(IMAGE_DOS_HEADER)) {
        return;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER) base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }

    if ((size_t) dos->e_lfanew > image_size - sizeof(IMAGE_NT_HEADERS)) {
        return;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS) (base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }

    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (memcmp(sec[i].Name, ".text", 5) != 0) {
            continue;
        }

        size_t rva = sec[i].VirtualAddress;
        size_t len = sec[i].Misc.VirtualSize;
        if (rva >= image_size) {
            return;
        }
        if (rva + len > image_size) {
            len = image_size - rva;
        }

        uint8_t *text = base + rva;

        for (size_t off = 0; off + 5 < len; ++off) {
            if (text[off] != 0xE8) {
                continue;
            }

            int32_t rel = 0;
            memcpy(&rel, text + off + 1, sizeof(rel));
            uint8_t *target = text + off + 5 + rel;
            if (target != base + throw_rva) {
                continue;
            }

            uint8_t *after = text + off + 5;
            if (*after == 0xCC) {
                *after = 0x90;
            }
        }
        return;
    }
}

enum patch_mode {
    PATCH_NONE,
    PATCH_INT3,
    PATCH_NOTHROW,
    PATCH_FULL
};

struct mpengine_patch {
    size_t rva;
    uint8_t expected[8];
    uint8_t replacement[8];
    size_t len;
};

static void apply_mpengine_patches(void *image_base,
                                   size_t image_size,
                                   const struct mpengine_patch *patches,
                                   size_t patch_count)
{
    uint8_t *base = (uint8_t *)image_base;

    if (!base) {
        return;
    }

    for (size_t i = 0; i < patch_count; ++i) {
        if (image_size < (patches[i].rva + patches[i].len)) {
            continue;
        }
        if (memcmp(base + patches[i].rva, patches[i].replacement, patches[i].len) == 0) {
            continue;
        }
        if (memcmp(base + patches[i].rva, patches[i].expected, patches[i].len) != 0) {
            LogMessage("mpengine patch mismatch at %#zx", patches[i].rva);
            continue;
        }
        memcpy(base + patches[i].rva, patches[i].replacement, patches[i].len);
    }
}

static void patch_mpengine_bytes(void *image_base, size_t image_size, enum patch_mode mode)
{
    static const struct mpengine_patch patches[] = {
        { 0x28201c, { 0x48, 0x89, 0x5c }, { 0x31, 0xc0, 0xc3 }, 3 },
        { 0x2b7f0e, { 0x78, 0x05 }, { 0x90, 0x90 }, 2 },
        { 0x1536c6, { 0x74, 0x2a }, { 0x74, 0x68 }, 2 },
        { 0x2f7be, { 0xcc }, { 0x90 }, 1 },
        { 0x2f825, { 0xcc }, { 0x90 }, 1 },
        { 0x2f835, { 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90 }, 3 },
        { 0x30b68, { 0xcc }, { 0x90 }, 1 },
        { 0x667650, { 0x48, 0x89, 0x5c }, { 0x31, 0xc0, 0xc3 }, 3 },
        { 0x6676e8, { 0xcc, 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90, 0x90 }, 4 },
        { 0x6676ec, { 0x48, 0x83, 0xec }, { 0x31, 0xc0, 0xc3 }, 3 },
        { 0x08a4aa, { 0xcc }, { 0x90 }, 1 },
        { 0x089ef7, { 0x48, 0x8b }, { 0xeb, 0x0e }, 2 },
        { 0x93e34e, { 0x66 }, { 0xf3 }, 1 },
        { 0x9749b5, { 0xcc }, { 0x90 }, 1 },
        { 0x9576de, { 0xcc, 0xcc }, { 0x90, 0x90 }, 2 },
        { 0x95770c, { 0xcc }, { 0x90 }, 1 },
        { 0x95770d, { 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90 }, 3 },
    };
    static const struct mpengine_patch nothrow_patches[] = {
        { 0x28201c, { 0x48, 0x89, 0x5c }, { 0x31, 0xc0, 0xc3 }, 3 },
        { 0x2b7f0e, { 0x78, 0x05 }, { 0x90, 0x90 }, 2 },
        { 0x1536c6, { 0x74, 0x2a }, { 0x74, 0x68 }, 2 },
        { 0x2f7be, { 0xcc }, { 0x90 }, 1 },
        { 0x2f825, { 0xcc }, { 0x90 }, 1 },
        { 0x2f835, { 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90 }, 3 },
        { 0x30b68, { 0xcc }, { 0x90 }, 1 },
        { 0x6676e8, { 0xcc, 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90, 0x90 }, 4 },
        { 0x08a4aa, { 0xcc }, { 0x90 }, 1 },
        { 0x089ef7, { 0x48, 0x8b }, { 0xeb, 0x0e }, 2 },
        { 0x93e34e, { 0x66 }, { 0xf3 }, 1 },
        { 0x9749b5, { 0xcc }, { 0x90 }, 1 },
        { 0x9576de, { 0xcc, 0xcc }, { 0x90, 0x90 }, 2 },
        { 0x95770c, { 0xcc }, { 0x90 }, 1 },
        { 0x95770d, { 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90 }, 3 },
        { 0x6676ec, { 0x48, 0x83, 0xec }, { 0x31, 0xc0, 0xc3 }, 3 },
    };
    static const struct mpengine_patch int3_patches[] = {
        { 0x2f7be, { 0xcc }, { 0x90 }, 1 },
        { 0x2f825, { 0xcc }, { 0x90 }, 1 },
        { 0x2f835, { 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90 }, 3 },
        { 0x30b68, { 0xcc }, { 0x90 }, 1 },
        { 0x6676e8, { 0xcc, 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90, 0x90 }, 4 },
        { 0x08a4aa, { 0xcc }, { 0x90 }, 1 },
        { 0x9749b5, { 0xcc }, { 0x90 }, 1 },
        { 0x9576de, { 0xcc, 0xcc }, { 0x90, 0x90 }, 2 },
        { 0x95770c, { 0xcc }, { 0x90 }, 1 },
        { 0x95770d, { 0xcc, 0xcc, 0xcc }, { 0x90, 0x90, 0x90 }, 3 },
    };
    uint8_t *base = (uint8_t *)image_base;

    if (mode == PATCH_NONE) {
        return;
    }

    if (mode == PATCH_INT3) {
        apply_mpengine_patches(image_base,
                               image_size,
                               int3_patches,
                               sizeof(int3_patches) / sizeof(int3_patches[0]));
    } else if (mode == PATCH_NOTHROW) {
        apply_mpengine_patches(image_base,
                               image_size,
                               nothrow_patches,
                               sizeof(nothrow_patches) / sizeof(nothrow_patches[0]));
    } else {
        apply_mpengine_patches(image_base,
                               image_size,
                               patches,
                               sizeof(patches) / sizeof(patches[0]));
    }

    patch_throw_call_sites(base, image_size, 0x92977c);
    patch_throw_call_sites(base, image_size, 0x667650);
}

static void patch_mpengine_scan_bytes(void *image_base, size_t image_size, enum patch_mode mode)
{
    static const struct mpengine_patch scan_patches[] = {
    };

    if (mode != PATCH_FULL && mode != PATCH_NOTHROW) {
        return;
    }

    apply_mpengine_patches(image_base,
                           image_size,
                           scan_patches,
                           sizeof(scan_patches) / sizeof(scan_patches[0]));
}

static enum patch_mode mpengine_patch_mode(void)
{
    const char *env = getenv("MPCLIENT_PATCH_ENGINE");

    if (!env || *env == '\0') {
        return PATCH_FULL;
    }

    if (!strcasecmp(env, "0") || !strcasecmp(env, "off") || !strcasecmp(env, "false")) {
        return PATCH_NONE;
    }
    if (!strcasecmp(env, "int3") || !strcasecmp(env, "lite")) {
        return PATCH_INT3;
    }
    if (!strcasecmp(env, "nothrow") || !strcasecmp(env, "no-throw")) {
        return PATCH_NOTHROW;
    }

    return atoi(env) != 0 ? PATCH_FULL : PATCH_NONE;
}

// Any usage limits to prevent bugs disrupting system.
const struct rlimit kUsageLimits[] = {
    [RLIMIT_FSIZE]  = { .rlim_cur = 0x20000000, .rlim_max = 0x20000000 },
    [RLIMIT_CPU]    = { .rlim_cur = 3600,       .rlim_max = RLIM_INFINITY },
    [RLIMIT_CORE]   = { .rlim_cur = 0,          .rlim_max = 0 },
    [RLIMIT_NOFILE] = { .rlim_cur = 32,         .rlim_max = 32 },
};

DWORD WINAPI (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);

static DWORD WINAPI EngineScanCallback(PSCANSTRUCT Scan)
{
    if (Scan->Flags & SCAN_MEMBERNAME) {
        LogMessage("Scanning archive member %s", Scan->VirusName);
    }
    if (Scan->Flags & SCAN_FILENAME) {
        LogMessage("Scanning %s", Scan->FileName);
    }
    if (Scan->Flags & SCAN_PACKERSTART) {
        LogMessage("Packer %s identified.", Scan->VirusName);
    }
    if (Scan->Flags & SCAN_ENCRYPTED) {
        LogMessage("File is encrypted.");
    }
    if (Scan->Flags & SCAN_CORRUPT) {
        LogMessage("File may be corrupt.");
    }
    if (Scan->Flags & SCAN_FILETYPE) {
        LogMessage("File %s is identified as %s", Scan->FileName, Scan->VirusName);
    }
    if (Scan->Flags & 0x08000022) {
        LogMessage("Threat %s identified.", Scan->VirusName);
    }
    // This may indicate PUA.
    if ((Scan->Flags & 0x40010000) == 0x40010000) {
        LogMessage("Threat %s identified.", Scan->VirusName);
    }
    return 0;
}

static DWORD WINAPI ReadStream(PVOID this, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    fseek(this, Offset, SEEK_SET);
    *SizeRead = fread(Buffer, 1, Size, this);
    return TRUE;
}

static DWORD WINAPI WriteStream(PVOID this,
                                ULONGLONG Offset,
                                PVOID Buffer,
                                DWORD Size,
                                PDWORD TotalWritten)
{
    (void)this;
    (void)Offset;
    (void)Buffer;
    if (TotalWritten) {
        *TotalWritten = 0;
    }
    return TRUE;
}

static DWORD WINAPI SetStreamSize(PVOID this, PULONGLONG FileSize)
{
    (void)this;
    (void)FileSize;
    return TRUE;
}

static DWORD WINAPI GetStreamSize(PVOID this, PULONGLONG FileSize)
{
    fseek(this, 0, SEEK_END);
    *FileSize = ftell(this);
    return TRUE;
}

static DWORD WINAPI GetStreamAttributes(PVOID this,
                                        DWORD Attribute,
                                        PVOID Data,
                                        DWORD DataSize,
                                        PDWORD DataSizeWritten)
{
    FILE *fp = (FILE *)this;
    struct stat st;
    bool have_stat = false;

    if (fp && fstat(fileno(fp), &st) == 0) {
        have_stat = true;
    }

    if (DataSizeWritten) {
        *DataSizeWritten = 0;
    }

    switch (Attribute) {
        case STREAM_ATTRIBUTE_SCANREASON:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = SCANREASON_ONOPEN;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILE_ATTRIBUTES:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 0x80; // FILE_ATTRIBUTE_NORMAL
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILEOPPROCESSID:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = (DWORD)getpid();
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_DONOTCACHESCANRESULT:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 1;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILEID:
            if (Data && DataSize >= sizeof(ULONGLONG)) {
                *(ULONGLONG *)Data = have_stat ? (ULONGLONG)st.st_ino : 0;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(ULONGLONG);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILEVOLUMESERIALNUMBER:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = have_stat ? (DWORD)st.st_dev : 0;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_REQUESTORMODE:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 0;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILECOPYPERFHINT:
            if (DataSizeWritten) {
                *DataSizeWritten = sizeof(DWORD);
            }
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 0;
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILECOPYSOURCEPATH: {
            const wchar_t *name = g_stream_name[0] ? g_stream_name : k_default_stream_name;
            DWORD needed = (DWORD)((wcslen(name) + 1) * sizeof(WCHAR));
            if (DataSizeWritten) {
                *DataSizeWritten = needed;
            }
            if (!Data || DataSize < needed) {
                return FALSE;
            }
            memcpy(Data, name, needed);
            return TRUE;
        }
        case STREAM_ATTRIBUTE_FILE_OPERATION_PPID:
            if (Data && DataSize >= sizeof(DWORD)) {
                memset(Data, 0, DataSize);
                *(DWORD *)Data = (DWORD)getppid();
                if (DataSizeWritten) {
                    *DataSizeWritten = DataSize;
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILEOPPROCESSNAME:
            if (Data && DataSize >= sizeof(WCHAR)) {
                ((PWCHAR)Data)[0] = L'\0';
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(WCHAR);
                }
                return TRUE;
            }
            if (DataSizeWritten) {
                *DataSizeWritten = sizeof(WCHAR);
            }
            return FALSE;
        case STREAM_ATTRIBUTE_OPEN_CREATEPROCESS_HINT:
        case STREAM_ATTRIBUTE_IS_CONTAINER_FILE:
        case STREAM_ATTRIBUTE_DEVICE_CHARACTERISTICS:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 0;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_SESSION_ID:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 0;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(DWORD);
                }
                return TRUE;
            }
            return FALSE;
        case 74: // STREAM_ATTRIBUTE 74 observed in newer engines; return empty payload.
            if (DataSizeWritten) {
                *DataSizeWritten = DataSize;
            }
            if (Data && DataSize) {
                memset(Data, 0, DataSize);
                return TRUE;
            }
            return DataSize == 0;
        case 86: // STREAM_ATTRIBUTE 86 observed in newer engines; treat as present but empty.
            if (Data && DataSize) {
                memset(Data, 0, DataSize);
                if (DataSizeWritten) {
                    *DataSizeWritten = DataSize;
                }
            } else if (DataSizeWritten) {
                *DataSizeWritten = 0;
            }
            return TRUE;
        default:
            if (DataSizeWritten) {
                *DataSizeWritten = 0;
            }
            return FALSE;
    }
}

static DWORD WINAPI SetStreamAttributes(PVOID this __attribute__((unused)),
                                        DWORD Attribute __attribute__((unused)),
                                        PVOID Data __attribute__((unused)),
                                        DWORD DataSize __attribute__((unused)))
{
    return TRUE;
}

static PWCHAR WINAPI GetStreamName(PVOID this)
{
    if (!g_stream_name[0]) {
        return (PWCHAR)k_default_stream_name;
    }
    return g_stream_name;
}

static void MaskFpExceptions(void)
{
    unsigned int csr = _mm_getcsr();

    feclearexcept(FE_ALL_EXCEPT);
    csr &= ~0x3f;
    csr |= 0x1f80;
    _mm_setcsr(csr);
}

static void SigFpeHandler(int sig, siginfo_t *info, void *ctx)
{
    (void)sig;
    (void)info;
    (void)ctx;

    MaskFpExceptions();

#if defined(__x86_64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    if (uc && uc->uc_mcontext.fpregs) {
        struct _libc_fpstate *fp = uc->uc_mcontext.fpregs;
#ifdef __USE_MISC
        fp->mxcsr = (fp->mxcsr | 0x1f80) & ~0x3f;
#else
        fp->__mxcsr = (fp->__mxcsr | 0x1f80) & ~0x3f;
#endif
    }
#endif
}

static void *g_image_base = NULL;
static size_t g_image_size = 0;
static volatile sig_atomic_t g_in_scan = 0;
static sigjmp_buf g_scan_jmpbuf;

static void SigSegvHandler(int sig, siginfo_t *info, void *ctx)
{
    (void)sig;
    (void)info;
    (void)ctx;

    if (g_in_scan) {
        // During scan, try to recover by jumping back to scan loop
        siglongjmp(g_scan_jmpbuf, 1);
    }
    // If not in scan, let it crash normally
    signal(SIGSEGV, SIG_DFL);
    raise(SIGSEGV);
}

static void SigTrapHandler(int sig, siginfo_t *info, void *ctx)
{
    (void)sig;
    (void)info;

#if defined(__x86_64__)
    ucontext_t *uc = (ucontext_t *)ctx;
    if (uc) {
        unsigned char *rip = (unsigned char *)uc->uc_mcontext.gregs[REG_RIP];
        unsigned char *base = (unsigned char *)g_image_base;
        unsigned char *end = base + g_image_size;

        // Only skip INT3 instructions within the loaded PE image
        if (base && rip >= base && rip < end) {
            while (rip < end && *rip == 0xCC) {
                uc->uc_mcontext.gregs[REG_RIP]++;
                rip++;
            }
        }
    }
#endif
}

static void SetStreamNameFromPath(const char *path)
{
    char resolved[PATH_MAX];
    const char *use_path = path;
    const char *base = NULL;
    FILE *src = NULL;
    FILE *dst = NULL;
    char dst_path[PATH_MAX];
    char win_path[PATH_MAX];
    bool copied = false;
    char buf[8192];
    size_t nread;

    if (path && realpath(path, resolved)) {
        use_path = resolved;
    }

    if (use_path) {
        const char *slash = strrchr(use_path, '/');
        const char *bslash = strrchr(use_path, '\\');
        const char *sep = slash;
        if (bslash && (!sep || bslash > sep)) {
            sep = bslash;
        }
        base = sep ? sep + 1 : use_path;
    }

    if (!base || *base == '\0') {
        base = "mpclient.input";
    }

    snprintf(dst_path, sizeof(dst_path), "c:/%s", base);
    snprintf(win_path, sizeof(win_path), "C:\\%s", base);

    if (use_path) {
        src = fopen(use_path, "rb");
        if (src) {
            dst = fopen(dst_path, "wb");
            if (dst) {
                while ((nread = fread(buf, 1, sizeof(buf), src)) > 0) {
                    fwrite(buf, 1, nread, dst);
                }
                copied = true;
                fclose(dst);
            } else {
                LogMessage("Failed to write %s", dst_path);
            }
            fclose(src);
        } else {
            LogMessage("Failed to open %s for %s", use_path, dst_path);
        }
    }

    if (copied) {
        strncpy(g_stream_path, dst_path, sizeof(g_stream_path));
    } else if (use_path) {
        strncpy(g_stream_path, use_path, sizeof(g_stream_path));
    } else {
        g_stream_path[0] = '\0';
    }
    g_stream_path[sizeof(g_stream_path) - 1] = '\0';

    mbstowcs(g_stream_name, win_path, sizeof(g_stream_name) / sizeof(g_stream_name[0]));
    g_stream_name[(sizeof(g_stream_name) / sizeof(g_stream_name[0])) - 1] = L'\0';
}

// These are available for pintool.
BOOL __noinline InstrumentationCallback(PVOID ImageStart, SIZE_T ImageSize)
{
    // Prevent the call from being optimized away.
    asm volatile ("");
    return TRUE;
}

int main(int argc, char **argv, char **envp)
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    HANDLE KernelHandle;
    uint8_t ScanReplyStorage[32];
    PSCAN_REPLY ScanReply = (PSCAN_REPLY)ScanReplyStorage;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;
    ENGINE_CONTEXT EngineContext;

    // Load the mpengine module.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        LogMessage("You must add the dll and vdm files to the engine directory");
        return 1;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);

    // Store image bounds for SIGTRAP handler to skip INT3 padding
    g_image_base = image.image;
    g_image_size = image.size;

    // Fetch the headers to get base offsets.
    DosHeader   = (PIMAGE_DOS_HEADER) image.image;
    PeHeader    = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

    // Load any additional exports.
    if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/x64/mpengine.map")) {
#ifndef NDEBUG
        LogMessage("The map file wasn't found, symbols wont be available");
#endif
    } else {
        // Calculate the commands needed to get export and map symbols visible in gdb.
        if (IsGdbPresent()) {
            LogMessage("GDB: add-symbol-file %s %#x+%#x",
                       image.name,
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode);
            LogMessage("GDB: shell bash genmapsym.sh %#x+%#x symbols_%d.o < %s",
                       image.image,
                       PeHeader->OptionalHeader.BaseOfCode,
                       getpid(),
                       "engine/mpengine.map");
            LogMessage("GDB: add-symbol-file symbols_%d.o 0", getpid());
            __debugbreak();
        }
    }

    if (get_export("__rsignal", &__rsignal) == -1) {
        errx(EXIT_FAILURE, "Failed to resolve mpengine entrypoint");
    }

    EXCEPTION_DISPOSITION ExceptionHandler(struct _EXCEPTION_RECORD *ExceptionRecord __attribute__((unused)),
            struct _EXCEPTION_FRAME *EstablisherFrame __attribute__((unused)),
            struct _CONTEXT *ContextRecord __attribute__((unused)),
            struct _EXCEPTION_FRAME **DispatcherContext __attribute__((unused)))
    {
        DWORD code = ExceptionRecord ? ExceptionRecord->ExceptionCode : 0;
        if (code == 0xE06D7363) {
            return ExceptionContinueSearch;
        }

        return ExceptionContinueExecution;
    }

    VOID ResourceExhaustedHandler(int Signal)
    {
        errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
    }

    if (argc < 2) {
        LogMessage("usage: %s [filenames...]", *argv);
        return 1;
    }

    struct sigaction trap_action;
    memset(&trap_action, 0, sizeof(trap_action));
    trap_action.sa_sigaction = SigTrapHandler;
    trap_action.sa_flags = SA_SIGINFO;
    sigemptyset(&trap_action.sa_mask);
    sigaction(SIGTRAP, &trap_action, NULL);
    setup_nt_threadinfo(ExceptionHandler);

    // Call DllMain()
    image.entry((PVOID) 'MPENENGN', DLL_PROCESS_ATTACH, NULL);

    enum patch_mode patch_mode = mpengine_patch_mode();
    if (patch_mode != PATCH_NONE) {
        patch_mpengine_bytes(image.image, image.size, patch_mode);
    }

    // Install usage limits to prevent system crash.
    setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
    setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);
    setrlimit(RLIMIT_FSIZE, &kUsageLimits[RLIMIT_FSIZE]);
    setrlimit(RLIMIT_NOFILE, &kUsageLimits[RLIMIT_NOFILE]);

    signal(SIGXCPU, ResourceExhaustedHandler);
    signal(SIGXFSZ, ResourceExhaustedHandler);
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = SigFpeHandler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGFPE, &sa, NULL);
    }
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_sigaction = SigSegvHandler;
        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGSEGV, &sa, NULL);
    }
    MaskFpExceptions();

# ifndef NDEBUG
    // Enable Maximum heap checking.
    mcheck_pedantic(NULL);
# endif

    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);
    ZeroMemory(&EngineContext, sizeof EngineContext);

    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.Attributes    = BOOT_ATTR_NORMAL;
    BootParams.SignatureLocation = L"c:\\engine\\x64";
    BootParams.BootFlags = BOOT_REALTIMESIGS;
    BootParams.ProductName = L"Legitimate Antivirus";
    EngineConfig.QuarantineLocation = L"c:\\quarantine";
    EngineConfig.Inclusions = L"*.*";
    EngineConfig.EngineFlags = ENGINE_UNPACK;
    BootParams.EngineInfo = &EngineInfo;
    BootParams.EngineConfig = &EngineConfig;
    KernelHandle = NULL;

    {
        DWORD boot_status = __rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof BootParams);
        if (boot_status != 0 && boot_status != 0xa005) {
            LogMessage("__rsignal(RSIG_BOOTENGINE) returned %#x, missing definitions?", boot_status);
            LogMessage("Make sure the VDM files and mpengine.dll are in the engine directory");
            return 1;
        }
    }

    if (!KernelHandle) {
        DWORD ctx_status = __rsignal(&KernelHandle,
                                     RSIG_INIT_ENGINE_CONTEXT,
                                     &EngineContext,
                                     sizeof EngineContext);
        (void)ctx_status;
    }

    {
        DWORD init_status = __rsignal(&KernelHandle, RSIG_COMPLETE_INITIALIZATION, NULL, 0);
        if (init_status != 0) {
            LogMessage("__rsignal(RSIG_COMPLETE_INITIALIZATION) returned %#x", init_status);
        }
    }

    ZeroMemory(&ScanParams, sizeof ScanParams);
    ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
    ZeroMemory(ScanReplyStorage, sizeof ScanReplyStorage);

    ScanParams.Descriptor        = &ScanDescriptor;
    ScanParams.ScanReply         = ScanReply;
    ScanReply->EngineScanCallback = EngineScanCallback;
    ScanReply->field_C            = 0x7fffffff;
    *(DWORD *)(ScanReplyStorage + 24) = 0x7fffffff;
    ScanDescriptor.Read          = ReadStream;
    ScanDescriptor.Write         = WriteStream;
    ScanDescriptor.GetSize       = GetStreamSize;
    ScanDescriptor.SetSize       = SetStreamSize;
    ScanDescriptor.GetName       = GetStreamName;
    ScanDescriptor.GetAttributes = GetStreamAttributes;
    ScanDescriptor.SetAttributes = SetStreamAttributes;

    // Enable Instrumentation.
    InstrumentationCallback(image.image, image.size);

    patch_mpengine_scan_bytes(image.image, image.size, patch_mode);

    for (char *filename = *++argv; *argv; ++argv) {
        SetStreamNameFromPath(*argv);
        const char *open_path = g_stream_path[0] ? g_stream_path : *argv;
        ScanDescriptor.UserPtr = fopen(open_path, "rb");

        if (ScanDescriptor.UserPtr == NULL) {
            LogMessage("failed to open file %s", open_path);
            continue;
        }

        LogMessage("Scanning %s...", *argv);
        sigaction(SIGTRAP, &trap_action, NULL);

        // Set up crash recovery point
        g_in_scan = 1;
        if (sigsetjmp(g_scan_jmpbuf, 1) != 0) {
            // Recovered from crash during scan
            LogMessage("Scan crashed, skipping file %s", *argv);
            g_in_scan = 0;
            if (ScanDescriptor.UserPtr) {
                fclose(ScanDescriptor.UserPtr);
                ScanDescriptor.UserPtr = NULL;
            }
            continue;
        }

        DWORD scan_status = __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);
        g_in_scan = 0;

        if (scan_status != 0) {
            LogMessage("__rsignal(RSIG_SCAN_STREAMBUFFER) returned %#x, file unreadable?", scan_status);
        }

        fclose(ScanDescriptor.UserPtr);
    }

    return 0;
}
