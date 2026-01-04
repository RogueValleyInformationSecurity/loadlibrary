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
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <mcheck.h>
#include <err.h>
#include <limits.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "hook.h"
#include "log.h"
#include "rsignal.h"
#include "engineboot.h"
#include "scanreply.h"
#include "streambuffer.h"
#include "openscan.h"
#include "mpclient.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct pe_image image = {
        .entry  = NULL,
        .name   = "engine/mpengine.dll",
};

// Any usage limits to prevent bugs disrupting system.
const struct rlimit kUsageLimits[] = {
    [RLIMIT_FSIZE]  = { .rlim_cur = 0x20000000, .rlim_max = 0x20000000 },
    [RLIMIT_CPU]    = { .rlim_cur = 3600,       .rlim_max = RLIM_INFINITY },
    [RLIMIT_CORE]   = { .rlim_cur = 0,          .rlim_max = 0 },
    [RLIMIT_NOFILE] = { .rlim_cur = 32,         .rlim_max = 32 },
    [RLIMIT_STACK]  = { .rlim_cur = 768 * 1024 * 1024, .rlim_max = 768 * 1024 * 1024 },
};

DWORD (* __rsignal)(PHANDLE KernelHandle, DWORD Code, PVOID Params, DWORD Size);

static volatile int g_threat_found = 0;
static char g_threat_name[sizeof(((PSCANSTRUCT)0)->VirusName)];
static wchar_t g_stream_name[PATH_MAX * 2];
static unsigned int g_stream_attr_log_count = 0;

static void RecordThreat(PSCANSTRUCT Scan)
{
    if (Scan->VirusName[0] != '\0') {
        strncpy(g_threat_name, Scan->VirusName, sizeof(g_threat_name) - 1);
        g_threat_name[sizeof(g_threat_name) - 1] = '\0';
    }
    g_threat_found = 1;
}

static DWORD EngineScanCallback(PSCANSTRUCT Scan)
{
    if (Scan) {
        LogMessage("EngineScanCallback(): flags=%#x threat=%.*s file=%s",
                   Scan->Flags,
                   (int)sizeof(Scan->VirusName),
                   Scan->VirusName,
                   Scan->FileName ? Scan->FileName : "(null)");
    }
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
        RecordThreat(Scan);
    }
    // This may indicate PUA.
    if ((Scan->Flags & 0x40010000) == 0x40010000) {
        LogMessage("Threat %s identified.", Scan->VirusName);
        RecordThreat(Scan);
    }
    return 0;
}

static DWORD ReadStream(PVOID this, ULONGLONG Offset, PVOID Buffer, DWORD Size, PDWORD SizeRead)
{
    fseek(this, Offset, SEEK_SET);
    *SizeRead = fread(Buffer, 1, Size, this);
    return TRUE;
}

static DWORD GetStreamSize(PVOID this, PULONGLONG FileSize)
{
    fseek(this, 0, SEEK_END);
    *FileSize = ftell(this);
    return TRUE;
}

static DWORD GetStreamAttributes(PVOID this __attribute__((unused)),
                                 DWORD Attribute,
                                 PVOID Data,
                                 DWORD DataSize,
                                 PDWORD DataSizeWritten)
{
    if (g_stream_attr_log_count < 20) {
        fprintf(stderr, "GetAttributes(attr=%u, size=%u)\n", Attribute, DataSize);
        g_stream_attr_log_count++;
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
        case STREAM_ATTRIBUTE_FILEID:
            if (Data && DataSize >= sizeof(ULONGLONG)) {
                *(ULONGLONG *)Data = 0;
                if (DataSizeWritten) {
                    *DataSizeWritten = sizeof(ULONGLONG);
                }
                return TRUE;
            }
            return FALSE;
        case STREAM_ATTRIBUTE_FILEVOLUMESERIALNUMBER:
            if (Data && DataSize >= sizeof(DWORD)) {
                *(DWORD *)Data = 0;
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
        default:
            if (Data && DataSize > 0) {
                memset(Data, 0, DataSize);
                if (DataSizeWritten) {
                    *DataSizeWritten = DataSize;
                }
                return TRUE;
            }
            return TRUE;
    }
}

static DWORD SetStreamAttributes(PVOID this __attribute__((unused)),
                                 DWORD Attribute,
                                 PVOID Data __attribute__((unused)),
                                 DWORD DataSize __attribute__((unused)))
{
    if (g_stream_attr_log_count < 20) {
        fprintf(stderr, "SetAttributes(attr=%u)\n", Attribute);
        g_stream_attr_log_count++;
    }
    return TRUE;
}

static PWCHAR GetStreamName(PVOID this __attribute__((unused)))
{
    if (!g_stream_name[0]) {
        return L"c:\\input";
    }
    return g_stream_name;
}

static void SetStreamNameFromPath(const char *path)
{
    char resolved[PATH_MAX];
    const char *use_path = path;
    char winpath[PATH_MAX * 2];
    size_t i = 0;

    if (path && realpath(path, resolved)) {
        use_path = resolved;
    }

    if (use_path && use_path[0] == '/') {
        snprintf(winpath, sizeof(winpath), "c:%s", use_path);
    } else if (use_path && strchr(use_path, ':')) {
        snprintf(winpath, sizeof(winpath), "%s", use_path);
    } else if (use_path) {
        snprintf(winpath, sizeof(winpath), "c:\\%s", use_path);
    } else {
        snprintf(winpath, sizeof(winpath), "c:\\input");
    }

    for (; winpath[i] && i + 1 < sizeof(g_stream_name) / sizeof(g_stream_name[0]); i++) {
        char c = winpath[i];
        if (c == '/') {
            c = '\\';
        }
        g_stream_name[i] = (wchar_t)(unsigned char)c;
    }
    g_stream_name[i] = L'\0';
}

// These are available for pintool.
BOOL __noinline InstrumentationCallback(PVOID ImageStart __attribute__((unused)),
                                        SIZE_T ImageSize __attribute__((unused)))
{
    // Prevent the call from being optimized away.
    asm volatile ("");
    return TRUE;
}

static int run_mpclient(int argc, char **argv)
{
    pthread_attr_t self_attr;
    void *stack_addr = NULL;
    size_t stack_size = 0;
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS PeHeader;
    HANDLE KernelHandle;
    SCAN_REPLY ScanReply;
    BOOTENGINE_PARAMS BootParams;
    SCANSTREAM_PARAMS ScanParams;
    STREAMBUFFER_DESCRIPTOR ScanDescriptor;
    ENGINE_INFO EngineInfo;
    ENGINE_CONFIG EngineConfig;

    if (pthread_getattr_np(pthread_self(), &self_attr) == 0) {
        if (pthread_attr_getstack(&self_attr, &stack_addr, &stack_size) == 0) {
            LogMessage("Thread stack %p-%p (%zu bytes)",
                       stack_addr,
                       (char *)stack_addr + stack_size,
                       stack_size);
        }
        pthread_attr_destroy(&self_attr);
    }

    // Load the mpengine module.
    if (pe_load_library(image.name, &image.image, &image.size) == false) {
        LogMessage("You must add the dll and vdm files to the engine directory");
        return 1;
    }

    // Handle relocations, imports, etc.
    link_pe_images(&image, 1);

    // Fetch the headers to get base offsets.
    DosHeader   = (PIMAGE_DOS_HEADER) image.image;
    PeHeader    = (PIMAGE_NT_HEADERS)(image.image + DosHeader->e_lfanew);

    // Load any additional exports.
    if (!process_extra_exports(image.image, PeHeader->OptionalHeader.BaseOfCode, "engine/mpengine.map")) {
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
        if (ExceptionRecord && ExceptionRecord->ExceptionCode == 0xE06D7363) {
            return ExceptionContinueExecution;
        }

        LogMessage("Toplevel Exception Handler Caught Exception %#x at %p",
                   ExceptionRecord ? ExceptionRecord->ExceptionCode : 0,
                   ExceptionRecord ? ExceptionRecord->ExceptionAddress : NULL);
        abort();
    }

    VOID ResourceExhaustedHandler(int Signal)
    {
        errx(EXIT_FAILURE, "Resource Limits Exhausted, Signal %s", strsignal(Signal));
    }

    struct sigaction trap_action;
    memset(&trap_action, 0, sizeof trap_action);
    trap_action.sa_handler = SIG_IGN;
    sigaction(SIGTRAP, &trap_action, NULL);
    setup_nt_threadinfo(ExceptionHandler);

    // Install usage limits to prevent system crash.
    setrlimit(RLIMIT_CORE, &kUsageLimits[RLIMIT_CORE]);
    setrlimit(RLIMIT_CPU, &kUsageLimits[RLIMIT_CPU]);
    setrlimit(RLIMIT_FSIZE, &kUsageLimits[RLIMIT_FSIZE]);
    setrlimit(RLIMIT_NOFILE, &kUsageLimits[RLIMIT_NOFILE]);
    setrlimit(RLIMIT_STACK, &kUsageLimits[RLIMIT_STACK]);

    // Call DllMain()
    image.entry((PVOID) 'MPEN', DLL_PROCESS_ATTACH, NULL);

    signal(SIGXCPU, ResourceExhaustedHandler);
    signal(SIGXFSZ, ResourceExhaustedHandler);

# ifndef NDEBUG
    // Enable Maximum heap checking.
    mcheck_pedantic(NULL);
# endif

    ZeroMemory(&BootParams, sizeof BootParams);
    ZeroMemory(&EngineInfo, sizeof EngineInfo);
    ZeroMemory(&EngineConfig, sizeof EngineConfig);

    BootParams.ClientVersion = BOOTENGINE_PARAMS_VERSION;
    BootParams.Attributes    = BOOT_ATTR_NORMAL;
    BootParams.SignatureLocation = L"c:\\engine";
    BootParams.ProductName = L"Legitimate Antivirus";
    EngineConfig.QuarantineLocation = L"c:\\quarantine";
    EngineConfig.Inclusions = L"*.*";
    EngineConfig.EngineFlags = 1 << 1;
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

        if (boot_status == 0xa005) {
            LogMessage("__rsignal(RSIG_BOOTENGINE) returned %#x, continuing with engine initialized", boot_status);
        }
    }

    {
        DWORD init_status = __rsignal(&KernelHandle, RSIG_COMPLETE_INITIALIZATION, NULL, 0);
        if (init_status != 0) {
            LogMessage("__rsignal(RSIG_COMPLETE_INITIALIZATION) returned %#x", init_status);
        }
    }

    ZeroMemory(&ScanParams, sizeof ScanParams);
    ZeroMemory(&ScanDescriptor, sizeof ScanDescriptor);
    ZeroMemory(&ScanReply, sizeof ScanReply);

    ScanParams.Descriptor        = &ScanDescriptor;
    ScanParams.ScanReply         = &ScanReply;
    ScanReply.EngineScanCallback = EngineScanCallback;
    ScanReply.field_C            = 0x7fffffff;
    ScanDescriptor.Read          = ReadStream;
    ScanDescriptor.GetSize       = GetStreamSize;
    ScanDescriptor.GetName       = GetStreamName;
    ScanDescriptor.GetAttributes = GetStreamAttributes;
    ScanDescriptor.SetAttributes = SetStreamAttributes;

    if (argc < 2) {
        LogMessage("usage: %s [filenames...]", *argv);
        return 1;
    }

    // Enable Instrumentation.
    InstrumentationCallback(image.image, image.size);

    for (++argv; *argv; ++argv) {
        g_threat_found = 0;
        g_threat_name[0] = '\0';
        SetStreamNameFromPath(*argv);
        ScanDescriptor.UserPtr = fopen(*argv, "r");

        if (ScanDescriptor.UserPtr == NULL) {
            LogMessage("failed to open file %s", *argv);
            return 1;
        }

        LogMessage("Scanning %s...", *argv);

        DWORD scan_status = __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);
        if (scan_status != 0) {
            LogMessage("__rsignal(RSIG_SCAN_STREAMBUFFER) returned %#x, file unreadable?", scan_status);
            return 1;
        }

        fclose(ScanDescriptor.UserPtr);
    }

    return 0;
}

struct run_args {
    int argc;
    char **argv;
    int result;
};

static void *run_thread(void *data)
{
    struct run_args *args = data;
    args->result = run_mpclient(args->argc, args->argv);
    return NULL;
}

int main(int argc, char **argv)
{
    pthread_t thread;
    pthread_attr_t attr;
    struct run_args args = {
        .argc = argc,
        .argv = argv,
        .result = 1,
    };

    if (pthread_attr_init(&attr) != 0) {
        return run_mpclient(argc, argv);
    }
    if (pthread_attr_setstacksize(&attr, 768 * 1024 * 1024) != 0) {
        pthread_attr_destroy(&attr);
        return run_mpclient(argc, argv);
    }
    if (pthread_create(&thread, &attr, run_thread, &args) != 0) {
        pthread_attr_destroy(&attr);
        return run_mpclient(argc, argv);
    }
    pthread_attr_destroy(&attr);
    pthread_join(thread, NULL);
    return args.result;
}
