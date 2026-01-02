# Porting Windows Dynamic Link Libraries to Linux
## Introduction

This repository contains a library that allows native Linux programs to load
and call functions from a Windows DLL.

As a demonstration, I've ported Windows Defender to Linux.

```
$ ./mpclient eicar.com
main(): Scanning eicar.com...
EngineScanCallback(): Scanning input
EngineScanCallback(): Threat Virus:DOS/EICAR_Test_File identified.
```

### How does it work?

The `peloader` directory contains a custom PE/COFF loader derived from
ndiswrapper. The library will process the relocations and imports, then provide
a `dlopen`-like API. The code supports debugging with gdb (including symbols),
basic block coverage collection, and runtime hooking and patching.

![Is such a thing even possible?](https://media.giphy.com/media/2pDSW8QQU6jRe/giphy.gif)

### What works?

The intention is to allow scalable and efficient fuzzing of self-contained
Windows libraries on Linux. Good candidates might be video codecs,
decompression libraries, virus scanners, image decoders, and so on.

* C++ exception dispatch and unwinding.
* Loading additional symbols from IDA.
* Debugging with gdb (including symbols), breakpoints, stack traces, etc.
* Runtime hooking and patching.
* Support for ASAN and Valgrind to detect subtle memory corruption bugs.

If you need to add support for any external imports, writing stubs is usually
quick and easy.

### Why?

Distributed, scalable fuzzing on Windows can be challenging and inefficient.
This is especially true for endpoint security products, which use complex
interconnected components that span across kernel and user space. This
often requires spinning up an entire virtualized Windows environment to fuzz
them or collect coverage data.

This is less of a problem on Linux, and I've found that porting components of
Windows Antivirus products to Linux is often possible. This allows me to run
the code I’m testing in minimal containers with very little overhead, and
easily scale up testing.

This is just personal opinion, but I also think Linux has better tools. `¯\_(ツ)_/¯`

## Windows Defender

MsMpEng is the Malware Protection service that is enabled by default on Windows
8, 8.1, 10, Windows Server 2016, and so on. Additionally, Microsoft Security
Essentials, System Centre Endpoint Protection and various other Microsoft
security products share the same core engine.

The core component of MsMpEng responsible for scanning and analysis is called
mpengine. Mpengine is a vast and complex attack surface, comprising of handlers
for dozens of esoteric archive formats, executable packers, full system
emulators for various architectures and interpreters for various languages. All
of this code is accessible to remote attackers.

### Building

To build the test client, simply type `make`.

```
$ make
```

### Dependencies

*Note that the `.i686` or `:i386` suffixes are important, we need the 32bit libraries to use the 32bit dll.*

| Fedora / RedHat       | Ubuntu / Debian                     | Comment                      |
| --------------------- | ----------------------------------- |:---------------------------- |
| `glibc-devel.i686`    | `libc6-dev:i386` / `libc6-dev-i386` | Name varies with version.    |
| `libgcc.i686`         | `gcc-multilib`                      |                              |
| `readline-devel.i686` | `libreadline-dev:i386`              | Optional, used in mpscript.  |
| `cabextract`          | `cabextract`                        | Used to extract definitions. |

You will need to download the 32-bit antimalware update file from this page:

* https://www.microsoft.com/security/portal/definitions/adl.aspx#manual

This should be a direct link to the right file:

* https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86

This will download a file called `mpam-fe.exe`, which is a cabinet file that
can be extracted with `cabextract`. Extract the files into the `engine`
directory:

```
$ cabextract mpam-fe.exe
Extracting cabinet: mpam-fe.exe
  extracting MPSigStub.exe
  extracting mpavdlta.vdm
  extracting mpasdlta.vdm
  extracting mpavbase.vdm
  extracting mpasbase.vdm
  extracting mpengine.dll

All done, no errors.
```

If you want to know which version you got, try this:

```
$ exiftool mpengine.dll | grep 'Product Version Number'
Product Version Number          : 1.1.13701.0
```

### Running

The main mpengine loader is called `mpclient`, it accepts filenames to scan as
a parameter.

```
$ ./mpclient netsky.exe
main(): Scanning netsky.exe...
EngineScanCallback(): Scanning input
EngineScanCallback(): Threat Worm:Win32/Netsky.P@mm identified.
```

There are some other sample tools, `mpstreamfuzz` and `mpscript`.

### Debugging

If you want to debug a crash, single step through a routine or set breakpoints,
follow these examples. First, you need a map file from IDA.

Microsoft doesn't release public symbols for every build, and sometimes the
symbols lag behind for a few months after release. Make sure you're using an
mpengine version with public symbols available.

Use the following sample commandline to generate map and idb files.

```
> idaw -A -P+ -S"createmap.idc mpengine.map" mpengine.dll
```

If you generate the map files on Windows, you'll get CRLF line terminators, fix
them like this:

```
$ dos2unix mpengine.map
```

When you run mpclient under gdb, it will detect a debugger and print the
commands you need to enter to teach gdb about the symbols:

```
$ gdb -q ./mpclient
(gdb) r testfile.txt
Starting program: mpclient
main(): GDB: add-symbol-file engine/mpengine.dll 0xf6af4008+0x1000
main(): GDB: shell bash genmapsym.sh 0xf6af4008+0x1000 symbols_19009.o < mpengine.map
main(): GDB: add-symbol-file symbols_19009.o 0

Program received signal SIGTRAP, Trace/breakpoint trap.
0x0804d213 in main (argc=1, argv=0xffffcc64, envp=0xffffcc6c) at mpclient.c:156
156	        __debugbreak();
(gdb)
```

If you enter the commands it shows into gdb, you will have symbols available.

> *Note that `genmapsym.sh` assumes you're using GNU awk.*

```
(gdb) add-symbol-file engine/mpengine.dll 0xf6af4008+0x1000
add symbol table from file "engine/mpengine.dll" at
	.text_addr = 0xf6af5008
Reading symbols from engine/mpengine.dll...done.
(gdb) shell bash genmapsym.sh 0xf6af4008+0x1000 symbols_19009.o < mpengine.map
(gdb) add-symbol-file symbols_19009.o 0
add symbol table from file "symbols_19009.o" at
	.text_addr = 0x0
Reading symbols from symbols_19009.o...done.
(gdb) p as3_parsemetadata_swf_vars_t
$1 = {void (void)} 0xf6feb842 <as3_parsemetadata_swf_vars_t>
```

Then you can continue, and it will run as normal.

```
(gdb) c
```

Breakpoints, watchpoints and backtraces all work as normal, although it may be
more reliable to use hardware breakpoints than software breakpoints.

To use hardware breakpoints in gdb, you just use `hb` or `hbreak` instead of
`break`. Note that you only get a limited number of hardware breakpoints.

```
(gdb) b as3_parsemethodinfo_swf_vars_t
Breakpoint 1 at 0xf6feb8da
(gdb) c
Continuing.
main(): Scanning test/input.swf...
EngineScanCallback(): Scanning input
Breakpoint 1, 0xf6feb8da in as3_parsemethodinfo_swf_vars_t ()
(gdb) bt
#0  0xf6feb8da in as3_parsemethodinfo_swf_vars_t ()
#1  0xf6dbad7f in SwfScanFunc ()
#2  0xf6d73ec3 in UfsScannerWrapper__ScanFile_scanresult_t ()
#3  0xf6d6c9e3 in UfsClientRequest__fscan_SCAN_REPLY ()
#4  0xf6d6a818 in UfsNode__ScanLoopHelper_wchar_t ()
#5  0xf6d6a626 in UfsNode__Analyze_UfsAnalyzeSetup ()
#6  0xf6d71f7f in UfsClientRequest__AnalyzeLeaf_wchar_t ()
#7  0xf6d71bb9 in UfsClientRequest__AnalyzePath_wchar_t ()
#8  0xf6dbbd88 in std___String_alloc_std___String_base_types_char_std__allocator_char______Myptr_void_ ()
#9  0xf6d75e72 in UfsCmdBase__ExecuteCmd__lambda_c80a88e180c1f4524a759d69aa15f87e____lambda_c80a88e180c1f4524a759d69aa15f87e__ ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
(gdb) x/3i $pc
=> 0xf6feb8da <as3_parsemethodinfo_swf_vars_t+7>:	lea    ebx,[edx+0x1c]
   0xf6feb8dd <as3_parsemethodinfo_swf_vars_t+10>:	push   esi
   0xf6feb8de <as3_parsemethodinfo_swf_vars_t+11>:	mov    edx,ebx
```

## What about Wine and Winelib?

This project does not replace Wine or Winelib.

Winelib is used to port Windows C++ projects to Linux, and Wine is
intended to run full Windows applications. This project is intended to allow
native Linux code to load simple Windows DLLs.

The closest analogy would be ndiswrapper but for userspace.

## Building Fuzzing Harnesses

The primary use case for loadlibrary is fuzzing Windows DLLs on Linux using
tools like AFL, libFuzzer, or honggfuzz. Here's how to create fuzzing harnesses.

### Prerequisites

For 32-bit DLLs:
```bash
# Fedora/RedHat
dnf install gcc-mingw-w64-i686

# Ubuntu/Debian
apt install gcc-mingw-w64-i686
```

For 64-bit DLLs:
```bash
# Fedora/RedHat
dnf install gcc-mingw-w64-x86-64

# Ubuntu/Debian
apt install gcc-mingw-w64-x86-64
```

### Simple 64-bit Example

This example shows the minimal code needed to fuzz a 64-bit Windows DLL.

**Step 1: Create a test DLL (`test/fuzz64.c`):**

```c
#include <stdint.h>

#define EXPORT __declspec(dllexport)

// Function that processes input data (the fuzzing target)
EXPORT int parse_records(const uint8_t *data, int size) {
    int count = 0, i = 0;
    while (i < size) {
        uint8_t record_len = data[i];
        if (i + 1 + record_len > size) return -1;  // Truncated
        i += 1 + record_len;
        count++;
    }
    return count;
}

EXPORT int __stdcall DllMain(void *h, uint32_t reason, void *r) {
    return 1;
}

int __stdcall _DllMainCRTStartup(void *h, uint32_t reason, void *r) {
    return DllMain(h, reason, r);
}
```

**Step 2: Compile the DLL (no CRT dependencies):**
```bash
x86_64-w64-mingw32-gcc -shared -nostdlib -e _DllMainCRTStartup \
    -o test/fuzz64.dll test/fuzz64.c
```

**Step 3: Create the harness (`examples/harness64.c`):**

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

// WINCALL ensures correct calling convention (ms_abi on x64)
typedef int (WINCALL *parse_records_fn)(const uint8_t *data, int size);

#define MAX_INPUT_SIZE (1024 * 1024)

int main(int argc, char *argv[]) {
    const char *dll_path = "test/fuzz64.dll";
    void *image = NULL;
    size_t size = 0;
    struct pe_image pe;

    if (argc > 1) dll_path = argv[1];

    // Load and link the DLL
    if (!pe_load_library(dll_path, &image, &size)) return 1;
    memset(&pe, 0, sizeof(pe));
    strncpy(pe.name, dll_path, sizeof(pe.name) - 1);
    pe.image = image;
    pe.size = size;
    if (link_pe_images(&pe, 1) != 0) return 1;

    // Initialize the DLL
    if (pe.entry) pe.entry(pe.image, DLL_PROCESS_ATTACH, NULL);

    // Get the target function
    parse_records_fn parse_records = get_export_address("parse_records");
    if (!parse_records) return 1;

    // Read input from stdin (AFL-compatible)
    uint8_t *input = malloc(MAX_INPUT_SIZE);
    ssize_t input_size = read(STDIN_FILENO, input, MAX_INPUT_SIZE);
    if (input_size <= 0) return 1;

    // Call the target function
    parse_records(input, (int)input_size);

    free(input);
    return 0;
}
```

**Step 4: Build and run:**
```bash
make harness64
echo -e '\x03abc\x02de' | ./harness64
```

**Step 5: Fuzz with AFL:**
```bash
mkdir -p corpus findings
echo -e '\x03abc' > corpus/seed.bin
afl-fuzz -i corpus -o findings -- ./harness64
```

### Simple 32-bit Example

The 32-bit version is similar, but simpler because calling conventions are
compatible between Linux and Windows on x86.

**Compile the DLL:**
```bash
i686-w64-mingw32-gcc -shared -nostdlib -e __DllMainCRTStartup \
    -o test/fuzz32.dll test/fuzz32.c
```

**Build the harness:**
```bash
make harness32
echo -e '\x03abc' | ./harness32
```

Key differences from 64-bit:
- No `WINCALL` attribute needed (calling conventions match)
- Use 32-bit libraries (`libc6-dev:i386`, `gcc-multilib`)

### Complex Example: mpclient (Windows Defender)

The `mpclient` harness demonstrates a real-world fuzzing scenario with a
complex 32-bit Windows DLL (Microsoft's mpengine.dll).

**Key patterns from mpclient:**

1. **Stream-based input** - Uses callbacks for reading data:
```c
static DWORD ReadStream(PVOID this, ULONGLONG Offset, PVOID Buffer,
                        DWORD Size, PDWORD SizeRead) {
    fseek(this, Offset, SEEK_SET);
    *SizeRead = fread(Buffer, 1, Size, this);
    return TRUE;
}

ScanDescriptor.Read    = ReadStream;
ScanDescriptor.GetSize = GetStreamSize;
ScanDescriptor.GetName = GetStreamName;
```

2. **Exception handling** - Install a top-level handler:
```c
EXCEPTION_DISPOSITION ExceptionHandler(...) {
    LogMessage("Exception caught");
    abort();
}
setup_nt_threadinfo(ExceptionHandler);
```

3. **Resource limits** - Prevent runaway DLLs:
```c
setrlimit(RLIMIT_CPU, &(struct rlimit){3600, RLIM_INFINITY});
setrlimit(RLIMIT_FSIZE, &(struct rlimit){0x20000000, 0x20000000});
```

4. **DLL initialization** - Call DllMain and boot routines:
```c
image.entry((PVOID)'MPEN', DLL_PROCESS_ATTACH, NULL);
__rsignal(&KernelHandle, RSIG_BOOTENGINE, &BootParams, sizeof BootParams);
```

5. **Scanning loop** - Process each input file:
```c
for (++argv; *argv; ++argv) {
    ScanDescriptor.UserPtr = fopen(*argv, "r");
    __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);
    fclose(ScanDescriptor.UserPtr);
}
```

See `mpclient.c` for the complete implementation.

### Tips for Effective Fuzzing

1. **Use persistent mode** for faster fuzzing (see below)
2. **Compile with ASAN** (`-fsanitize=address`) to detect memory bugs
3. **Use coverage guidance** - AFL and libFuzzer both support this
4. **Create good seed inputs** - Start with valid files for the format
5. **Monitor for hangs** - Set appropriate timeouts

### AFL++ Persistent Mode

AFL++ persistent mode dramatically improves fuzzing speed by keeping the
process alive across multiple test cases instead of forking for each input.
This can provide 10-100x speedup.

**Building the persistent mode harnesses:**

```bash
# 32-bit persistent mode harness
make CC=afl-clang-fast afl_persistent

# 64-bit persistent mode harness
make CC=afl-clang-fast afl_persistent64
```

**Running with AFL++:**

```bash
# Create seed corpus
mkdir -p corpus
echo "test" > corpus/seed.bin

# Fuzz a 64-bit DLL
afl-fuzz -i corpus -o findings -- ./afl_persistent64 path/to/target.dll

# Fuzz a 32-bit DLL
afl-fuzz -i corpus -o findings -- ./afl_persistent path/to/target.dll
```

**How it works:**

The persistent mode harnesses use AFL++'s deferred forkserver and persistent
loop macros:

```c
// Expensive DLL loading happens once, before forking
if (init_target(dll_path) != 0) return 1;

// Fork server starts here - child inherits loaded DLL
__AFL_INIT();

// Process 10,000 inputs per fork (configurable)
while (__AFL_LOOP(10000)) {
    size_t len = __AFL_FUZZ_TESTCASE_LEN;
    fuzz_one(__AFL_FUZZ_TESTCASE_BUF, len);
}
```

**Performance comparison:**

| Mode | Typical Speed |
|------|---------------|
| Fork-per-input | 500-2,000 exec/sec |
| Persistent mode | 15,000-35,000 exec/sec |

**Note on coverage:** The persistent mode harnesses instrument the Linux
harness code, not the Windows DLL. For coverage-guided fuzzing of the DLL
itself, consider:

- **Loadlibrary AFL callsite coverage** - See the section below for the
  built-in AFL-style coverage map based on PE callsites into the loader.
- **Intel PIN** - Use `coverage/deepcover.cpp` for offline corpus distillation
- **AFL++ Frida mode** (`-O` flag) - Runtime instrumentation, slower but covers DLL code
- **Intel PT** - Hardware tracing on supported CPUs

See `test/afl_persistent.c` and `test/afl_persistent64.c` for the full
implementation.

### AFL-Style PE Callsite Coverage

This fork can emit AFL-style coverage for **PE callsites into the loader**
(imported Windows API stubs). This makes standard AFL++ instrumentation usable
without QEMU/Frida, as long as the target DLL calls into the loader.

**Build:**

```bash
# Build peloader with callsite coverage enabled
AFL_PE_COVERAGE=1 make -C peloader all all64

# Build the example harnesses
AFL_PE_COVERAGE=1 make afl_cov afl_cov64
```

**Run (standalone sanity check):**

```bash
export LL_AFL_COVERAGE=1
export LL_AFL_COVERAGE_STATS=1

# 64-bit example
export LL_PE_FIXED_BASE=0x40000000
printf "A" | ./afl_cov64
printf "B" | ./afl_cov64

# 32-bit example (fuzz32.dll ImageBase)
export LL_PE_FIXED_BASE=0x64540000
printf "A" | ./afl_cov
```

**Run with AFL++:**

```bash
export LL_PE_FIXED_BASE=0x40000000
afl-fuzz -i corpus -o findings -- ./afl_cov64 path/to/target.dll
```

**AFL++ corpus minimization (32-bit):**

```bash
# afl-cmin uses afl-showmap batch mode; 32-bit needs the map size and no-forkserver.
export LL_PE_FIXED_BASE=0x64540000
export AFL_MAP_SIZE=8388608
export AFL_NO_FORKSRV=1
afl-cmin -m none -i corpus -o findings -- ./afl_cov path/to/target.dll
```

**Notes:**

- Coverage tracks **PE -> loader callsites**, not every basic block inside the DLL.
- The loader enforces a deterministic image base when coverage is enabled.
  Use `LL_PE_FIXED_BASE` if the preferred base is occupied.
- You can find a DLL's ImageBase with `objdump -x path/to.dll | rg ImageBase`.
- On kernels without `MAP_FIXED_NOREPLACE`, set `LL_AFL_ALLOW_MAP_FIXED=1`
  to permit fixed mapping.

## Adding Ordinal Import Support

Some Windows DLLs import functions by ordinal (numeric ID) rather than by name.
The PE loader includes ordinal-to-name mappings for common DLLs like OLEAUT32.

### When You Need This

If you see errors like:
```
ordinal import not supported: OLEAUT32 ordinal 42
```

This means the DLL you're loading imports a function by ordinal that isn't in the mapping table.

### Adding New Ordinal Mappings

To add support for additional ordinals, edit `peloader/pe_linker.c`:

1. Find the ordinal table for the DLL (e.g., `oleaut32_ordinals[]`)
2. Add the missing ordinal-to-name mapping:

```c
static const struct {
    int ordinal;
    const char *name;
} oleaut32_ordinals[] = {
    { 2, "SysAllocString" },
    { 6, "SysFreeString" },
    // Add your new mapping here:
    { 42, "YourFunctionName" },
    { 0, NULL }  // Terminator
};
```

3. Implement the function stub in `peloader/winapi/OleAut32.c`:

```c
HRESULT WINCALL YourFunctionName(DWORD arg1, PVOID arg2)
{
    DebugLog("%u, %p", arg1, arg2);
    return 0;  // S_OK
}

DECLARE_CRT_EXPORT("YourFunctionName", YourFunctionName);
```

### Finding Ordinal Numbers

To find which ordinals a DLL exports, use `dumpbin` on Windows or `winedump` on Linux:
```bash
# Windows
dumpbin /exports oleaut32.dll

# Linux (with Wine)
winedump -j export oleaut32.dll
```

### Adding Support for New DLLs

To add ordinal support for a completely new DLL:

1. Create an ordinal table in `pe_linker.c`:
```c
static const struct {
    int ordinal;
    const char *name;
} mydll_ordinals[] = {
    { 1, "Function1" },
    { 2, "Function2" },
    { 0, NULL }
};

static const char* resolve_mydll_ordinal(int ordinal) {
    for (int i = 0; mydll_ordinals[i].name; i++) {
        if (mydll_ordinals[i].ordinal == ordinal)
            return mydll_ordinals[i].name;
    }
    return NULL;
}
```

2. Add the DLL check in the `import()` function's ordinal handling (both 32-bit and 64-bit paths):
```c
if (strcasecmp(dll, "MYDLL.dll") == 0 || strcasecmp(dll, "MYDLL") == 0) {
    ordname = resolve_mydll_ordinal(ordinal);
}
```

3. Create stub implementations in `peloader/winapi/MyDll.c`

## Further Examples

* [avscript](https://github.com/taviso/avscript) - Loading another antivirus engine, demonstrates hooking and patching.

## License

GPL2
