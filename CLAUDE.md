# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

loadlibrary is a specialized library that allows native Linux programs to load and execute Windows PE DLLs. It supports both 32-bit (PE32) and 64-bit (PE32+/PE64) Windows binaries. The primary use case is scalable fuzzing of Windows security products (particularly Windows Defender's mpengine.dll) on Linux without virtualization overhead.

## Build Commands

```bash
# Build everything
make

# Clean build artifacts
make clean

# Build individual components
make -C peloader all    # PE loader library
make -C intercept all   # Hook/interception library

# Build AFL-style PE callsite coverage harnesses
AFL_PE_COVERAGE=1 make -C peloader all all64
AFL_PE_COVERAGE=1 make afl_cov afl_cov64
```

**Required 32-bit dependencies:**
- Fedora/RHEL: `glibc-devel.i686`, `libgcc.i686`, `readline-devel.i686` (optional), `cabextract`
- Ubuntu/Debian: `libc6-dev:i386`, `gcc-multilib`, `libreadline-dev:i386` (optional), `cabextract`

## Running

```bash
# Basic file scan with Windows Defender engine
./mpclient <filename>

# Interactive scripting interface (requires readline)
./mpscript
```

**AFL-style PE callsite coverage (standalone sanity check):**

```bash
export LL_AFL_COVERAGE=1
export LL_AFL_COVERAGE_STATS=1
export LL_PE_FIXED_BASE=0x40000000
printf "A" | ./afl_cov64
```

For 32-bit `afl-cmin` runs, set `AFL_MAP_SIZE=8388608` and `AFL_NO_FORKSRV=1`
to match AFL++ map sizing in batch mode.

Before running, extract the Windows Defender engine files into `engine/` directory:
```bash
cabextract mpam-fe.exe   # Downloads from Microsoft's definition update page
```

## Architecture

**Core Components:**

- `peloader/` - Custom PE/COFF loader (derived from ndiswrapper)
  - `pe_linker.c` - Main PE parsing and linking engine
  - `winapi/` - Windows API stub implementations (35 modules covering memory, file I/O, threading, registry, crypto, etc.)
  - `winnt_types.h` - Windows NT type definitions

- `intercept/` - Runtime hooking and patching
  - `hook.c` - Function hooking mechanism
  - `libdisasm/` - x86 instruction disassembler

- `coverage/` - Intel PIN-based code coverage collection
  - `deepcover.cpp` - PIN tool for basic block tracking

- `mpclient.c` - Main loader application for Windows Defender
- `mpscript.c` - Interactive REPL interface
- `peloader/afl_coverage.c` - AFL-style callsite coverage for PE -> loader calls
- `examples/afl_coverage_harness.c` - Example harness that prints coverage stats

**Key Design Constraints:**
- Supports both 32-bit (PE32) and 64-bit (PE32+) Windows PE files
- 32-bit builds use `-m32` flag; 64-bit builds require 64-bit host
- Uses `-fshort-wchar` for Windows wchar_t compatibility
- Custom memory allocator (dlmalloc) in `peloader/codealloc.h`

**Build Configuration:**
- Compiler warnings enabled: `-Wall -Wextra -Wno-multichar`
- Security hardening: `-fstack-protector-strong -D_FORTIFY_SOURCE=2`
- Automatic header dependency tracking via `-MMD -MP`
- Baseline ISA for compatibility: `-march=i686` (32-bit), `-march=x86-64` (64-bit)

## Debugging

GDB integration with custom commands in `.gdbinit`:
- `hni` / `hnexti` - Hardware breakpoint-based next instruction (more reliable than `nexti` for Windows code)
- `mc` / `multichar` - Decode multichar constants
- `trace <condition>` - Step until condition is true

To debug with symbols:
1. Generate map file from IDA: `idaw -A -P+ -S"createmap.idc mpengine.map" mpengine.dll`
2. Convert line endings: `dos2unix mpengine.map`
3. Run under gdb - it will print `add-symbol-file` commands to enter

Use hardware breakpoints (`hb`/`hbreak`) instead of software breakpoints for reliability.

## Adding Windows API Stubs

When a loaded DLL requires an unimplemented Windows API function, add a stub in `peloader/winapi/`. Stubs typically log the call and return a reasonable default. See existing files for patterns.
