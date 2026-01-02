# IrfanView fuzzing harness (loadlibrary)

This example shows how to fuzz IrfanView plugin DLLs on Linux using loadlibrary.
IrfanView and its plugins are proprietary; do not redistribute them. Download
and extract the 64-bit IrfanView plugin pack locally.

## Layout
- `irfanview-harness.c` - persistent-mode harness that loads plugin DLLs
- `Makefile` - builds the harness against loadlibrary
- `extracted/` - place plugin DLLs here (for example `Formats.dll`)
- `seeds/` - input corpus, one subdir per extension (for example `seeds/ani/`)

## Setup
1. Extract the 64-bit IrfanView plugin pack into `example/irfanview/extracted/`.
   You should have files like `extracted/Formats.dll` and `extracted/WebP.dll`.
2. Add seed files under `example/irfanview/seeds/<ext>/`.

## Build
```bash
make -C example/irfanview
# AFL++ instrumented build:
AFL_MAP_SIZE=65536 make -C example/irfanview CC=afl-clang-fast
```

Note: `AFL_MAP_SIZE` must be set when compiling the target to take effect.

Run the commands below from `example/irfanview`.

## Quick run
```bash
LL_PE_FIXED_BASE=1 ./harness ani seeds/ani/file000001.ani
```

## Verify basic block coverage
```bash
LL_AFL_BB_COVERAGE=1 LL_PE_FIXED_BASE=1 \
  afl-showmap -o /tmp/iv_bb.txt -- ./harness ani seeds/ani/file000001.ani
```

You should see more tuples with BB coverage enabled than without it.

## Fuzzing
```bash
LL_AFL_BB_COVERAGE=1 LL_PE_FIXED_BASE=1 \
  afl-fuzz -i seeds/ani -o output/ani -t 1000 -- ./harness ani @@
```

## loadlibrary-specific harness changes
- Use `pe_load_library()` and `link_pe_images()` instead of `LoadLibrary`.
- Call the DLL entry point (`DllMain`) manually after linking.
- Resolve exports with `get_export_address()` and use `WINCALL` for ms_abi calls.
- Use `LL_PE_FIXED_BASE=1` so BB coverage IDs stay stable across runs.
- Enable `LL_AFL_BB_COVERAGE=1` to instrument the loaded DLL code.

## Notes
- This harness targets 64-bit plugins only.
- If a format crashes due to missing Windows stubs, add them under
  `peloader/winapi/`.
- `LL_AFL_COVERAGE_VERBOSE=1` and `LL_AFL_BB_VERBOSE=1` print coverage logs.
