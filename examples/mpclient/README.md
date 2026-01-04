# mpclient (x64) example

This example shows how to run the Windows Defender engine (mpengine.dll) on
Linux using loadlibrary and the mpclient_x64 harness.

## Download Defender data (x64)

Grab the latest definition package (mpam-fe.exe) and extract it into
`engine/x64` so the harness can find mpengine.dll and the VDM signature files.

```
mkdir -p examples/mpclient/downloads
curl -L -o examples/mpclient/downloads/mpam-fe.exe \
  "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x64"

mkdir -p engine/x64
7z x examples/mpclient/downloads/mpam-fe.exe -oengine/x64
# or
cabextract -d engine/x64 examples/mpclient/downloads/mpam-fe.exe
```

You should end up with files like:

- `engine/x64/mpengine.dll`
- `engine/x64/mpengine.dll.sig`
- `engine/x64/mpengine.cat`
- `engine/x64/mpavbase.vdm`
- `engine/x64/mpasbase.vdm`

## Build and run

```
timeout 120s make -B mpclient_x64
timeout 60s ./mpclient_x64 /path/to/file
```

Optional patching controls:

- `MPCLIENT_PATCH_ENGINE=0` disables engine patching.
- `MPCLIENT_PATCH_ENGINE=int3` only removes int3 traps.
- `MPCLIENT_PATCH_ENGINE=nothrow` also avoids known throw sites.

## How this example was put together

High-level steps used to keep mpengine working on Linux:

- Load the PE image with `pe_load_library()` and resolve relocations/imports
  via `link_pe_images()`.
- Provide stream callbacks (read/size/name/attributes) that mimic Windows
  scanning paths so mpengine can access file content.
- Update structure definitions to match 64-bit layouts (`include/` headers).
- Extend WinAPI stubs to satisfy new imports as the engine evolves.
- Improve SEH/C++ exception handling in the loader to survive `_CxxThrowException`
  paths.
- Patch a few engine call sites that hit Windows-only behavior in this
  environment.

## Porting other libraries with loadlibrary

Use this same playbook for other Windows DLLs:

1) Start with a tiny harness that loads the DLL and calls a single exported
   entrypoint.
2) Run it, inspect missing import errors, and add minimal stubs in
   `peloader/winapi/`.
3) Fix up struct layouts and calling conventions until the library runs.
4) If the DLL uses SEH/C++ exceptions, make sure exception dispatch and unwind
   are supported for its patterns.
5) Add only the OS surface the DLL actually consumes (files, registry, time,
   crypto, etc.), and keep it as minimal as possible.

Keep extracted engine binaries and signature data out of the repo; only the
code and harness belong in git.
