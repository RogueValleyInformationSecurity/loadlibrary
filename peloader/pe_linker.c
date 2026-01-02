//
// Copyright (C) 2017 Tavis Ormandy
//
// Portions of this code are based on ndiswrapper, which included this
// notice:
//
// Copyright (C) 2003-2005 Pontus Fuchs, Giridhar Pemmasani
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <search.h>
#include <stdlib.h>
#include <assert.h>
#include <err.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "util.h"
#include "log.h"
#include "afl_coverage.h"

struct pe_exports {
        char *dll;
        char *name;
        generic_func addr;
};

static struct pe_exports *pe_exports;
static int num_pe_exports;
PKUSER_SHARED_DATA SharedUserData;

#define DRIVER_NAME "pelinker"
#define RVA2VA(image, rva, type) (type)(ULONG_PTR)((void *)image + rva)

//#define DBGLINKER(fmt, ...) printf("%s (%s:%d): " fmt "\n",     \
//                                   DRIVER_NAME, __func__,               \
//                                   __LINE__ , ## __VA_ARGS__);

#define DBGLINKER(fmt, ...)

#ifndef NDEBUG
#define ERROR(fmt, ...) printf("%s (%s:%d): " fmt "\n", \
                                   DRIVER_NAME, __func__,               \
                                   __LINE__ , ## __VA_ARGS__);
#else
# define ERROR(fmt, ...)
#endif
#define TRACE1(fmt, ...) printf("%s (%s:%d): " fmt "\n",        \
                                   DRIVER_NAME, __func__,               \
                                   __LINE__ , ## __VA_ARGS__);

static const char *image_directory_name[] = {
    "EXPORT",
    "IMPORT",
    "RESOURCE",
    "EXCEPTION",
    "SECURITY",
    "BASERELOC",
    "DEBUG",
    "COPYRIGHT",
    "GLOBALPTR",
    "TLS",
    "LOAD_CONFIG",
    "BOUND_IMPORT",
    "IAT",
    "DELAY_IMPORT",
    "COM_DESCRIPTOR"
};

extern struct wrap_export crt_exports[];

uintptr_t LocalStorage[1024] = {0};
PFLS_CALLBACK_FUNCTION FlsCallbacks[1024] = {0};

static ULONG TlsBitmapData[32];
static RTL_BITMAP TlsBitmap = {
    .SizeOfBitMap = sizeof(TlsBitmapData) * CHAR_BIT,
    .Buffer = (PVOID) &TlsBitmapData[0],
};

struct hsearch_data extraexports;
struct hsearch_data crtexports;

void __destructor clearexports(void)
{
    hdestroy_r(&crtexports);
}

int get_data_export(char *name, uint32_t base, void *result)
{
    uint32_t *hack = result;

    get_export(name, result);

    *hack += base - 0x3000;

    ERROR("THIS WAS A TEMPORARY HACK DO NOT CALL WITHOUT FIXING");
    return 0;
}

void * get_export_address(const char *name)
{
    void *address;
    if (get_export(name, &address) != -1)
        return address;
    return NULL;
}

int get_export(const char *name, void *result)
{
        ENTRY key = { (char *)(name) }, *item;
        int i, j;
        void **func = result;

        if (crtexports.size) {
            if (hsearch_r(key, FIND, &item, &crtexports)) {
                *func = item->data;
                return 0;
            }
        }

        if (extraexports.size) {
            if (hsearch_r(key, FIND, &item, &extraexports)) {
                *func = item->data;
                return 0;
            }
        }

        // Search the ndiswrapper crt
        for (i = 0; crt_exports[i].name != NULL; i++) {
                if (strcmp(crt_exports[i].name, name) == 0) {
                        *func = crt_exports[i].func;
                        return 0;
                }
        }

        // Search PE exports
        for (i = 0; i < num_pe_exports; i++)
                if (strcmp(pe_exports[i].name, name) == 0) {
                        *func = pe_exports[i].addr;
                        return 0;
                }

        return -1;
}

static void *get_dll_init(char *name)
{
        int i;
        for (i = 0; i < num_pe_exports; i++)
                if ((strcmp(pe_exports[i].dll, name) == 0) &&
                    (strcmp(pe_exports[i].name, "DllInitialize") == 0))
                        return (void *)pe_exports[i].addr;
        return NULL;
}

/*
 * Find and validate the coff header
 * Supports both PE32 (32-bit) and PE32+ (64-bit) images.
 * Sets pe->is_64bit based on the detected architecture.
 */
static int check_nt_hdr(struct pe_image *pe)
{
        WORD attr;
        WORD magic;
        IMAGE_FILE_HEADER *file_hdr;

        /* Use 32-bit header to access common fields (Signature, FileHeader) */
        IMAGE_NT_HEADERS32 *nt_hdr = pe->nt_hdr32;

        /* Validate the "PE\0\0" signature */
        if (nt_hdr->Signature != IMAGE_NT_SIGNATURE) {
                ERROR("is this driver file? bad signature %08x",
                      nt_hdr->Signature);
                return -EINVAL;
        }

        file_hdr = &nt_hdr->FileHeader;

        /* Detect architecture from optional header magic */
        magic = nt_hdr->OptionalHeader.Magic;

        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
                pe->is_64bit = 0;
                pe->opt32 = &pe->nt_hdr32->OptionalHeader;

                /* Validate the image for 32-bit architecture */
                if (file_hdr->Machine != IMAGE_FILE_MACHINE_I386) {
                        ERROR("PE32 image has wrong machine type: %04X",
                              file_hdr->Machine);
                        return -EINVAL;
                }

                /* 32-bit images must have 32BIT_MACHINE flag */
                attr = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE;
                if ((file_hdr->Characteristics & attr) != attr)
                        return -EINVAL;

        } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
                pe->is_64bit = 1;
                pe->opt64 = &pe->nt_hdr64->OptionalHeader;

                /* Validate the image for 64-bit architecture */
                if (file_hdr->Machine != IMAGE_FILE_MACHINE_AMD64) {
                        ERROR("PE32+ image has wrong machine type: %04X",
                              file_hdr->Machine);
                        return -EINVAL;
                }

                /* 64-bit images only need EXECUTABLE_IMAGE */
                attr = IMAGE_FILE_EXECUTABLE_IMAGE;
                if ((file_hdr->Characteristics & attr) != attr)
                        return -EINVAL;

        } else {
                ERROR("unsupported PE magic: %04X", magic);
                return -EINVAL;
        }

        /* Must be relocatable */
        attr = IMAGE_FILE_RELOCS_STRIPPED;
        if ((file_hdr->Characteristics & attr))
                return -EINVAL;

        /* Make sure we have at least one section */
        if (file_hdr->NumberOfSections == 0)
                return -EINVAL;

        /* Check alignment - use appropriate optional header */
        DWORD sect_align = PE_OPT_HDR_FIELD(pe, SectionAlignment);
        DWORD file_align = PE_OPT_HDR_FIELD(pe, FileAlignment);

        if (sect_align < file_align) {
                ERROR("alignment mismatch: section: 0x%x, file: 0x%x",
                      sect_align, file_align);
                return -EINVAL;
        }

        if ((file_hdr->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
                return IMAGE_FILE_EXECUTABLE_IMAGE;
        if ((file_hdr->Characteristics & IMAGE_FILE_DLL))
                return IMAGE_FILE_DLL;
        return -EINVAL;
}

// OLEAUT32 ordinal-to-name mapping
static const struct {
        int ordinal;
        const char *name;
} oleaut32_ordinals[] = {
        { 2, "SysAllocString" },
        { 4, "SysReAllocString" },
        { 6, "SysFreeString" },
        { 7, "SysStringLen" },
        { 8, "VariantInit" },
        { 9, "VariantClear" },
        { 12, "SafeArrayGetDim" },
        { 15, "SafeArrayCreate" },
        { 16, "SafeArrayDestroy" },
        { 17, "SafeArrayGetElement" },
        { 18, "SafeArrayPutElement" },
        { 22, "SafeArrayCreateVector" },
        { 77, "SafeArrayGetVartype" },
        { 149, "SysStringByteLen" },
        { 150, "SysAllocStringByteLen" },
        { 184, "VarBstrCat" },
        { 314, "VarBstrCmp" },
        { 0, NULL }
};

static const char* resolve_oleaut32_ordinal(int ordinal)
{
        for (int i = 0; oleaut32_ordinals[i].name; i++) {
                if (oleaut32_ordinals[i].ordinal == ordinal)
                        return oleaut32_ordinals[i].name;
        }
        return NULL;
}

static const char *normalize_import_name(const char *symname, char *buf, size_t buf_len)
{
        if (!symname || !buf || buf_len == 0) {
                return NULL;
        }

        const char *name = symname;
        if (name[0] == '_') {
                name++;
        }

        size_t len = strcspn(name, "@");
        if (len == 0 || len >= buf_len) {
                return NULL;
        }

        memcpy(buf, name, len);
        buf[len] = '\0';

        if (strcmp(buf, symname) == 0) {
                return NULL;
        }

        return buf;
}

static int import(void *image, IMAGE_IMPORT_DESCRIPTOR *dirent, char *dll, int is_64bit)
{
        char *symname = NULL;
        char altname[128];
        int i;
        generic_func adr;

        void ordinal_import_stub(void)
        {
            warnx("function at %p attempted to call a symbol imported by ordinal", __builtin_return_address(0));
            __debugbreak();
        }

        void unknown_symbol_stub(void)
        {
            warnx("function at %p attempted to call an unknown symbol", __builtin_return_address(0));
            __debugbreak();
        }

        if (is_64bit) {
                /* 64-bit: use IMAGE_THUNK_DATA64 */
                ULONGLONG *lookup_tbl = RVA2VA(image, dirent->u.OriginalFirstThunk, ULONGLONG *);
                ULONGLONG *address_tbl = RVA2VA(image, dirent->FirstThunk, ULONGLONG *);

                for (i = 0; lookup_tbl[i]; i++) {
                        if (IMAGE_SNAP_BY_ORDINAL64(lookup_tbl[i])) {
                                int ordinal = (int)(lookup_tbl[i] & 0xFFFF);
                                const char *ordname = NULL;

                                if (strcasecmp(dll, "OLEAUT32.dll") == 0 || strcasecmp(dll, "OLEAUT32") == 0) {
                                        ordname = resolve_oleaut32_ordinal(ordinal);
                                }

                                if (ordname && get_export(ordname, &adr) >= 0) {
                                        address_tbl[i] = (ULONGLONG)(uintptr_t)adr;
                                        continue;
                                }

                                ERROR("ordinal import not supported: %s ordinal %d", dll, ordinal);
                                address_tbl[i] = (ULONGLONG)(uintptr_t)ordinal_import_stub;
                                continue;
                        } else {
                                symname = RVA2VA(image, ((lookup_tbl[i] & ~IMAGE_ORDINAL_FLAG64) + 2), char *);
                        }

                        if (get_export(symname, &adr) < 0) {
                                const char *demangled = normalize_import_name(symname, altname, sizeof(altname));
                                if (!demangled || get_export(demangled, &adr) < 0) {
                                        ERROR("unknown symbol: %s:%s", dll, symname);
                                        address_tbl[i] = (ULONGLONG)(uintptr_t)unknown_symbol_stub;
                                        continue;
                                }
                        }

                        address_tbl[i] = (ULONGLONG)(uintptr_t)adr;
                }
        } else {
                /* 32-bit: use IMAGE_THUNK_DATA32 */
                DWORD *lookup_tbl = RVA2VA(image, dirent->u.OriginalFirstThunk, DWORD *);
                DWORD *address_tbl = RVA2VA(image, dirent->FirstThunk, DWORD *);

                for (i = 0; lookup_tbl[i]; i++) {
                        if (IMAGE_SNAP_BY_ORDINAL32(lookup_tbl[i])) {
                                int ordinal = (int)(lookup_tbl[i] & 0xFFFF);
                                const char *ordname = NULL;

                                if (strcasecmp(dll, "OLEAUT32.dll") == 0 || strcasecmp(dll, "OLEAUT32") == 0) {
                                        ordname = resolve_oleaut32_ordinal(ordinal);
                                }

                                if (ordname && get_export(ordname, &adr) >= 0) {
                                        address_tbl[i] = (DWORD)(uintptr_t)adr;
                                        continue;
                                }

                                ERROR("ordinal import not supported: %s ordinal %d", dll, ordinal);
                                address_tbl[i] = (DWORD)(uintptr_t)ordinal_import_stub;
                                continue;
                        } else {
                                symname = RVA2VA(image, ((lookup_tbl[i] & ~IMAGE_ORDINAL_FLAG32) + 2), char *);
                        }

                        if (get_export(symname, &adr) < 0) {
                                const char *demangled = normalize_import_name(symname, altname, sizeof(altname));
                                if (!demangled || get_export(demangled, &adr) < 0) {
                                        ERROR("unknown symbol: %s:%s", dll, symname);
                                        address_tbl[i] = (DWORD)(uintptr_t)unknown_symbol_stub;
                                        continue;
                                }
                        }

                        address_tbl[i] = (DWORD)(uintptr_t)adr;
                }
        }

        return 0;
}

static int read_exports(struct pe_image *pe)
{
        IMAGE_EXPORT_DIRECTORY *export_dir_table;
        int i;
        uint32_t *name_table;
        uint16_t *ordinal_table;
        IMAGE_DATA_DIRECTORY *export_data_dir;

        /* Use architecture-appropriate data directory */
        export_data_dir = &PE_DATA_DIRECTORY(pe)[IMAGE_DIRECTORY_ENTRY_EXPORT];

        if (export_data_dir->Size == 0) {
                DBGLINKER("no exports");
                return 0;
        }

        export_dir_table =
                RVA2VA(pe->image, export_data_dir->VirtualAddress,
                       IMAGE_EXPORT_DIRECTORY *);

        /* Export tables use 32-bit RVAs even in PE64 */
        name_table = (uint32_t *)(pe->image +
                                      export_dir_table->AddressOfNames);
        ordinal_table = (uint16_t *)(pe->image +
                                      export_dir_table->AddressOfNameOrdinals);

        /* Reset export count for this image */
        num_pe_exports = 0;
        pe_exports = calloc(export_dir_table->NumberOfNames, sizeof(struct pe_exports));
        if (!pe_exports && export_dir_table->NumberOfNames > 0) {
                ERROR("failed to allocate exports table");
                return -ENOMEM;
        }

        for (i = 0; i < export_dir_table->NumberOfNames; i++) {
                /* Export RVAs are 32-bit even in PE64 */
                uint32_t address = ((uint32_t *)(pe->image + export_dir_table->AddressOfFunctions))[*ordinal_table];

                if (export_data_dir->VirtualAddress <= address ||
                    address >= (export_data_dir->VirtualAddress +
                                           export_data_dir->Size)) {
                        //DBGLINKER("forwarder rva");
                }

                //DBGLINKER("export symbol: %s, at %p",
                //          (char *)(pe->image + *name_table),
                //          pe->image + address);

                pe_exports[num_pe_exports].dll = pe->name;
                pe_exports[num_pe_exports].name = pe->image + *name_table;
                pe_exports[num_pe_exports].addr = pe->image + address;

                num_pe_exports++;
                name_table++;
                ordinal_table++;
        }
        return 0;
}

static int fixup_imports(struct pe_image *pe)
{
        int i;
        char *name;
        int ret = 0;
        IMAGE_IMPORT_DESCRIPTOR *dirent;
        IMAGE_DATA_DIRECTORY *import_data_dir;

        import_data_dir = &PE_DATA_DIRECTORY(pe)[IMAGE_DIRECTORY_ENTRY_IMPORT];
        dirent = RVA2VA(pe->image, import_data_dir->VirtualAddress,
                        IMAGE_IMPORT_DESCRIPTOR *);

        for (i = 0; dirent[i].Name; i++) {
                name = RVA2VA(pe->image, dirent[i].Name, char*);

                DBGLINKER("imports from dll: %s", name);
                ret += import(pe->image, &dirent[i], name, pe->is_64bit);
        }
        return ret;
}

static int fixup_reloc(struct pe_image *pe)
{
        ULONGLONG base;
        ULONG_PTR size;
        IMAGE_BASE_RELOCATION *fixup_block;
        IMAGE_DATA_DIRECTORY *base_reloc_data_dir;

        /* Get ImageBase as 64-bit value (works for both architectures) */
        base = PE_IMAGE_BASE(pe);
        base_reloc_data_dir = &PE_DATA_DIRECTORY(pe)[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        if (base_reloc_data_dir->Size == 0)
                return 0;

        fixup_block = RVA2VA(pe->image, base_reloc_data_dir->VirtualAddress,
                             IMAGE_BASE_RELOCATION *);
        DBGLINKER("fixup_block=%p, image=%p", fixup_block, pe->image);
        DBGLINKER("fixup_block info: %x %d",
                  fixup_block->VirtualAddress, fixup_block->SizeOfBlock);

        while (fixup_block->SizeOfBlock) {
                int i;
                WORD fixup, offset;

                size = (fixup_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

                for (i = 0; i < size; i++) {
                        fixup = fixup_block->TypeOffset[i];
                        offset = fixup & 0xfff;
                        switch ((fixup >> 12) & 0x0f) {
                        case IMAGE_REL_BASED_ABSOLUTE:
                                break;

                        case IMAGE_REL_BASED_HIGHLOW: {
                                uint32_t addr;
                                uint32_t *loc =
                                        RVA2VA(pe->image,
                                               fixup_block->VirtualAddress +
                                               offset, uint32_t *);
                                addr = RVA2VA(pe->image, (*loc - (uint32_t)base), uint32_t);
                                *loc = addr;
                        }
                                break;

                        case IMAGE_REL_BASED_DIR64: {
                                uint64_t addr;
                                uint64_t *loc =
                                        RVA2VA(pe->image,
                                               fixup_block->VirtualAddress +
                                               offset, uint64_t *);
                                addr = RVA2VA(pe->image, (*loc - base), uint64_t);
                                DBGLINKER("relocation: *%p (Val:%llX)= %llx",
                                          loc, *loc, addr);
                                *loc = addr;
                        }
                                break;

                        default:
                                ERROR("unknown fixup: %08X",
                                      (fixup >> 12) & 0x0f);
                                return -EOPNOTSUPP;
                                break;
                        }
                }

                fixup_block = (IMAGE_BASE_RELOCATION *)
                        ((void *)fixup_block + fixup_block->SizeOfBlock);
        };

        return 0;
}

/* Expand the image in memory if necessary. The image on disk does not
 * necessarily maps the image of the driver in memory, so we have to
 * re-write it in order to fulfill the sections alignments. The
 * advantage to do that is that rva_to_va becomes a simple
 * addition. */
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

static int fix_pe_image(struct pe_image *pe)
{
        void *image;
        IMAGE_SECTION_HEADER *sect_hdr;
        int i, sections;
        size_t image_size;
        ULONGLONG image_base;

        image_size = PE_OPT_HDR_FIELD(pe, SizeOfImage);
        image_base = PE_IMAGE_BASE(pe);

        uintptr_t fixed_base = 0;
        bool use_fixed = afl_coverage_get_fixed_base(image_base, &fixed_base);

        if (pe->size == image_size && !use_fixed) {
                /* Nothing to do */
                return 0;
        }

        // When AFL PE coverage is enabled, prefer a deterministic base.
        void *map_addr = pe->is_64bit ? NULL : (PVOID)(uintptr_t)image_base;
        int map_flags = MAP_ANONYMOUS | MAP_PRIVATE;

        if (use_fixed) {
                map_addr = (PVOID)(uintptr_t)fixed_base;
                int fixed_flag = afl_coverage_map_fixed_flag();
                if (fixed_flag) {
                        map_flags |= fixed_flag;
                }
        }

        image = mmap(map_addr,
                          image_size + getpagesize(),
                          PROT_READ | PROT_WRITE | PROT_EXEC,
                          map_flags,
                          -1,
                          0);

        if (image == MAP_FAILED) {
                ULONGLONG desired_base = use_fixed ? (ULONGLONG)fixed_base : image_base;
                TRACE1("failed to mmap desired space for image: %zu bytes, image base %#llx, %m",
                    image_size, (unsigned long long)desired_base);
                return -ENOMEM;
        }

        if (use_fixed && image != map_addr) {
                TRACE1("fixed mapping requested but got %p (wanted %p). "
                       "Set LL_PE_FIXED_BASE to a free address or allow MAP_FIXED "
                       "with LL_AFL_ALLOW_MAP_FIXED=1 on older kernels.",
                       image, map_addr);
                munmap(image, image_size + getpagesize());
                return -ENOMEM;
        }

        memset(image, 0, image_size);

        /* Copy all the headers, ie everything before the first section. */

        sections = PE_FILE_HEADER(pe)->NumberOfSections;
        sect_hdr = PE_FIRST_SECTION(pe);

        DBGLINKER("copying headers: %u bytes", sect_hdr->PointerToRawData);

        memcpy(image, pe->image, sect_hdr->PointerToRawData);

        /* Copy all the sections */
        for (i = 0; i < sections; i++) {
                DBGLINKER("Copy section %s from %x to %x",
                          sect_hdr->Name, sect_hdr->PointerToRawData,
                          sect_hdr->VirtualAddress);
                if (sect_hdr->VirtualAddress+sect_hdr->SizeOfRawData >
                    image_size) {
                        ERROR("Invalid section %s in driver", sect_hdr->Name);
                        munmap(image, image_size + getpagesize());
                        return -EINVAL;
                }

                memcpy(image+sect_hdr->VirtualAddress,
                       pe->image + sect_hdr->PointerToRawData,
                       sect_hdr->SizeOfRawData);
                sect_hdr++;
        }

        // If the original is still there, clean it up.
        munmap(pe->image, pe->size);

        pe->image = image;
        pe->size = image_size;

        /* Update our internal pointers - use union member to set both */
        pe->nt_hdr = pe->image + ((IMAGE_DOS_HEADER *)pe->image)->e_lfanew;
        if (pe->is_64bit) {
                pe->opt64 = &pe->nt_hdr64->OptionalHeader;
        } else {
                pe->opt32 = &pe->nt_hdr32->OptionalHeader;
        }

        DBGLINKER("set nt headers: nt_hdr=%p, opt_hdr=%p, image=%p",
                  pe->nt_hdr, pe->opt_hdr, pe->image);

        return 0;
}

int link_pe_images(struct pe_image *pe_image, unsigned short n)
{
        int i;
        struct pe_image *pe;

        for (i = 0; i < n; i++) {
                IMAGE_DOS_HEADER *dos_hdr;
                pe = &pe_image[i];
                dos_hdr = pe->image;

                if (pe->size < sizeof(IMAGE_DOS_HEADER)) {
                        TRACE1("image too small: %zu", pe->size);
                        return -EINVAL;
                }

                /* Set up NT headers pointer (use nt_hdr which aliases both) */
                pe->nt_hdr = pe->image + dos_hdr->e_lfanew;

                /* check_nt_hdr sets is_64bit, opt32/opt64, and validates the PE */
                pe->type = check_nt_hdr(pe);
                if (pe->type <= 0) {
                        TRACE1("type <= 0");
                        return -EINVAL;
                }

        if (fix_pe_image(pe)) {
                        TRACE1("bad PE image");
                        return -EINVAL;
                }

                afl_coverage_register_image(pe->image, pe->size);

                if (read_exports(pe)) {
                        TRACE1("read exports failed");
                        return -EINVAL;
                }
        }

        for (i = 0; i < n; i++) {
                pe = &pe_image[i];

                if (fixup_reloc(pe)) {
                        TRACE1("fixup reloc failed");
                        return -EINVAL;
                }
                if (fixup_imports(pe)) {
                        TRACE1("fixup imports failed");
                        return -EINVAL;
                }

                /* Get entry point using architecture-appropriate field */
                pe->entry = RVA2VA(pe->image,
                               PE_OPT_HDR_FIELD(pe, AddressOfEntryPoint), void *);
                //TRACE1("entry is at %p, rva at %08X", pe->entry,
                //       PE_OPT_HDR_FIELD(pe, AddressOfEntryPoint));

                // Check if there were enough data directories for a TLS section.
                if (PE_OPT_HDR_FIELD(pe, NumberOfRvaAndSizes) >= IMAGE_DIRECTORY_ENTRY_TLS) {
                    // Normally, we would be expected to allocate a TLS slot,
                    // place the number into *TlsData->AddressOfIndex, and make
                    // it a pointer to RawData, and then process the callbacks.
                    //
                    // We don't support threads, so it seems safe to just
                    // pre-allocate a slot and point it straight to the
                    // template data.
                    //
                    // FIXME: Verify callbacks list is empty and SizeOfZeroFill is zero.
                    //
                    PIMAGE_TLS_DIRECTORY TlsData = RVA2VA(pe->image,
                                                          PE_DATA_DIRECTORY(pe)[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress,
                                                          IMAGE_TLS_DIRECTORY *);

                    // This means that slot 0 is reserved.
                    LocalStorage[0] = (uintptr_t) TlsData->RawDataStart;
                }
        }

        return 0;
}


// Map (but do not link) the DLL specified in filename, return an image pointer
// and size in the appropriate parameters.
bool pe_load_library(const char *filename, void **image, size_t *size)
{
    struct stat buf;
    int fd;

    assert(image);
    assert(size);

    *image  = MAP_FAILED;
    *size   = 0;
    fd      = -1;

    if ((fd = open(filename, O_RDONLY)) < 0) {
        l_error("failed to open pe library %s, %m", filename);
        goto error;
    }

    // Stat the file descriptor to determine filesize.
    if (fstat(fd, &buf) < 0) {
        l_error("failed to stat the specified pe library %s, %m", filename);
        goto error;
    }

    // Attempt to map the file PROT_READ | PROT_WRITE, it doesn't need to be
    // executable yet because I haven't applied the relocations.
    *size  = buf.st_size;
    *image = mmap(NULL, *size, PROT_READ, MAP_SHARED, fd, 0);

    if (*image == MAP_FAILED) {
        l_error("failed to map library %s, %m", filename);
        goto error;
    }

    // If that succeeded, we can proceed.
    l_debug("successfully mapped %s@%p", filename, *image);

    // File descriptor no longer required.
    close(fd);

    // Install a minimal thread information block (TIB), this is required for
    // code that uses SEH as it accesses it via fs selector.
    setup_nt_threadinfo(NULL);

    // Install a minimal KUSER_SHARED_DATA structure.
    setup_kuser_shared_data();

    return true;

error:
    if (fd >= 0)
        close(fd);

    if (image != MAP_FAILED)
        munmap(image, buf.st_size);

    return false;
}

bool setup_nt_threadinfo(PEXCEPTION_HANDLER ExceptionHandler)
{
    static EXCEPTION_FRAME ExceptionFrame;
    static PEB ProcessEnvironmentBlock = {
        .TlsBitmap          = &TlsBitmap,
    };
    static TEB ThreadEnvironment = {
        .Tib.Self                   = &ThreadEnvironment.Tib,
        .ThreadLocalStoragePointer  = LocalStorage, // https://github.com/taviso/loadlibrary/issues/65
        .ProcessEnvironmentBlock    = &ProcessEnvironmentBlock,
    };

    if (ExceptionHandler) {
        if (ThreadEnvironment.Tib.ExceptionList) {
            DebugLog("Resetting ThreadInfo.ExceptionList");
        }
        ExceptionFrame.handler              = ExceptionHandler;
        ExceptionFrame.prev                 = NULL;
        ThreadEnvironment.Tib.ExceptionList = &ExceptionFrame;
    }

#ifdef __x86_64__
    // x86_64: Use arch_prctl to set GS base (Windows x64 uses GS for TEB)
    #ifndef ARCH_SET_GS
    #define ARCH_SET_GS 0x1001
    #endif
    if (syscall(__NR_arch_prctl, ARCH_SET_GS, &ThreadEnvironment) != 0) {
        return false;
    }
#else
    // x86: Use set_thread_area to set up FS segment
    struct user_desc pebdescriptor = {
        .entry_number       = -1,
        .base_addr          = (uintptr_t) &ThreadEnvironment,
        .limit              = sizeof ThreadEnvironment,
        .seg_32bit          = 1,
        .contents           = 0,
        .read_exec_only     = 0,
        .limit_in_pages     = 0,
        .seg_not_present    = 0,
        .useable            = 1,
    };

    if (syscall(__NR_set_thread_area, &pebdescriptor) != 0) {
        return false;
    }

    // Install descriptor
    asm("mov %[segment], %%fs" :: [segment] "r"(pebdescriptor.entry_number*8+3));
#endif

    return true;
}

// Minimal KUSER_SHARED_DATA structure, for those applications that require it.
bool setup_kuser_shared_data(void)
{
    SharedUserData = mmap((PVOID)(MM_SHARED_USER_DATA_VA),
                          sizeof(KUSER_SHARED_DATA),
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                          -1,
                          0);

    if (SharedUserData == MAP_FAILED) {
        DebugLog("failed to map KUSER_SHARED_DATA, %m");
        return false;
    }

    return true;
}
