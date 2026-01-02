#include <capstone/capstone.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "afl_bb_coverage.h"
#include "afl_coverage.h"
#include "log.h"
#include "pe_linker.h"

#define RVA2VA(image, rva, type) (type)((uint8_t *)(image) + (rva))
#define TRAMP_REGION_SIZE (1U << 20)

struct code_range {
    uint32_t start;
    uint32_t end;
};

struct rva_set {
    uint32_t *slots;
    size_t cap;
    size_t count;
};

struct rva_list {
    uint32_t *items;
    size_t count;
    size_t cap;
};

struct rva_queue {
    uint32_t *items;
    size_t head;
    size_t tail;
    size_t cap;
};

struct tramp_region {
    uint8_t *base;
    size_t size;
    size_t offset;
};

struct tramp_pool {
    struct tramp_region *regions;
    size_t count;
    size_t cap;
    uintptr_t image_base;
};

static bool bb_enabled(void)
{
    static int enabled = -1;
    const char *env;

    if (enabled != -1) {
        return enabled != 0;
    }

    env = getenv("LL_AFL_BB_COVERAGE");
    enabled = (env != NULL && atoi(env) > 0) ? 1 : 0;
    return enabled != 0;
}

static unsigned int bb_max_images(void)
{
    static unsigned int max_images = 0;
    const char *env;
    unsigned long value;

    if (max_images != 0) {
        return max_images;
    }

    env = getenv("LL_MAX_IMAGES");
    if (env != NULL && env[0] != '\0') {
        value = strtoul(env, NULL, 10);
        if (value > 0 && value <= UINT32_MAX) {
            max_images = (unsigned int)value;
            return max_images;
        }
    }

    max_images = 64;
    return max_images;
}

static size_t next_pow2(size_t value)
{
    size_t pow2 = 16;

    while (pow2 < value) {
        pow2 <<= 1;
    }

    return pow2;
}

static bool rva_set_init(struct rva_set *set, size_t expected)
{
    set->cap = next_pow2(expected);
    set->count = 0;
    set->slots = calloc(set->cap, sizeof(*set->slots));

    return set->slots != NULL;
}

static void rva_set_free(struct rva_set *set)
{
    free(set->slots);
    memset(set, 0, sizeof(*set));
}

static bool rva_set_grow(struct rva_set *set)
{
    struct rva_set tmp;
    size_t i;

    if (!rva_set_init(&tmp, set->cap * 2)) {
        return false;
    }

    for (i = 0; i < set->cap; i++) {
        uint32_t val = set->slots[i];
        if (val != 0) {
            uint32_t rva = val - 1;
            size_t idx = (rva * 2654435761u) & (tmp.cap - 1);
            while (tmp.slots[idx] != 0) {
                idx = (idx + 1) & (tmp.cap - 1);
            }
            tmp.slots[idx] = val;
            tmp.count++;
        }
    }

    free(set->slots);
    *set = tmp;
    return true;
}

static bool rva_set_insert(struct rva_set *set, uint32_t rva)
{
    uint32_t key = rva + 1;
    size_t idx;

    if (set->count * 2 >= set->cap) {
        if (!rva_set_grow(set)) {
            return false;
        }
    }

    idx = (rva * 2654435761u) & (set->cap - 1);
    while (set->slots[idx] != 0) {
        if (set->slots[idx] == key) {
            return false;
        }
        idx = (idx + 1) & (set->cap - 1);
    }

    set->slots[idx] = key;
    set->count++;
    return true;
}

static bool rva_list_push(struct rva_list *list, uint32_t rva)
{
    uint32_t *items;

    if (list->count == list->cap) {
        size_t next_cap = list->cap ? list->cap * 2 : 128;
        items = realloc(list->items, next_cap * sizeof(*list->items));
        if (items == NULL) {
            return false;
        }
        list->items = items;
        list->cap = next_cap;
    }

    list->items[list->count++] = rva;
    return true;
}

static void rva_list_free(struct rva_list *list)
{
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static bool rva_queue_push(struct rva_queue *queue, uint32_t rva)
{
    uint32_t *items;

    if (queue->tail == queue->cap) {
        size_t next_cap = queue->cap ? queue->cap * 2 : 128;
        items = realloc(queue->items, next_cap * sizeof(*queue->items));
        if (items == NULL) {
            return false;
        }
        queue->items = items;
        queue->cap = next_cap;
    }

    queue->items[queue->tail++] = rva;
    return true;
}

static bool rva_queue_pop(struct rva_queue *queue, uint32_t *out)
{
    if (queue->head >= queue->tail) {
        return false;
    }

    *out = queue->items[queue->head++];
    return true;
}

static void rva_queue_free(struct rva_queue *queue)
{
    free(queue->items);
    memset(queue, 0, sizeof(*queue));
}

static size_t collect_code_ranges(struct pe_image *pe, struct code_range **out)
{
    int sections = PE_FILE_HEADER(pe)->NumberOfSections;
    struct code_range *ranges = calloc((size_t)sections, sizeof(*ranges));
    IMAGE_SECTION_HEADER *sect = PE_FIRST_SECTION(pe);
    uint32_t image_size = (uint32_t)PE_OPT_HDR_FIELD(pe, SizeOfImage);
    size_t count = 0;
    int i;

    if (ranges == NULL) {
        return 0;
    }

    for (i = 0; i < sections; i++, sect++) {
        uint32_t size;
        uint32_t start;
        uint32_t end;

        if ((sect->Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))
            != (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)) {
            continue;
        }

        size = sect->Misc.VirtualSize ? sect->Misc.VirtualSize : sect->SizeOfRawData;
        start = sect->VirtualAddress;
        end = start + size;
        if (end > image_size) {
            end = image_size;
        }
        if (start >= end) {
            continue;
        }

        ranges[count].start = start;
        ranges[count].end = end;
        count++;
    }

    *out = ranges;
    return count;
}

static bool rva_in_ranges(const struct code_range *ranges, size_t count, uint32_t rva, size_t *out_idx)
{
    size_t i;

    for (i = 0; i < count; i++) {
        if (rva >= ranges[i].start && rva < ranges[i].end) {
            if (out_idx) {
                *out_idx = i;
            }
            return true;
        }
    }

    return false;
}

static bool add_seed_rva(const struct code_range *ranges, size_t count, struct rva_queue *queue, uint32_t rva)
{
    if (!rva_in_ranges(ranges, count, rva, NULL)) {
        return false;
    }

    return rva_queue_push(queue, rva);
}

static void add_export_seeds(struct pe_image *pe, const struct code_range *ranges, size_t count, struct rva_queue *queue)
{
    IMAGE_DATA_DIRECTORY *export_dir = &PE_DATA_DIRECTORY(pe)[IMAGE_DIRECTORY_ENTRY_EXPORT];
    IMAGE_EXPORT_DIRECTORY *exports;
    DWORD *funcs;
    DWORD i;

    if (export_dir->VirtualAddress == 0 || export_dir->Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
        return;
    }

    exports = RVA2VA(pe->image, export_dir->VirtualAddress, IMAGE_EXPORT_DIRECTORY *);
    funcs = RVA2VA(pe->image, exports->AddressOfFunctions, DWORD *);

    for (i = 0; i < exports->NumberOfFunctions; i++) {
        uint32_t rva = funcs[i];
        if (rva == 0) {
            continue;
        }
        add_seed_rva(ranges, count, queue, rva);
    }
}

static void add_tls_seeds(struct pe_image *pe, const struct code_range *ranges, size_t count, struct rva_queue *queue)
{
    uint64_t base = (uint64_t)(uintptr_t)pe->image;
    IMAGE_DATA_DIRECTORY *tls_dir = &PE_DATA_DIRECTORY(pe)[IMAGE_DIRECTORY_ENTRY_TLS];
    PIMAGE_TLS_DIRECTORY tls;
    PVOID *callbacks;

    if (PE_OPT_HDR_FIELD(pe, NumberOfRvaAndSizes) <= IMAGE_DIRECTORY_ENTRY_TLS) {
        return;
    }

    if (tls_dir->VirtualAddress == 0 || tls_dir->Size < sizeof(IMAGE_TLS_DIRECTORY)) {
        return;
    }

    tls = RVA2VA(pe->image, tls_dir->VirtualAddress, IMAGE_TLS_DIRECTORY *);
    callbacks = (PVOID *)tls->AddressOfCallbacks;

    if (callbacks == NULL) {
        return;
    }

    for (; *callbacks != NULL; callbacks++) {
        uint64_t addr = (uint64_t)(uintptr_t)*callbacks;
        if (addr < base) {
            continue;
        }
        add_seed_rva(ranges, count, queue, (uint32_t)(addr - base));
    }
}

static bool is_unconditional_jump(const cs_insn *insn)
{
    return insn->id == X86_INS_JMP || insn->id == X86_INS_LJMP;
}

static bool is_syscall_insn(const cs_insn *insn)
{
    return insn->id == X86_INS_SYSCALL || insn->id == X86_INS_SYSENTER;
}

static bool resolve_direct_target(const cs_insn *insn, uint64_t *out_target)
{
    const cs_x86 *x86;
    int i;

    if (insn->detail == NULL) {
        return false;
    }

    x86 = &insn->detail->x86;
    for (i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type == X86_OP_IMM) {
            int64_t imm = x86->operands[i].imm;
            *out_target = (uint64_t)imm;
            return true;
        }
    }

    return false;
}

static bool rel_fits(int64_t value, uint8_t size)
{
    int64_t min;
    int64_t max;

    switch (size) {
    case 1:
        min = -128;
        max = 127;
        break;
    case 2:
        min = -32768;
        max = 32767;
        break;
    case 4:
        min = INT32_MIN;
        max = INT32_MAX;
        break;
    default:
        return false;
    }

    return value >= min && value <= max;
}

static bool relocate_branch(csh handle, const cs_insn *insn, uint8_t *dst_bytes, uint64_t dst_addr)
{
    const cs_x86 *x86;
    uint8_t imm_offset;
    uint8_t imm_size;
    uint64_t target;
    int64_t disp;
    int i;
    bool is_relative;

    if (!cs_insn_group(handle, insn, CS_GRP_JUMP)
     && !cs_insn_group(handle, insn, CS_GRP_CALL)) {
        return true;
    }

    is_relative = cs_insn_group(handle, insn, CS_GRP_BRANCH_RELATIVE);
    if (!is_relative) {
        return true;
    }

    x86 = &insn->detail->x86;
    imm_offset = x86->encoding.imm_offset;
    imm_size = x86->encoding.imm_size;

    if (imm_size == 0) {
        return true;
    }

    for (i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type != X86_OP_IMM) {
            continue;
        }
        disp = x86->operands[i].imm;
        target = (uint64_t)disp;
        disp = (int64_t)target - (int64_t)(dst_addr + insn->size);
        if (!rel_fits(disp, imm_size)) {
            return false;
        }
        memcpy(dst_bytes + imm_offset, &disp, imm_size);
        return true;
    }

    return true;
}

static bool relocate_rip_relative(const cs_insn *insn, uint8_t *dst_bytes, uint64_t dst_addr)
{
    const cs_x86 *x86;
    uint8_t disp_offset;
    uint8_t disp_size;
    int64_t disp;
    uint64_t target;
    int i;

    if (insn->detail == NULL) {
        return true;
    }

    x86 = &insn->detail->x86;
    disp_offset = x86->encoding.disp_offset;
    disp_size = x86->encoding.disp_size;

    if (disp_size == 0) {
        return true;
    }

    for (i = 0; i < x86->op_count; i++) {
        if (x86->operands[i].type != X86_OP_MEM) {
            continue;
        }
        if (x86->operands[i].mem.base != X86_REG_RIP) {
            continue;
        }

        disp = x86->operands[i].mem.disp;
        target = insn->address + insn->size + disp;
        disp = (int64_t)target - (int64_t)(dst_addr + insn->size);
        if (!rel_fits(disp, disp_size)) {
            return false;
        }
        memcpy(dst_bytes + disp_offset, &disp, disp_size);
        return true;
    }

    return true;
}

static bool relocate_instruction(csh handle, const cs_insn *insn, uint8_t *dst_bytes, uint64_t dst_addr)
{
    if (insn->detail == NULL) {
        return true;
    }

    if (!relocate_branch(handle, insn, dst_bytes, dst_addr)) {
        return false;
    }

    if (!relocate_rip_relative(insn, dst_bytes, dst_addr)) {
        return false;
    }

    return true;
}

static bool is_rel32(int64_t value)
{
    return value >= INT32_MIN && value <= INT32_MAX;
}

static bool make_writable_range(void *addr, size_t len)
{
    size_t page_size = (size_t)getpagesize();
    uintptr_t start = (uintptr_t)addr & ~(page_size - 1);
    uintptr_t end = ((uintptr_t)addr + len + page_size - 1) & ~(page_size - 1);

    for (; start < end; start += page_size) {
        if (mprotect((void *)start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            return false;
        }
    }

    return true;
}

static bool tramp_pool_add_region(struct tramp_pool *pool, size_t size, bool prefer_near)
{
    struct tramp_region region = {0};
    void *hint = NULL;
    void *addr = MAP_FAILED;
    uintptr_t base = pool->image_base;
    size_t page_size = (size_t)getpagesize();
    size_t aligned = (size + page_size - 1) & ~(page_size - 1);
    uintptr_t start_hint;
    uintptr_t end_hint;
    uintptr_t hints[6];
    size_t hint_count = 0;
    int i;

    start_hint = (base + aligned + page_size) & ~(page_size - 1);
    end_hint = (base > aligned + page_size) ? (base - aligned - page_size) : 0;

    if (prefer_near) {
        if (start_hint != 0) {
            hints[hint_count++] = start_hint;
            hints[hint_count++] = start_hint + (1U << 20);
            hints[hint_count++] = start_hint + (1U << 24);
        }
        if (end_hint != 0) {
            hints[hint_count++] = end_hint;
            if (end_hint > (1U << 20)) {
                hints[hint_count++] = end_hint - (1U << 20);
            }
            if (end_hint > (1U << 24)) {
                hints[hint_count++] = end_hint - (1U << 24);
            }
        }

        for (i = 0; i < (int)hint_count; i++) {
            hint = (void *)hints[i];
            addr = mmap(hint, aligned, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (addr != MAP_FAILED) {
                break;
            }
        }
    }

    if (addr == MAP_FAILED) {
        addr = mmap(NULL, aligned, PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            return false;
        }
    }

    region.base = addr;
    region.size = aligned;
    region.offset = 0;

    if (pool->count == pool->cap) {
        size_t next_cap = pool->cap ? pool->cap * 2 : 4;
        struct tramp_region *regions = realloc(pool->regions, next_cap * sizeof(*regions));
        if (regions == NULL) {
            munmap(addr, aligned);
            return false;
        }
        pool->regions = regions;
        pool->cap = next_cap;
    }

    pool->regions[pool->count++] = region;
    return true;
}

static void *tramp_pool_alloc(struct tramp_pool *pool, size_t size)
{
    struct tramp_region *region;
    size_t i;

    for (i = 0; i < pool->count; i++) {
        region = &pool->regions[i];
        if (region->offset + size <= region->size) {
            void *addr = region->base + region->offset;
            region->offset += size;
            return addr;
        }
    }

    if (!tramp_pool_add_region(pool, size > TRAMP_REGION_SIZE ? size : TRAMP_REGION_SIZE, true)) {
        return NULL;
    }

    region = &pool->regions[pool->count - 1];
    region->offset += size;
    return region->base;
}

static void tramp_pool_free(struct tramp_pool *pool)
{
    free(pool->regions);
    memset(pool, 0, sizeof(*pool));
}

static size_t compute_patch_len(csh handle, cs_insn *insn, const uint8_t *base,
                                uint64_t addr, size_t max_len, size_t required)
{
    const uint8_t *cursor = base;
    size_t size = max_len;
    size_t total = 0;
    bool terminator = false;

    while (total < required && size > 0) {
        if (!cs_disasm_iter(handle, &cursor, &size, &addr, insn)) {
            return 0;
        }
        total += insn->size;

        if (cs_insn_group(handle, insn, CS_GRP_JUMP)
         || cs_insn_group(handle, insn, CS_GRP_CALL)
         || cs_insn_group(handle, insn, CS_GRP_RET)
         || cs_insn_group(handle, insn, CS_GRP_INT)
         || cs_insn_group(handle, insn, CS_GRP_IRET)
         || is_syscall_insn(insn)) {
            terminator = true;
            if (total < required) {
                return 0;
            }
            break;
        }
    }

    if (!terminator && total < required) {
        return 0;
    }

    return total;
}

static bool copy_relocated_bytes(csh handle, cs_insn *insn, const uint8_t *src,
                                 uint64_t src_addr, uint8_t *dst, size_t len)
{
    const uint8_t *cursor = src;
    size_t size = len;
    uint64_t addr = src_addr;

    while (size > 0) {
        uint64_t dst_addr;

        if (!cs_disasm_iter(handle, &cursor, &size, &addr, insn)) {
            return false;
        }

        dst_addr = (uint64_t)(uintptr_t)dst;
        memcpy(dst, insn->bytes, insn->size);
        if (!relocate_instruction(handle, insn, dst, dst_addr)) {
            return false;
        }

        dst += insn->size;
        if (insn->size > len) {
            return false;
        }
        len -= insn->size;
    }

    return true;
}

static uint8_t *emit_u8(uint8_t *p, uint8_t v)
{
    *p++ = v;
    return p;
}

static uint8_t *emit_u32(uint8_t *p, uint32_t v)
{
    memcpy(p, &v, sizeof(v));
    return p + sizeof(v);
}

static uint8_t *emit_u64(uint8_t *p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
    return p + sizeof(v);
}

static bool build_trampoline_x86(csh handle, cs_insn *insn, uint8_t *tramp,
                                 size_t tramp_size, const uint8_t *src,
                                 uint64_t src_addr, size_t patch_len)
{
    uint8_t *p = tramp;
    uint8_t *end = tramp + tramp_size;
    int64_t rel;

    if ((size_t)(end - p) < patch_len + 32) {
        return false;
    }

    p = emit_u8(p, 0x9C);
    p = emit_u8(p, 0x60);

    p = emit_u8(p, 0x68);
    p = emit_u32(p, (uint32_t)src_addr);

    p = emit_u8(p, 0xE8);
    rel = (int64_t)(uintptr_t)afl_coverage_hit_pc - (int64_t)(uintptr_t)(p + 4);
    if (!is_rel32(rel)) {
        return false;
    }
    p = emit_u32(p, (uint32_t)rel);

    p = emit_u8(p, 0x83);
    p = emit_u8(p, 0xC4);
    p = emit_u8(p, 0x04);

    p = emit_u8(p, 0x61);
    p = emit_u8(p, 0x9D);

    if (!copy_relocated_bytes(handle, insn, src, src_addr, p, patch_len)) {
        return false;
    }
    p += patch_len;

    p = emit_u8(p, 0xE9);
    rel = (int64_t)(src_addr + patch_len) - (int64_t)(uintptr_t)(p + 4);
    if (!is_rel32(rel)) {
        return false;
    }
    p = emit_u32(p, (uint32_t)rel);

    return true;
}

static uint8_t *emit_push_reg(uint8_t *p, uint8_t reg)
{
    if (reg < 8) {
        return emit_u8(p, 0x50 + reg);
    }

    p = emit_u8(p, 0x41);
    return emit_u8(p, 0x50 + (reg - 8));
}

static uint8_t *emit_pop_reg(uint8_t *p, uint8_t reg)
{
    if (reg < 8) {
        return emit_u8(p, 0x58 + reg);
    }

    p = emit_u8(p, 0x41);
    return emit_u8(p, 0x58 + (reg - 8));
}

static bool build_trampoline_x64(csh handle, cs_insn *insn, uint8_t *tramp,
                                 size_t tramp_size, const uint8_t *src,
                                 uint64_t src_addr, size_t patch_len)
{
    uint8_t *p = tramp;
    uint8_t *end = tramp + tramp_size;
    int64_t rel;
    size_t i;
    static const uint8_t regs[] = { 0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    size_t reg_count = sizeof(regs) / sizeof(regs[0]);

    if ((size_t)(end - p) < patch_len + 128) {
        return false;
    }

    p = emit_u8(p, 0x9C);
    for (i = 0; i < reg_count; i++) {
        p = emit_push_reg(p, regs[i]);
    }

    p = emit_u8(p, 0x4C);
    p = emit_u8(p, 0x8B);
    p = emit_u8(p, 0xDC);

    p = emit_u8(p, 0x48);
    p = emit_u8(p, 0x83);
    p = emit_u8(p, 0xE4);
    p = emit_u8(p, 0xF0);

    p = emit_u8(p, 0x48);
    p = emit_u8(p, 0x83);
    p = emit_u8(p, 0xEC);
    p = emit_u8(p, 0x20);

    p = emit_u8(p, 0x48);
    p = emit_u8(p, 0xBF);
    p = emit_u64(p, src_addr);

    p = emit_u8(p, 0x48);
    p = emit_u8(p, 0xB8);
    p = emit_u64(p, (uint64_t)(uintptr_t)afl_coverage_hit_pc);
    p = emit_u8(p, 0xFF);
    p = emit_u8(p, 0xD0);

    p = emit_u8(p, 0x4C);
    p = emit_u8(p, 0x89);
    p = emit_u8(p, 0xDC);

    for (i = reg_count; i-- > 0;) {
        p = emit_pop_reg(p, regs[i]);
    }
    p = emit_u8(p, 0x9D);

    if (!copy_relocated_bytes(handle, insn, src, src_addr, p, patch_len)) {
        return false;
    }
    p += patch_len;

    rel = (int64_t)(src_addr + patch_len) - (int64_t)(uintptr_t)(p + 5);
    if (is_rel32(rel)) {
        p = emit_u8(p, 0xE9);
        p = emit_u32(p, (uint32_t)rel);
    } else {
        p = emit_u8(p, 0x48);
        p = emit_u8(p, 0xB8);
        p = emit_u64(p, src_addr + patch_len);
        p = emit_u8(p, 0xFF);
        p = emit_u8(p, 0xE0);
    }

    return true;
}

static bool patch_block_x86(csh handle, cs_insn *insn, struct tramp_pool *pool,
                            const uint8_t *image, uint32_t rva,
                            const struct code_range *ranges, size_t range_idx,
                            const uint32_t *sorted_blocks, size_t block_index,
                            size_t block_count)
{
    const uint8_t *src = image + rva;
    uint64_t src_addr = (uint64_t)(uintptr_t)src;
    size_t max_len = ranges[range_idx].end - rva;
    size_t patch_size = 5;
    size_t patch_len;
    size_t next_rva = 0;
    uint8_t *tramp;
    size_t tramp_size;
    int64_t rel;
    uint8_t *dst;

    patch_len = compute_patch_len(handle, insn, src, src_addr, max_len, patch_size);
    if (patch_len == 0) {
        return false;
    }

    if (block_index + 1 < block_count) {
        next_rva = sorted_blocks[block_index + 1];
        if (next_rva > rva && next_rva < rva + patch_len) {
            return false;
        }
    }

    tramp_size = patch_len + 32;
    tramp = tramp_pool_alloc(pool, tramp_size);
    if (tramp == NULL) {
        return false;
    }

    if (!build_trampoline_x86(handle, insn, tramp, tramp_size, src, src_addr, patch_len)) {
        return false;
    }

    if (!make_writable_range((void *)src, patch_len)) {
        return false;
    }

    rel = (int64_t)(uintptr_t)tramp - (int64_t)(src_addr + 5);
    if (!is_rel32(rel)) {
        return false;
    }

    dst = (uint8_t *)src;
    dst[0] = 0xE9;
    memcpy(dst + 1, &rel, sizeof(int32_t));
    if (patch_len > patch_size) {
        memset(dst + patch_size, 0x90, patch_len - patch_size);
    }

    return true;
}

static bool patch_block_x64(csh handle, cs_insn *insn, struct tramp_pool *pool,
                            const uint8_t *image, uint32_t rva,
                            const struct code_range *ranges, size_t range_idx,
                            const uint32_t *sorted_blocks, size_t block_index,
                            size_t block_count)
{
    const uint8_t *src = image + rva;
    uint64_t src_addr = (uint64_t)(uintptr_t)src;
    size_t max_len = ranges[range_idx].end - rva;
    uint8_t *tramp;
    size_t tramp_size;
    uint8_t *dst;
    size_t patch_size;
    size_t patch_len;
    size_t next_rva = 0;
    int64_t rel;

    patch_size = 5;
    patch_len = compute_patch_len(handle, insn, src, src_addr, max_len, patch_size);
    if (patch_len == 0) {
        patch_size = 14;
        patch_len = compute_patch_len(handle, insn, src, src_addr, max_len, patch_size);
        if (patch_len == 0) {
            return false;
        }
    }

    if (block_index + 1 < block_count) {
        next_rva = sorted_blocks[block_index + 1];
        if (next_rva > rva && next_rva < rva + patch_len) {
            return false;
        }
    }

    tramp_size = patch_len + 128;
    tramp = tramp_pool_alloc(pool, tramp_size);
    if (tramp == NULL) {
        return false;
    }

    if (patch_size == 5) {
        rel = (int64_t)(uintptr_t)tramp - (int64_t)(src_addr + 5);
        if (!is_rel32(rel)) {
            patch_size = 14;
            patch_len = compute_patch_len(handle, insn, src, src_addr, max_len, patch_size);
            if (patch_len == 0) {
                return false;
            }
            if (block_index + 1 < block_count) {
                next_rva = sorted_blocks[block_index + 1];
                if (next_rva > rva && next_rva < rva + patch_len) {
                    return false;
                }
            }
            tramp_size = patch_len + 128;
            tramp = tramp_pool_alloc(pool, tramp_size);
            if (tramp == NULL) {
                return false;
            }
        }
    }

    if (!build_trampoline_x64(handle, insn, tramp, tramp_size, src, src_addr, patch_len)) {
        return false;
    }

    if (!make_writable_range((void *)src, patch_len)) {
        return false;
    }

    dst = (uint8_t *)src;
    if (patch_size == 5) {
        rel = (int64_t)(uintptr_t)tramp - (int64_t)(src_addr + 5);
        if (!is_rel32(rel)) {
            return false;
        }
        dst[0] = 0xE9;
        memcpy(dst + 1, &rel, sizeof(int32_t));
    } else {
        uint64_t tramp_addr = (uint64_t)(uintptr_t)tramp;
        dst[0] = 0x48;
        dst[1] = 0xB8;
        memcpy(dst + 2, &tramp_addr, sizeof(tramp_addr));
        dst[10] = 0xFF;
        dst[11] = 0xE0;
        dst[12] = 0x90;
        dst[13] = 0x90;
    }

    if (patch_len > patch_size) {
        memset(dst + patch_size, 0x90, patch_len - patch_size);
    }

    return true;
}

static int compare_rva(const void *a, const void *b)
{
    uint32_t lhs = *(const uint32_t *)a;
    uint32_t rhs = *(const uint32_t *)b;

    if (lhs < rhs) {
        return -1;
    }
    if (lhs > rhs) {
        return 1;
    }
    return 0;
}

void afl_bb_coverage_instrument(struct pe_image *pe)
{
    static unsigned int instrumented = 0;
    struct code_range *ranges = NULL;
    struct rva_set visited = {0};
    struct rva_queue queue = {0};
    struct rva_list blocks = {0};
    struct tramp_pool pool = {0};
    csh handle;
    cs_insn *insn;
    size_t range_count;
    uint32_t entry_rva;
    unsigned int max_images;
    uint32_t rva;

    if (!bb_enabled()) {
        return;
    }

    max_images = bb_max_images();
    if (instrumented >= max_images) {
        return;
    }

    instrumented++;

    if (pe == NULL || pe->image == NULL) {
        return;
    }

    if (pe->is_64bit && sizeof(void *) < 8) {
        l_warning("cannot instrument 64-bit image in 32-bit build");
        return;
    }

    range_count = collect_code_ranges(pe, &ranges);
    if (range_count == 0) {
        free(ranges);
        return;
    }

    if (!rva_set_init(&visited, 1024)) {
        free(ranges);
        return;
    }

    if (cs_open(CS_ARCH_X86, pe->is_64bit ? CS_MODE_64 : CS_MODE_32, &handle) != CS_ERR_OK) {
        rva_set_free(&visited);
        free(ranges);
        return;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    insn = cs_malloc(handle);
    if (insn == NULL) {
        cs_close(&handle);
        rva_set_free(&visited);
        free(ranges);
        return;
    }

    entry_rva = (uint32_t)PE_OPT_HDR_FIELD(pe, AddressOfEntryPoint);
    if (entry_rva != 0) {
        add_seed_rva(ranges, range_count, &queue, entry_rva);
    }

    add_export_seeds(pe, ranges, range_count, &queue);
    add_tls_seeds(pe, ranges, range_count, &queue);

    while (rva_queue_pop(&queue, &rva)) {
        size_t range_idx;
        const uint8_t *cursor;
        size_t size;
        uint64_t addr;

        if (!rva_in_ranges(ranges, range_count, rva, &range_idx)) {
            continue;
        }
        if (!rva_set_insert(&visited, rva)) {
            continue;
        }
        if (!rva_list_push(&blocks, rva)) {
            break;
        }

        cursor = (const uint8_t *)pe->image + rva;
        size = ranges[range_idx].end - rva;
        addr = (uint64_t)(uintptr_t)pe->image + rva;

        while (size > 0) {
            uint64_t target;
            bool is_jump;
            bool is_call;
            bool is_ret;
            bool is_cond_jump;

            if (!cs_disasm_iter(handle, &cursor, &size, &addr, insn)) {
                break;
            }

            is_jump = cs_insn_group(handle, insn, CS_GRP_JUMP);
            is_call = cs_insn_group(handle, insn, CS_GRP_CALL);
            is_ret = cs_insn_group(handle, insn, CS_GRP_RET);
            is_cond_jump = is_jump && !is_unconditional_jump(insn);

            if (is_jump || is_call) {
                uint32_t target_rva;
                if (resolve_direct_target(insn, &target)) {
                    if (target >= (uint64_t)(uintptr_t)pe->image) {
                        target_rva = (uint32_t)(target - (uint64_t)(uintptr_t)pe->image);
                        add_seed_rva(ranges, range_count, &queue, target_rva);
                    }
                }
            }

            if (is_cond_jump || is_call) {
                uint32_t fall_rva = (uint32_t)(addr - (uint64_t)(uintptr_t)pe->image);
                add_seed_rva(ranges, range_count, &queue, fall_rva);
            }

            if (is_jump || is_call || is_ret
             || cs_insn_group(handle, insn, CS_GRP_INT)
             || cs_insn_group(handle, insn, CS_GRP_IRET)
             || is_syscall_insn(insn)) {
                break;
            }
        }
    }

    if (blocks.count > 0) {
        size_t i;
        qsort(blocks.items, blocks.count, sizeof(*blocks.items), compare_rva);
        pool.image_base = (uintptr_t)pe->image;

        if (!tramp_pool_add_region(&pool, TRAMP_REGION_SIZE, true)) {
            tramp_pool_free(&pool);
            rva_queue_free(&queue);
            rva_list_free(&blocks);
            rva_set_free(&visited);
            cs_free(insn, 1);
            cs_close(&handle);
            free(ranges);
            return;
        }

        for (i = 0; i < blocks.count; i++) {
            size_t range_idx;

            if (!rva_in_ranges(ranges, range_count, blocks.items[i], &range_idx)) {
                continue;
            }

            if (pe->is_64bit) {
                patch_block_x64(handle, insn, &pool, pe->image, blocks.items[i],
                                ranges, range_idx, blocks.items, i, blocks.count);
            } else {
                patch_block_x86(handle, insn, &pool, pe->image, blocks.items[i],
                                ranges, range_idx, blocks.items, i, blocks.count);
            }
        }
    }

    tramp_pool_free(&pool);
    rva_queue_free(&queue);
    rva_list_free(&blocks);
    rva_set_free(&visited);
    cs_free(insn, 1);
    cs_close(&handle);
    free(ranges);
}
