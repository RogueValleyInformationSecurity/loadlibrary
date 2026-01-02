#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/user.h>
#include <unistd.h>
#include <capstone/capstone.h>
#include "hook.h"

// Routines to intercept or redirect routines.
// Author: Tavis Ormandy

// This was chosen arbitrarily, the maximum amount of code we will search to
// find a call when looking for callsites, feel free to adjust as required.
#define MAX_FUNCTION_LENGTH 2048

// A redirect is usually 9 bytes (5 bytes of call, 4 bytes of encoded size),
// but we round it up to the next instruction boundary. Because of this, the
// worst possible case would be a 15 byte instruction, followed by 15 byte
// instruction (where 15 is the longest possible instruction intel allows).
#define MAX_REDIRECT_LENGTH 32

static csh cs_handle;
static cs_insn *cs_insn_cache;

static bool is_controlflow_insn(const cs_insn *insn)
{
    return cs_insn_group(cs_handle, insn, CS_GRP_JUMP)
        || cs_insn_group(cs_handle, insn, CS_GRP_CALL)
        || cs_insn_group(cs_handle, insn, CS_GRP_RET)
        || cs_insn_group(cs_handle, insn, CS_GRP_INT)
        || cs_insn_group(cs_handle, insn, CS_GRP_IRET);
}

static bool is_call_insn(const cs_insn *insn)
{
    return cs_insn_group(cs_handle, insn, CS_GRP_CALL);
}

static bool is_x64(void)
{
    return sizeof(void *) == 8;
}

static size_t hook_jump_size(void)
{
    return is_x64() ? 12 : 5;
}

static size_t hook_call_size(void)
{
    return is_x64() ? 12 : 5;
}

static bool rel32_fits(int64_t rel)
{
    return rel >= INT32_MIN && rel <= INT32_MAX;
}

static bool rel_fits(int64_t value, uint8_t size)
{
    switch (size) {
    case 1:
        return value >= -128 && value <= 127;
    case 2:
        return value >= -32768 && value <= 32767;
    case 4:
        return value >= INT32_MIN && value <= INT32_MAX;
    default:
        return false;
    }
}

static bool write_rel32(uint8_t *at, uint8_t opcode, void *target)
{
    int64_t rel = (int64_t)(uintptr_t)target - (int64_t)((uintptr_t)at + 5);
    int32_t rel32;

    if (!rel32_fits(rel)) {
        return false;
    }

    rel32 = (int32_t)rel;
    at[0] = opcode;
    memcpy(at + 1, &rel32, sizeof(rel32));
    return true;
}

static void write_abs64(uint8_t *at, void *target, uint8_t op2)
{
    uint64_t addr = (uint64_t)(uintptr_t)target;

    at[0] = 0x48;
    at[1] = 0xB8;
    memcpy(at + 2, &addr, sizeof(addr));
    at[10] = 0xFF;
    at[11] = op2;
}

static bool write_jump(uint8_t *at, void *target)
{
    if (is_x64()) {
        write_abs64(at, target, 0xE0);
        return true;
    }

    return write_rel32(at, X86_OPCODE_JMP_NEAR, target);
}

static bool write_call(uint8_t *at, void *target)
{
    if (is_x64()) {
        write_abs64(at, target, 0xD0);
        return true;
    }

    return write_rel32(at, X86_OPCODE_CALL_NEAR, target);
}

static void *read_jump_target(const uint8_t *at)
{
    if (is_x64()) {
        if (at[0] != 0x48 || at[1] != 0xB8 || at[10] != 0xFF || at[11] != 0xE0) {
            return NULL;
        }

        return (void *)(uintptr_t)(*(const uint64_t *)(at + 2));
    }

    {
        int32_t rel32;
        memcpy(&rel32, at + 1, sizeof(rel32));
        return (void *)((uintptr_t)at + 5 + rel32);
    }
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

static size_t page_align(size_t size)
{
    size_t page_size = (size_t)getpagesize();
    return (size + page_size - 1) & ~(page_size - 1);
}

static void *alloc_exec(size_t size)
{
    size_t alloc_size = page_align(size);
    void *addr = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (addr == MAP_FAILED) {
        return NULL;
    }

    return addr;
}

static void *alloc_exec_near(void *origin, size_t size)
{
    size_t page_size = (size_t)getpagesize();
    size_t alloc_size = page_align(size);
    uintptr_t base = (uintptr_t)origin;
    uintptr_t start_hint;
    uintptr_t end_hint;
    uintptr_t hints[6];
    size_t hint_count = 0;
    size_t i;

    start_hint = (base + alloc_size + page_size) & ~(page_size - 1);
    end_hint = (base > alloc_size + page_size) ? (base - alloc_size - page_size) : 0;

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

    for (i = 0; i < hint_count; i++) {
        void *addr = mmap((void *)hints[i], alloc_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED) {
            continue;
        }

        if (rel32_fits((int64_t)(uintptr_t)addr - (int64_t)((uintptr_t)origin + 5))) {
            return addr;
        }

        munmap(addr, alloc_size);
    }

    return NULL;
}

static void *build_call_stub(void *callsite, void *target)
{
    uint8_t *stub = alloc_exec_near(callsite, 16);

    if (stub == NULL) {
        return NULL;
    }

    write_abs64(stub, target, 0xD0);
    stub[12] = 0xC3;

    return stub;
}

static bool resolve_call_target(const cs_insn *insn, uint64_t *out_target)
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

static bool relocate_rip_relative(uint8_t *dst, const uint8_t *src, size_t len, uint64_t src_addr)
{
    const uint8_t *cursor = src;
    size_t size = len;
    uint64_t addr = src_addr;
    uint8_t *dst_cursor = dst;

    while (size > 0) {
        const cs_x86 *x86;
        uint8_t disp_offset;
        uint8_t disp_size;
        int64_t disp;
        uint64_t target;
        int i;

        if (!cs_disasm_iter(cs_handle, &cursor, &size, &addr, cs_insn_cache)) {
            return false;
        }

        if (cs_insn_cache->detail != NULL) {
            x86 = &cs_insn_cache->detail->x86;
            disp_offset = x86->encoding.disp_offset;
            disp_size = x86->encoding.disp_size;

            if (disp_size != 0) {
                for (i = 0; i < x86->op_count; i++) {
                    if (x86->operands[i].type != X86_OP_MEM) {
                        continue;
                    }
                    if (x86->operands[i].mem.base != X86_REG_RIP) {
                        continue;
                    }

                    disp = x86->operands[i].mem.disp;
                    target = cs_insn_cache->address + cs_insn_cache->size + disp;
                    disp = (int64_t)target - (int64_t)((uintptr_t)dst_cursor + cs_insn_cache->size);
                    if (!rel_fits(disp, disp_size)) {
                        return false;
                    }
                    memcpy(dst_cursor + disp_offset, &disp, disp_size);
                    break;
                }
            }
        }

        dst_cursor += cs_insn_cache->size;
    }

    return true;
}

static void __attribute__((constructor)) init(void)
{
    cs_mode mode = sizeof(void *) == 8 ? CS_MODE_64 : CS_MODE_32;

    if (cs_open(CS_ARCH_X86, mode, &cs_handle) != CS_ERR_OK) {
        fprintf(stderr, "error: failed to initialize Capstone\n");
        abort();
    }

    cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_insn_cache = cs_malloc(cs_handle);
    if (cs_insn_cache == NULL) {
        fprintf(stderr, "error: failed to allocate Capstone instruction cache\n");
        abort();
    }
}

// Intercept calls to this function and execute redirect first. Depending on
// flags, you can either replace this function, or simply be inserted into the
// call chain.
//  function    The address of the function you want intercepted.
//  redirect    Your callback function. The prototype should be the same as
//              function, except an additional first parameter which you can
//              ignore (it's the return address for the caller).
//  flags       Options, see header file for flags available. Use HOOK_DEFAULT
//              if you don't need any.
//
// Remember to add an additional parameter to your redirect, e.g. if you were
// expecting tcp_input(struct mbuf *m, int len), your redirect should be:
//
// my_tcp_input(intptr_t retaddr, struct mbuf *m, int len);
//
// *UNLESS* You are using the flag HOOK_REPLACE_FUNCTION, in which case the
// prototype is the same, as you literally become the function instead of
// intercepting it.
bool insert_function_redirect(void *function, void *redirect, uint32_t flags)
{
    size_t              redirectsize    = 0;
    unsigned            insncount       = 0;
    size_t              jump_size       = hook_jump_size();
    size_t              call_size       = hook_call_size();
    size_t              min_redirect    = jump_size + sizeof(struct encodedsize);
    size_t              fixup_size      = 0;
    size_t              fixup_alloc     = 0;
    uint8_t            *fixup;
    uint8_t            *callsite;
    struct encodedsize *savedoffset;
    uint8_t            *cursor_bytes;

    // Keep disassembling until I have enough bytes of code to store my
    // redirect, five bytes for the redirect call, and four bytes to record the
    // length to restore when we're unloaded.
    //
    // XXX: If there is a branch target or return within the first few bytes,
    //      we cannot relocate safely. We refuse to redirect in that case.
    //
    for (redirectsize = 0; redirectsize < min_redirect; insncount++) {
        const uint8_t  *cursor          = (const uint8_t *)function + redirectsize;
        size_t          size            = MAX_REDIRECT_LENGTH - redirectsize;
        uint64_t        address         = (uintptr_t)cursor;
        ssize_t         insnlength      = 0;

        if (cs_disasm_iter(cs_handle, &cursor, &size, &address, cs_insn_cache)) {
            insnlength = (ssize_t)cs_insn_cache->size;

            if (redirectsize + (size_t)insnlength > MAX_REDIRECT_LENGTH) {
                printf("error: redirect size exceeds max length at %p\n", function);
                return false;
            }

            // Valid, increment size.
            redirectsize += insnlength;

            // Check for branches just to be safe, as these instructions are
            // relative and cannot be relocated safely (there are others of
            // course, but these are the most likely).
            if (is_controlflow_insn(cs_insn_cache) && flags != HOOK_REPLACE_FUNCTION) {
                printf("error: refusing to redirect function %p due to early controlflow manipulation (+%zu)\n",
                       function,
                       redirectsize);

                return false;
            }

            // Next instuction.
            continue;
        }

        // Invalid instruction, abort.
        printf("error: %s encountered an invalid instruction @%p+%zu, so redirection was aborted\n",
               __func__,
               function,
               redirectsize);

        return false;
    }

    // We need to create a fixup, a small chunk of code that repairs the damage
    // we did redirecting the function. This basically handles calling the
    // redirect, then fixes the damage and restores execution. So it's going to be
    // redirectsize + call_size + jump_size bytes, which looks like this:
    //
    // call/jmp  your_routine              ; call_size bytes
    // <code clobbered to get here>             ; redirectsize bytes
    // jmp       original_routine+redirectsize  ; jump_size bytes
    //
    // Your routine will get an extra first argument which you should
    // ignore, e.g.
    //
    //  void your_routine(uintptr_t retaddr, int expected_arg1, void *expected_arg2, etc);
    //
    // If you replace the function instead of redirect it, you don't get the extra
    // parameter, because we literally just jmp to your routine instead of call
    // it. The call operand is a relative, displaced address, hence the
    // calculation.
    //

    fixup_size = redirectsize + call_size + jump_size;
    fixup_alloc = page_align(fixup_size);

    if (is_x64()) {
        fixup = alloc_exec_near(function, fixup_alloc);
        if (fixup == NULL) {
            fixup = alloc_exec(fixup_alloc);
        }
    } else {
        fixup = alloc_exec(fixup_alloc);
    }

    if (fixup == NULL) {
        return false;
    }
    memset(fixup, 0, fixup_size);

    cursor_bytes = fixup;
    if (flags & HOOK_REPLACE_FUNCTION) {
        if (!write_jump(cursor_bytes, redirect)) {
            munmap(fixup, fixup_alloc);
            return false;
        }
    } else {
        if (!write_call(cursor_bytes, redirect)) {
            munmap(fixup, fixup_alloc);
            return false;
        }
    }
    cursor_bytes += call_size;

    // Copy over the code we are going to clobber by installing the redirect.
    memcpy(cursor_bytes, function, redirectsize);
    if (is_x64() && !(flags & HOOK_REPLACE_FUNCTION)) {
        if (!relocate_rip_relative(cursor_bytes, function, redirectsize,
                                   (uint64_t)(uintptr_t)function)) {
            munmap(fixup, fixup_alloc);
            return false;
        }
    }
    cursor_bytes += redirectsize;

    // And install a branch to restore execution to the rest of the original routine.
    if (!write_jump(cursor_bytes, (uint8_t *)function + redirectsize)) {
        munmap(fixup, fixup_alloc);
        return false;
    }

    // Now I need to install the redirect, I also clobber any left over bytes
    // with x86 nops, so as not to disrupt disassemblers while debugging.
    callsite             = (uint8_t *)function;

    // In general this is expected to be called on functions.
    if (!is_x64() && callsite[0] != X86_OPCODE_PUSH_EBP) {
#ifndef NDEBUG
        printf("warning: requested hook location %p does not look like a function, begins with opcode %#02x.\n",
               callsite,
               callsite[0]);
#endif
    }

    if (!make_writable_range(callsite, redirectsize)) {
        munmap(fixup, fixup_alloc);
        return false;
    }

    if (!write_jump(callsite, fixup)) {
        munmap(fixup, fixup_alloc);
        return false;
    }

    // I need to remember how much data I clobbered so that I can restore it
    // when my module is unloaded. I do this by encoding it as an instruction, e.g.
    //
    //   mov eax, imm16
    //
    // This is so as not to disrupt disassembly.
    savedoffset          = (void *)(callsite + jump_size);
    savedoffset->prefix  = X86_PREFIX_DATA16;
    savedoffset->opcode  = X86_OPCODE_MOV_EAX_IMM;
    savedoffset->operand = (uint16_t)redirectsize;

    // Clean up the left over slack bytes (not acutally needed, as we're careful to
    // restore execution to the next valid instructions, but intended to make
    // sure we dont desync disassembly when debugging problems in kgdb).
    if (redirectsize > jump_size + sizeof(struct encodedsize)) {
        memset(callsite + jump_size + sizeof(struct encodedsize),
               X86_OPCODE_NOP,
               redirectsize - jump_size - sizeof(struct encodedsize));
    }

    //printf("info: successfully installed %lu byte (%u instructions) redirect from %p to %p, via fixup@%p\n",
    //       redirectsize,
    //       insncount,
    //       function,
    //       redirect,
    //       fixup);

    return true;
}

// This routine will simply remove a previously inserted redirect. It's careful
// to verify there really is a redirect present, but you should probably be
// careful.
//
//  function    The location of the redirected function to restore.
//
bool remove_function_redirect(void *function)
{
    uint8_t              *callsite;
    struct encodedsize   *savedsize;
    void                 *fixup;
    size_t                jump_size;
    size_t                call_size;
    size_t                fixup_size;
    size_t                fixup_alloc;

    // The process for removal is:
    //
    //  * Read the branch instuction and the encoded size from the original location.
    //  * From this, calculate the fixup address.
    //  * Restore the clobbered data from the fixup to the function using the
    //    size I recorded in the original function.
    //  * munmap() the fixup.
    //
    // And that's it, so let's grab the branch instruction.
    callsite            = (uint8_t *)function;
    jump_size           = hook_jump_size();
    call_size           = hook_call_size();
    fixup               = read_jump_target(callsite);
    savedsize           = (void *)(callsite + jump_size);

    // Let's verify this looks sane.
    if (fixup == NULL) {
        printf("error: tried to remove function hook from %p, but it didnt contain a redirect (%02x)\n",
               function,
               callsite[0]);
        return false;
    }

    // Check the encoded size looks sane.
    if (savedsize->opcode != X86_OPCODE_MOV_EAX_IMM
     || savedsize->prefix != X86_PREFIX_DATA16
     || savedsize->operand > MAX_REDIRECT_LENGTH) {
        printf("error: tried to remove function hook from %p, but encoded size did not validate { %02x %02x %04x }\n",
               function,
               savedsize->prefix,
               savedsize->opcode,
               savedsize->operand);
        return false;
    }

    // Restore clobbered code. Remember the fixup contains two branches, the
    // call at the start and the jmp at the end, we only want to restore the
    // clobbered data in the middle.
    if (!make_writable_range(function, savedsize->operand)) {
        return false;
    }

    memcpy(function, (uint8_t *)fixup + call_size, savedsize->operand);

    // Check it looks sane.
    if (!is_x64() && callsite[0] != X86_OPCODE_PUSH_EBP) {
        printf("warning: restored location %p does not look like a function %02x.\n",
               function,
               callsite[0]);
    }

    printf("info: successfully removed redirect from %p, via fixup@%p\n",
           function,
           fixup);

    // Release memory.
    fixup_size = savedsize->operand + call_size + jump_size;
    fixup_alloc = page_align(fixup_size);
    munmap(fixup, fixup_alloc);

    return true;
}

// Replace a call within an arbitrary function. Call as many times as you need
// on the same function. To reverse the operation, simply call again but switch
// the target and redirect parameters.
//
//  function    The function that contains the call you want to intercept.
//  target      The function that is called by @function that you want to intercept.
//  redirect    What to call instead.
//
//  For example, if tcp_input contains a call to inet_cksum, and you want to
//  intercept that call, but not every call to inet_cksum, you can do this:
//
//      redirect_call_within_function(tcp_input, inet_cksum, my_cksum_replacement);
//
bool redirect_call_within_function(void *function, void *target, void *redirect)
{
    size_t          offset      = 0;
    uint8_t        *callsite    = NULL;
    size_t          call_size   = 0;
    uint64_t        found_target = 0;

    while (true) {
        const uint8_t  *cursor  = (const uint8_t *)function + offset;
        size_t          size    = MAX_FUNCTION_LENGTH - offset;
        uint64_t        address = (uintptr_t)cursor;
        ssize_t         insnlength;

        if (cs_disasm_iter(cs_handle, &cursor, &size, &address, cs_insn_cache)) {
            insnlength = (ssize_t)cs_insn_cache->size;

            // Examine the instuction found to see if it matches the call we
            // want to replace.
            if (is_call_insn(cs_insn_cache) && resolve_call_target(cs_insn_cache, &found_target)) {
                if ((uintptr_t)found_target == (uintptr_t)target) {
                    // Success, this is the location the caller wants us to patch.
                    callsite = (uint8_t *)(function + offset);
                    call_size = (size_t)cs_insn_cache->size;

                    // Let's move on to patching.
                    printf("info: found a call at %p, the target is %#lx\n",
                           callsite, (unsigned long)found_target);

                    break;
                }

                // Not the call we want, continue scanning.
            }

            // Valid, but not interesting. Increment size.
            offset += insnlength;

            // Next instuction.
            continue;
        }

        // Invalid instruction, abort.
        printf("error: %s encountered an invalid instruction or end of stream @%p+%zu, so redirection was aborted\n",
               __func__,
               function,
               offset);

        return false;
    }

    if (callsite == NULL) {
        return false;
    }

    if (call_size != 5) {
        printf("error: unsupported call instruction size %zu at %p\n", call_size, callsite);
        return false;
    }

    if (!make_writable_range(callsite, call_size)) {
        return false;
    }

    {
        int64_t rel = (int64_t)(uintptr_t)redirect - (int64_t)((uintptr_t)callsite + 5);
        int32_t rel32;

        if (!rel32_fits(rel)) {
            if (is_x64()) {
                void *stub = build_call_stub(callsite, redirect);
                if (stub == NULL) {
                    printf("error: failed to allocate near stub for callsite %p\n", callsite);
                    return false;
                }
                rel = (int64_t)(uintptr_t)stub - (int64_t)((uintptr_t)callsite + 5);
            }
        }

        if (!rel32_fits(rel)) {
            printf("error: redirect target %p is out of range for callsite %p\n", redirect, callsite);
            return false;
        }

        rel32 = (int32_t)rel;
        callsite[0] = X86_OPCODE_CALL_NEAR;
        memcpy(callsite + 1, &rel32, sizeof(rel32));
    }

    printf("info: successfully redirected call to %p at %p+%zx with a call to %p\n",
           target,
           function,
           offset,
           redirect);

    // Complete.
    return true;
}
