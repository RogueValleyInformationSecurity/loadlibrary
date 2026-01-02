#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "afl_coverage.h"

#define LL_NOINSTR __attribute__((no_instrument_function))

#define LL_DEFAULT_MAP_SIZE (1u << 16)
#define LL_MAX_IMAGES 128

#define LL_ENV_COVERAGE_ENABLE "LL_AFL_COVERAGE"
#define LL_ENV_FIXED_BASE "LL_PE_FIXED_BASE"
#define LL_ENV_ALLOW_MAP_FIXED "LL_AFL_ALLOW_MAP_FIXED"

__attribute__((weak)) unsigned char *__afl_area_ptr;
__attribute__((weak)) unsigned int __afl_map_size;

struct ll_range {
    uintptr_t start;
    uintptr_t end;
};

static struct ll_range ll_ranges[LL_MAX_IMAGES];
static size_t ll_range_count;

static unsigned char ll_local_map[LL_DEFAULT_MAP_SIZE];
static unsigned char *ll_area_ptr;
static uint32_t ll_map_size;
static uint32_t ll_map_mask;
static __thread uintptr_t ll_prev_loc;

static bool ll_enabled;
static bool ll_initialized;
static bool ll_map_initialized;

static LL_NOINSTR bool ll_is_power_of_two(uint32_t value)
{
    return value && ((value & (value - 1)) == 0);
}

static LL_NOINSTR uint32_t ll_hash_pc(uintptr_t pc)
{
    pc >>= 4;
    pc ^= pc << 8;
    pc ^= pc >> 4;
    return (uint32_t)pc;
}

static LL_NOINSTR void ll_init_map(void)
{
    if (ll_map_initialized) {
        return;
    }

    ll_map_initialized = true;
    if (__afl_area_ptr != NULL) {
        ll_area_ptr = __afl_area_ptr;
        ll_map_size = (__afl_map_size != 0 && ll_is_power_of_two(__afl_map_size))
                          ? __afl_map_size
                          : LL_DEFAULT_MAP_SIZE;
    } else {
        ll_area_ptr = ll_local_map;
        ll_map_size = LL_DEFAULT_MAP_SIZE;
    }

    ll_map_mask = ll_map_size - 1;
}

static LL_NOINSTR bool ll_addr_in_range(uintptr_t addr)
{
    for (size_t i = 0; i < ll_range_count; ++i) {
        if (addr >= ll_ranges[i].start && addr < ll_ranges[i].end) {
            return true;
        }
    }
    return false;
}

LL_NOINSTR bool afl_coverage_active(void)
{
    if (ll_initialized) {
        return ll_enabled;
    }

    ll_initialized = true;
    ll_enabled = false;

    const char *env = getenv(LL_ENV_COVERAGE_ENABLE);
    if (env != NULL) {
        if (env[0] != '\0' && env[0] != '0') {
            ll_enabled = true;
        } else {
            ll_enabled = false;
            return ll_enabled;
        }
    }

    if (__afl_area_ptr != NULL) {
        ll_enabled = true;
    }

    return ll_enabled;
}

LL_NOINSTR bool afl_coverage_get_fixed_base(uintptr_t preferred_base, uintptr_t *base_out)
{
    const char *env = getenv(LL_ENV_FIXED_BASE);
    if (env != NULL && env[0] != '\0') {
        char *endptr = NULL;
        unsigned long long parsed = strtoull(env, &endptr, 0);
        if (endptr != env && *endptr == '\0' && parsed != 0) {
            *base_out = (uintptr_t)parsed;
            return true;
        }
    }

    if (afl_coverage_active()) {
        *base_out = preferred_base;
        return true;
    }

    return false;
}

LL_NOINSTR int afl_coverage_map_fixed_flag(void)
{
#ifdef MAP_FIXED_NOREPLACE
    return MAP_FIXED_NOREPLACE;
#else
    const char *env = getenv(LL_ENV_ALLOW_MAP_FIXED);
    if (env != NULL && env[0] != '\0' && env[0] != '0') {
        return MAP_FIXED;
    }
    return 0;
#endif
}

LL_NOINSTR void afl_coverage_register_image(void *base, size_t size)
{
    if (!afl_coverage_active()) {
        return;
    }

    ll_init_map();

    if (ll_range_count >= LL_MAX_IMAGES) {
        return;
    }

    uintptr_t start = (uintptr_t)base;
    uintptr_t end = start + size;
    if (start == 0 || end <= start) {
        return;
    }

    ll_ranges[ll_range_count].start = start;
    ll_ranges[ll_range_count].end = end;
    ll_range_count++;
}

LL_NOINSTR void afl_coverage_reset(void)
{
    if (!afl_coverage_active()) {
        return;
    }

    ll_init_map();
    if (ll_area_ptr == ll_local_map) {
        memset(ll_local_map, 0, ll_map_size);
    }
    ll_prev_loc = 0;
}

LL_NOINSTR size_t afl_coverage_count(void)
{
    if (!afl_coverage_active()) {
        return 0;
    }

    ll_init_map();

    size_t count = 0;
    for (uint32_t i = 0; i < ll_map_size; ++i) {
        if (ll_area_ptr[i] != 0) {
            count++;
        }
    }
    return count;
}

LL_NOINSTR uint64_t afl_coverage_hash(void)
{
    if (!afl_coverage_active()) {
        return 0;
    }

    ll_init_map();

    uint64_t hash = 1469598103934665603ull;
    for (uint32_t i = 0; i < ll_map_size; ++i) {
        hash ^= ll_area_ptr[i];
        hash *= 1099511628211ull;
    }
    return hash;
}

LL_NOINSTR void __cyg_profile_func_enter(void *this_fn, void *call_site)
{
    (void)this_fn;

    if (!ll_enabled || ll_range_count == 0) {
        return;
    }

    uintptr_t addr = (uintptr_t)call_site;
    if (!ll_addr_in_range(addr)) {
        return;
    }

    uint32_t cur_loc = ll_hash_pc(addr);
    uint32_t idx = (cur_loc ^ (uint32_t)ll_prev_loc) & ll_map_mask;
    ll_area_ptr[idx]++;
    ll_prev_loc = cur_loc >> 1;
}

LL_NOINSTR void __cyg_profile_func_exit(void *this_fn, void *call_site)
{
    (void)this_fn;
    (void)call_site;
}
