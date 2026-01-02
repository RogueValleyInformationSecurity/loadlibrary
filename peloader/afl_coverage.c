#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>
#include <stdio.h>

#include "afl_coverage.h"
#include "log.h"

#define AFL_DEFAULT_MAP_SIZE (1U << 16)

static unsigned char afl_dummy[AFL_DEFAULT_MAP_SIZE];
static unsigned char *afl_area_ptr;
static unsigned char *afl_local_area;
static uint32_t afl_map_size = AFL_DEFAULT_MAP_SIZE;
static uint32_t afl_map_mask = AFL_DEFAULT_MAP_SIZE - 1;
static __thread uint32_t afl_prev_loc;
static uint64_t afl_hit_count;
static int afl_count_enabled = -1;
static int afl_verbose_enabled = -1;

extern uint32_t __afl_final_loc __attribute__((weak));
extern uint32_t __afl_first_final_loc __attribute__((weak));
extern uint32_t __afl_map_size __attribute__((weak));

static bool afl_is_power_of_two(uint32_t value) __attribute__((no_instrument_function));
static uint32_t afl_hash(uintptr_t pc) __attribute__((no_instrument_function));
static uint32_t afl_parse_map_size(void) __attribute__((no_instrument_function));
static void afl_coverage_init(void) __attribute__((constructor, no_instrument_function));
static void afl_coverage_report(void) __attribute__((destructor, no_instrument_function));
void afl_coverage_expand_map(void) __attribute__((no_instrument_function));

static bool afl_counting_enabled(void)
{
    if (afl_count_enabled != -1) {
        return afl_count_enabled != 0;
    }

    afl_count_enabled = getenv("LL_AFL_COVERAGE_COUNT") ? 1 : 0;
    return afl_count_enabled != 0;
}

static bool afl_verbose(void)
{
    if (afl_verbose_enabled != -1) {
        return afl_verbose_enabled != 0;
    }

    afl_verbose_enabled = getenv("LL_AFL_COVERAGE_VERBOSE") ? 1 : 0;
    return afl_verbose_enabled != 0;
}

static bool afl_is_power_of_two(uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

static uint32_t afl_hash(uintptr_t pc)
{
    uint64_t x = (uint64_t)pc;

    x ^= x >> 7;
    x ^= x >> 13;
    x ^= x >> 21;

    return (uint32_t)x;
}

static uint32_t afl_parse_map_size(void)
{
    const char *env = getenv("AFL_MAP_SIZE");
    char *end = NULL;
    unsigned long value;

    if (env == NULL || env[0] == '\0') {
        return AFL_DEFAULT_MAP_SIZE;
    }

    errno = 0;
    value = strtoul(env, &end, 10);
    if (errno != 0 || end == env || value == 0 || value > UINT32_MAX) {
        return AFL_DEFAULT_MAP_SIZE;
    }

    if (!afl_is_power_of_two((uint32_t)value)) {
        return AFL_DEFAULT_MAP_SIZE;
    }

    return (uint32_t)value;
}

static void afl_coverage_init(void)
{
    const char *shm_env;
    const char *bb_env;
    int shm_id;
    void *map;
    struct shmid_ds shm_info;
    uint32_t runtime_map_size = 0;

    if (&__afl_map_size != NULL && __afl_map_size != 0) {
        afl_map_size = __afl_map_size;
    } else {
        afl_map_size = afl_parse_map_size();
    }
    afl_map_mask = afl_map_size - 1;
    afl_area_ptr = afl_dummy;

    shm_env = getenv("__AFL_SHM_ID");
    if (shm_env == NULL || shm_env[0] == '\0') {
        shm_env = getenv("AFL_SHM_ID");
    }

    if (shm_env != NULL && shm_env[0] != '\0') {
        shm_id = atoi(shm_env);
        map = shmat(shm_id, NULL, 0);
        if (map != (void *)-1) {
            afl_area_ptr = map;
            runtime_map_size = (&__afl_map_size != NULL) ? __afl_map_size : 0;
            if (runtime_map_size != 0) {
                afl_map_size = runtime_map_size;
                afl_map_mask = afl_map_size - 1;
            } else if (shmctl(shm_id, IPC_STAT, &shm_info) == 0) {
                uint64_t shm_size = shm_info.shm_segsz;
                if (shm_size > 0 && shm_size <= UINT32_MAX
                 && afl_is_power_of_two((uint32_t)shm_size)) {
                    afl_map_size = (uint32_t)shm_size;
                    afl_map_mask = afl_map_size - 1;
                }
            }
            if (afl_verbose()) {
                fprintf(stderr, "afl_coverage_init: shm=%d size=%u\n",
                        shm_id, afl_map_size);
            }
            return;
        }
    }

    if (afl_map_size != AFL_DEFAULT_MAP_SIZE) {
        afl_local_area = calloc(afl_map_size, 1);
        if (afl_local_area != NULL) {
            afl_area_ptr = afl_local_area;
        } else {
            afl_map_size = AFL_DEFAULT_MAP_SIZE;
            afl_map_mask = AFL_DEFAULT_MAP_SIZE - 1;
            afl_area_ptr = afl_dummy;
        }
    }

    if (afl_verbose()) {
        fprintf(stderr, "afl_coverage_init: shm_attach_failed, using local map size=%u\n",
                afl_map_size);
    }

    l_debug("AFL coverage map initialized with size %u", afl_map_size);

    bb_env = getenv("LL_AFL_BB_COVERAGE");
    if (bb_env != NULL && atoi(bb_env) > 0) {
        afl_coverage_expand_map();
    }
}

static void afl_coverage_report(void)
{
    if (!afl_counting_enabled()) {
        return;
    }

    fprintf(stderr, "afl_coverage_hit_pc() count: %llu\n",
            (unsigned long long)afl_hit_count);
}

void afl_coverage_hit_pc(uintptr_t pc) __attribute__((no_instrument_function));

void afl_coverage_hit_pc(uintptr_t pc)
{
    uint32_t cur;
    uint32_t idx;

    if (afl_area_ptr == NULL) {
        return;
    }

    cur = afl_hash(pc);
    idx = (cur ^ afl_prev_loc) & afl_map_mask;

    afl_area_ptr[idx]++;
    afl_prev_loc = cur >> 1;

    if (afl_counting_enabled()) {
        afl_hit_count++;
    }
}

void afl_coverage_expand_map(void)
{
    uint32_t *final_loc = &__afl_final_loc;
    uint32_t *first_final_loc = &__afl_first_final_loc;
    uint32_t *map_size_ptr = &__afl_map_size;
    uint32_t before = 0;
    uint32_t before_first = 0;
    uint32_t target;

    if (map_size_ptr && *map_size_ptr != 0) {
        afl_map_size = *map_size_ptr;
        afl_map_mask = afl_map_size - 1;
    } else if (afl_map_size == 0) {
        afl_map_size = afl_parse_map_size();
        afl_map_mask = afl_map_size - 1;
    }

    target = afl_map_size ? (afl_map_size - 1) : (AFL_DEFAULT_MAP_SIZE - 1);

    if (final_loc) {
        before = *final_loc;
        if (*final_loc < target) {
            *final_loc = target;
        }
    }
    if (first_final_loc) {
        before_first = *first_final_loc;
        if (*first_final_loc < target) {
            *first_final_loc = target;
        }
    }

    if (afl_verbose()) {
        if (final_loc) {
            fprintf(stderr,
                    "afl_coverage_expand_map: map_size %u, final_loc %u -> %u, first_final_loc %u -> %u\n",
                    map_size_ptr ? *map_size_ptr : 0,
                    before, *final_loc, before_first, first_final_loc ? *first_final_loc : 0);
        } else {
            fprintf(stderr, "afl_coverage_expand_map: __afl_final_loc unavailable\n");
        }
    }
}
