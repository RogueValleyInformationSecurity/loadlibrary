#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/shm.h>

#include "afl_coverage.h"
#include "log.h"

#define AFL_DEFAULT_MAP_SIZE (1U << 16)

static unsigned char afl_dummy[AFL_DEFAULT_MAP_SIZE];
static unsigned char *afl_area_ptr;
static unsigned char *afl_local_area;
static uint32_t afl_map_size = AFL_DEFAULT_MAP_SIZE;
static uint32_t afl_map_mask = AFL_DEFAULT_MAP_SIZE - 1;
static __thread uint32_t afl_prev_loc;

static bool afl_is_power_of_two(uint32_t value) __attribute__((no_instrument_function));
static uint32_t afl_hash(uintptr_t pc) __attribute__((no_instrument_function));
static uint32_t afl_parse_map_size(void) __attribute__((no_instrument_function));
static void afl_coverage_init(void) __attribute__((constructor, no_instrument_function));

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
    int shm_id;
    void *map;

    afl_map_size = afl_parse_map_size();
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

    l_debug("AFL coverage map initialized with size %u", afl_map_size);
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
}
