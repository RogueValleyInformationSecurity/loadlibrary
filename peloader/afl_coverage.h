#ifndef AFL_COVERAGE_H
#define AFL_COVERAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool afl_coverage_active(void);
bool afl_coverage_get_fixed_base(uintptr_t preferred_base, uintptr_t *base_out);
int afl_coverage_map_fixed_flag(void);

void afl_coverage_register_image(void *base, size_t size);
void afl_coverage_reset(void);
size_t afl_coverage_count(void);
uint64_t afl_coverage_hash(void);

#endif
