#ifndef AFL_COVERAGE_H
#define AFL_COVERAGE_H

#include <stdint.h>

void afl_coverage_hit_pc(uintptr_t pc) __attribute__((no_instrument_function));

#endif
