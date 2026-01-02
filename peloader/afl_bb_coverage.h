#ifndef AFL_BB_COVERAGE_H
#define AFL_BB_COVERAGE_H

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"

void afl_bb_coverage_instrument(struct pe_image *pe);

#endif
