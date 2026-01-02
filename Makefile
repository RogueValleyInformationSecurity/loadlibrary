# Common flags (no -march here, set per-architecture below)
COMMON_CFLAGS = -O3 -ggdb3 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar -Iinclude
COMMON_CFLAGS += -MMD -MP -fstack-protector-strong
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -I. -Iintercept -Ipeloader

# 32-bit flags (default)
# Use -march=i686 for QEMU compatibility (avoid AVX/SSE4 from -march=native)
CFLAGS  = $(COMMON_CFLAGS) -m32 -march=i686 -mtune=generic -mstackrealign
LDFLAGS = $(CFLAGS) -m32 -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = intercept/libdisasm.a -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive

# 64-bit flags
# Use -march=x86-64 for QEMU compatibility (baseline x86-64 without AVX)
CFLAGS64  = $(COMMON_CFLAGS) -m64 -march=x86-64 -mtune=generic
LDFLAGS64 = $(CFLAGS64) -m64 -lm -Wl,--dynamic-list=exports.lst
LDLIBS64  = -Wl,--whole-archive,peloader/libpeloader64.a,--no-whole-archive

.PHONY: clean peloader peloader64 intercept test64 harness32 harness64 afl_cov afl_cov64 examples afl_persistent afl_persistent64 test_ordinal test_ordinal64

TARGETS=mpclient | peloader

-include *.d

all: $(TARGETS)
	-mkdir -p faketemp

intercept:
	make -C intercept all

peloader:
	make -C peloader all

peloader64:
	make -C peloader all64

intercept/hook.o: intercept

mpclient: mpclient.o intercept/hook.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS) $(LDFLAGS)

# 64-bit test target (no hook support needed for basic PE loading test)
test64: test/test64_client.64.o | peloader64
	$(CC) $(CFLAGS64) $^ -o $@ $(LDLIBS64) $(LDFLAGS64)

test/test64_client.64.o: test/test64_client.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

# Example fuzzing harnesses (don't need intercept library)
LDLIBS_HARNESS = -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive
LDLIBS_HARNESS64 = -Wl,--whole-archive,peloader/libpeloader64.a,--no-whole-archive

examples: harness32 harness64

# AFL persistent mode harness
# Build with: make afl_persistent
# For best results: make CC=afl-clang-fast afl_persistent
afl_persistent: test/afl_persistent.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS_HARNESS) $(LDFLAGS)

test/afl_persistent.o: test/afl_persistent.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# 64-bit AFL persistent mode harness
afl_persistent64: test/afl_persistent64.64.o | peloader64
	$(CC) $(CFLAGS64) $^ -o $@ $(LDLIBS_HARNESS64) $(LDFLAGS64)

test/afl_persistent64.64.o: test/afl_persistent64.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

# Ordinal import tests
# test_ordinal: 32-bit test for 32-bit DLL ordinal imports
test_ordinal: test/test_ordinal_client.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS_HARNESS) $(LDFLAGS)

test/test_ordinal_client.o: test/test_ordinal_client.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

# test_ordinal64: 64-bit test for 64-bit DLL ordinal imports
test_ordinal64: test/test_ordinal_client.64.o | peloader64
	$(CC) $(CFLAGS64) $^ -o $@ $(LDLIBS_HARNESS64) $(LDFLAGS64)

test/test_ordinal_client.64.o: test/test_ordinal_client.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

harness32: examples/harness32.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS_HARNESS) $(LDFLAGS)

examples/harness32.o: examples/harness32.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

harness64: examples/harness64.64.o | peloader64
	$(CC) $(CFLAGS64) $^ -o $@ $(LDLIBS_HARNESS64) $(LDFLAGS64)

examples/harness64.64.o: examples/harness64.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

# AFL-style PE callsite coverage harnesses
afl_cov: examples/afl_coverage_harness.o | peloader
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS_HARNESS) $(LDFLAGS)

examples/afl_coverage_harness.o: examples/afl_coverage_harness.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

afl_cov64: examples/afl_coverage_harness.64.o | peloader64
	$(CC) $(CFLAGS64) $^ -o $@ $(LDLIBS_HARNESS64) $(LDFLAGS64)

examples/afl_coverage_harness.64.o: examples/afl_coverage_harness.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f a.out core *.o *.d core.* vgcore.* gmon.out mpclient test64 harness32 harness64 afl_cov afl_cov64 afl_persistent afl_persistent64 test_ordinal test_ordinal64 test/*.o test/*.d examples/*.o
	make -C intercept clean
	make -C peloader clean
	rm -rf faketemp
