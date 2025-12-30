# Common flags (no -march here, set per-architecture below)
COMMON_CFLAGS = -O3 -ggdb3 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar -Iinclude
COMMON_CFLAGS += -MMD -MP -fstack-protector-strong
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -I.

# 32-bit flags (default)
# Use -march=i686 for QEMU compatibility (avoid AVX/SSE4 from -march=native)
CFLAGS  = $(COMMON_CFLAGS) -m32 -march=i686 -mtune=generic -mstackrealign
LDFLAGS = $(CFLAGS) -m32 -lm

# 64-bit flags
# Use -march=x86-64 for QEMU compatibility (baseline x86-64 without AVX)
CFLAGS64 = $(COMMON_CFLAGS) -m64 -march=x86-64 -mtune=generic
LDFLAGS64 = $(CFLAGS64) -m64 -lm

.PHONY: clean all64

# This glob matches all the winapi exports we provide.
WINAPI  = $(patsubst %.c,%.o,$(wildcard winapi/*.c))
WINAPI64 = $(patsubst %.c,%.64.o,$(wildcard winapi/*.c))

TARGETS=libpeloader.a
TARGETS64=libpeloader64.a

-include *.d winapi/*.d

all: $(TARGETS)

all64: $(TARGETS64)

# 32-bit build rules
libpeloader.a: $(WINAPI) winstrings.o pe_linker.o crt.o log.o util.o extra.o
	$(AR) $(ARFLAGS) $@ $^

# 64-bit build rules
%.64.o: %.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

libpeloader64.a: $(WINAPI64) winstrings.64.o pe_linker.64.o crt.64.o log.64.o util.64.o extra.64.o
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f a.out core *.o *.d core.* vgcore.* gmon.out winapi/*.o winapi/*.64.o winapi/*.d $(TARGETS) $(TARGETS64)
