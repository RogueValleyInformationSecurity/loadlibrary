# Common flags
COMMON_CFLAGS = -O3 -march=native -ggdb3 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar -Iinclude
COMMON_CFLAGS += -MMD -MP -fstack-protector-strong
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -I. -Iintercept -Ipeloader

# 32-bit flags (default)
CFLAGS  = $(COMMON_CFLAGS) -m32 -mstackrealign
LDFLAGS = $(CFLAGS) -m32 -lm -Wl,--dynamic-list=exports.lst
LDLIBS  = intercept/libdisasm.a -Wl,--whole-archive,peloader/libpeloader.a,--no-whole-archive

# 64-bit flags
CFLAGS64  = $(COMMON_CFLAGS) -m64
LDFLAGS64 = $(CFLAGS64) -m64 -lm -Wl,--dynamic-list=exports.lst
LDLIBS64  = -Wl,--whole-archive,peloader/libpeloader64.a,--no-whole-archive

.PHONY: clean peloader peloader64 intercept test64

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

clean:
	rm -f a.out core *.o *.d core.* vgcore.* gmon.out mpclient test64 test/*.o
	make -C intercept clean
	make -C peloader clean
	rm -rf faketemp
