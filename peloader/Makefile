CFLAGS  = -O3 -march=native -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar -Iinclude -mstackrealign
CFLAGS += -MMD -MP -fstack-protector-strong
CPPFLAGS=-DNDEBUG -D_GNU_SOURCE -D_FORTIFY_SOURCE=2 -I.
LDFLAGS = $(CFLAGS) -m32 -lm

.PHONY: clean

# This glob matches all the winapi exports we provide.
WINAPI  = $(patsubst %.c,%.o,$(wildcard winapi/*.c))

TARGETS=libpeloader.a

-include *.d winapi/*.d

all: $(TARGETS)

libpeloader.a: $(WINAPI) winstrings.o pe_linker.o crt.o log.o util.o extra.o
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f a.out core *.o *.d core.* vgcore.* gmon.out winapi/*.o winapi/*.d $(TARGETS)
