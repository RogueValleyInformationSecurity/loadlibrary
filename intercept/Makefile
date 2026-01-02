CAPSTONE_DIR ?= ../third_party/capstone
CFLAGS	= -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar
CFLAGS += -MMD -MP -fstack-protector-strong
CFLAGS64 = -O0 -ggdb3 -m64 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar
CFLAGS64 += -MMD -MP -fstack-protector-strong
CPPFLAGS= -DNDEBUG -DCAPSTONE_STATIC -I$(CAPSTONE_DIR)/include
LDFLAGS	= $(CFLAGS) -m32
LDFLAGS64 = $(CFLAGS64) -m64

-include *.d

all: hook.o

all64: hook.64.o

%.64.o: %.c
	$(CC) $(CFLAGS64) $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f *.o *.64.o *.d *.a
