CFLAGS	= -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar
CFLAGS += -MMD -MP -fstack-protector-strong
CPPFLAGS= -DNDEBUG
LDFLAGS	= $(CFLAGS) -m32

-include *.d

all: hook.o
	make -C libdisasm all
	cp libdisasm/libdisasm.a .

clean:
	rm -f *.o *.d *.a
	make -C libdisasm clean
