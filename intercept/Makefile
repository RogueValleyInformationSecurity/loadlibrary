CFLAGS	= -O0 -ggdb3 -m32 -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-multichar
CPPFLAGS= -DNDEBUG
LDFLAGS	= $(CFLAGS) -m32

all: hook.o
	make -C libdisasm all
	cp libdisasm/libdisasm.a .

clean:
	rm -f *.o *.a
	make -C libdisasm clean
