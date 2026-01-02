# IrfanView Fuzzing Harness Makefile
#
# Build with AFL:
#   make CC=afl-clang-fast
#
# Build without AFL (for testing):
#   make
#
# Enable BB coverage during fuzzing:
#   export LL_AFL_BB_COVERAGE=1
#   export LL_PE_FIXED_BASE=1

# Loadlibrary paths
LOADLIB_DIR ?= ../..
PELOADER_LIB = $(LOADLIB_DIR)/peloader/libpeloader64.a
CAPSTONE_LIB = $(LOADLIB_DIR)/third_party/capstone/libcapstone64.a

# Compiler settings
CC ?= gcc
CFLAGS = -O2 -g -std=gnu99 -fshort-wchar -Wall -Wextra -Wno-unused-parameter
CFLAGS += -m64 -march=x86-64 -mtune=generic
CFLAGS += -I$(LOADLIB_DIR)/include -I$(LOADLIB_DIR)/peloader -I$(LOADLIB_DIR)
CPPFLAGS = -DNDEBUG -D_GNU_SOURCE

# Linker settings
LDFLAGS = -m64 -lm -Wl,--dynamic-list=$(LOADLIB_DIR)/exports.lst
LDLIBS = -Wl,--whole-archive,$(PELOADER_LIB),--no-whole-archive $(CAPSTONE_LIB)

# Targets
TARGET = irfanview_persistent
HARNESS_LINK = harness

.PHONY: all clean peloader test seeds

all: $(TARGET) $(HARNESS_LINK)

# Build peloader if needed
$(PELOADER_LIB):
	$(MAKE) -C $(LOADLIB_DIR) peloader64 capstone64

# Build the harness
irfanview-harness.o: irfanview-harness.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

$(TARGET): irfanview-harness.o $(PELOADER_LIB)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS) $(LDFLAGS)

# Create symlink
$(HARNESS_LINK): $(TARGET)
	ln -sf $(TARGET) $(HARNESS_LINK)

# Test harness with a sample file
test: $(TARGET)
	@echo "Testing harness with ani extension..."
	@if [ -f seeds/ani/sample.ani ]; then \
		./$(TARGET) ani seeds/ani/sample.ani; \
	else \
		echo "No seed file found. Create seeds/ani/sample.ani first."; \
	fi

# Create seed directories
seeds:
	@mkdir -p seeds/ani seeds/pcx seeds/dds seeds/psp seeds/ttf
	@mkdir -p seeds/webp seeds/jp2 seeds/mng seeds/b3d seeds/djvu
	@mkdir -p seeds/svg seeds/xcf seeds/pdf seeds/sff seeds/dcm
	@echo "Seed directories created. Add sample files to each."

# Clean build artifacts
clean:
	rm -f *.o $(TARGET) $(HARNESS_LINK)
	rm -rf output/

# Deep clean (including loadlibrary)
distclean: clean
	$(MAKE) -C $(LOADLIB_DIR) clean

# Help
help:
	@echo "IrfanView Fuzzing Harness"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build harness (default)"
	@echo "  test       - Test harness with sample file"
	@echo "  seeds      - Create seed directories"
	@echo "  clean      - Remove build artifacts"
	@echo "  distclean  - Deep clean including loadlibrary"
	@echo ""
	@echo "Building with AFL++:"
	@echo "  make CC=afl-clang-fast"
	@echo ""
	@echo "Running AFL++ with BB coverage:"
	@echo "  export LL_AFL_BB_COVERAGE=1"
	@echo "  export LL_PE_FIXED_BASE=1"
	@echo "  afl-fuzz -i seeds/ani -o output/ani -t 1000 -- ./harness ani @@"
	@echo ""
	@echo "Corpus minimization with BB coverage:"
	@echo "  export AFL_MAP_SIZE=8388608"
	@echo "  afl-cmin -i corpus -o min -t 2000 -- ./harness ani @@"
