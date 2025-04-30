# Compiler settings
# Use g++ for linking C and C++ code together
LD := g++
CXX := g++
CC := g++  # Use g++ for all files now
CLANG := clang # Use clang for BPF compilation
BPFTOOL := bpftool

# Build flags
APP_NAME := c_poc_self_profile # New executable name
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Include paths
LIBBPF_INCLUDE := /usr/include

# Flags
# Add -I. for local headers (like workload.hpp, *.skel.h)
# Add -pthread for std::thread
COMMON_FLAGS := -Wall -Wextra -O2 -I.
CXXFLAGS := -std=c++17 $(COMMON_FLAGS) -pthread -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls -DWITH_LIBUNWIND
CLANG_BPF_FLAGS := -g -O2 -target bpf -Wall -Werror -D__TARGET_ARCH_x86
# Linker flags
LDFLAGS := -Wl,-Bstatic -L/usr/src/libbpf/src -lbpf -Wl,-Bdynamic -lelf -lz -pthread -lunwind -lunwind-x86_64

# Source files
CXX_SRCS := self_profiler.cpp workload.cpp dwarf_unwind.cpp   # All C++ files
BPF_C_SRC := self_profiler.bpf.c # BPF file

# Object files
CXX_OBJS := $(patsubst %.cpp,%.o,$(CXX_SRCS))
BPF_OBJ := $(patsubst %.bpf.c,%.bpf.o,$(BPF_C_SRC))

# Generated Skeleton Header
BPF_SKEL := $(patsubst %.bpf.c,%.skel.h,$(BPF_C_SRC))

# Main target
all: $(APP_NAME)

# --- Generate vmlinux.h (CO-RE Header) ---
.PHONY: generate_headers
generate_headers: vmlinux.h

vmlinux.h:
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "Error: /sys/kernel/btf/vmlinux not found."; exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "Generated vmlinux.h"

# --- Generate BPF Skeleton Header ---
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated BPF skeleton header: $@"

# --- Link the final application ---
$(APP_NAME): $(CXX_OBJS) | $(BPF_OBJ) $(BPF_SKEL)
	$(LD) $(CXXFLAGS) $(CXX_OBJS) -o $@ $(LDFLAGS)
	@echo "Linked executable: $@"

# --- Compile BPF code ---
$(BPF_OBJ): $(BPF_C_SRC) vmlinux.h
	$(CLANG) $(CLANG_BPF_FLAGS) -c $< -o $@
	@echo "Compiled BPF object: $@"

# --- Compile C++ files ---
self_profiler.o: self_profiler.cpp workload.hpp dwarf_unwind.hpp $(BPF_SKEL) vmlinux.h
	$(CXX) $(CXXFLAGS) -c $< -o $@

workload.o: workload.cpp workload.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

dwarf_unwind.o: dwarf_unwind.cpp dwarf_unwind.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- Clean target ---
clean:
	rm -f $(APP_NAME) $(CXX_OBJS) $(BPF_OBJ) $(BPF_SKEL) vmlinux.h core.* *~
	@echo "Cleaned build files."

.PHONY: all clean generate_headers