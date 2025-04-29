# Compiler settings
# Use g++ for linking C and C++ code together
LD := g++
CXX := g++
# CC := gcc # Use gcc for the main C file now <-- NO, main uses C++ features
CC := g++  # *** USE g++ for main file now ***
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
CXXFLAGS := -std=c++17 $(COMMON_FLAGS) -pthread -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls
# CFLAGS := $(COMMON_FLAGS) -pthread # C flags also need includes and pthread if using atomics/threads directly <-- USE CXXFLAGS FOR MAIN FILE
CFLAGS_FOR_MAIN := $(CXXFLAGS) # Use C++ flags for the main file since it's compiled with g++
CLANG_BPF_FLAGS := -g -O2 -target bpf -Wall -Werror
# Linker flags
LDFLAGS := -lelf -lz -lbpf

# Source files
C_SRC := self_profiler.c   # Main file (compiled as C++)
CXX_SRC := workload.cpp    # Workload is C++
BPF_C_SRC := self_profiler.bpf.c # BPF file (matches main file name)

# Object files
C_OBJ := $(patsubst %.c,%.o,$(C_SRC))
CXX_OBJ := $(patsubst %.cpp,%.o,$(CXX_SRC))
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
$(APP_NAME): $(C_OBJ) $(CXX_OBJ) | $(BPF_OBJ) $(BPF_SKEL)
	$(LD) $(CXXFLAGS) $(C_OBJ) $(CXX_OBJ) -o $@ $(LDFLAGS)
	@echo "Linked executable: $@"

# --- Compile BPF code ---
$(BPF_OBJ): $(BPF_C_SRC) vmlinux.h
	$(CLANG) $(CLANG_BPF_FLAGS) -c $< -o $@
	@echo "Compiled BPF object: $@"

# --- Compile "C" main file (using g++) ---
# Depends on the generated skeleton header AND the C source file
$(C_OBJ): $(C_SRC) workload.hpp $(BPF_SKEL) vmlinux.h
	$(CC) $(CFLAGS_FOR_MAIN) -c $< -o $@ # Use g++ and C++ flags

# --- Compile C++ workload file ---
$(CXX_OBJ): $(CXX_SRC) workload.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# --- Clean target ---
clean:
	rm -f $(APP_NAME) $(C_OBJ) $(CXX_OBJ) $(BPF_OBJ) $(BPF_SKEL) vmlinux.h core.* *~
	@echo "Cleaned build files."

.PHONY: all clean generate_headers