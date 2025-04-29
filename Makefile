# Compiler settings
# Use g++ for linking C and C++ code together
LD := g++
CXX := g++
# Main file self_profiler.c includes C++ headers (iostream, vector, etc) and uses C++ features (std::thread)
CC := g++  # Use g++ for self_profiler.c
CLANG := clang # Use clang for BPF compilation
BPFTOOL := bpftool

# Build flags
APP_NAME := c_poc_self_profile
ARCH := $(shell uname -m | sed 's/x86_64/x86/')

# Include paths
LIBBPF_INCLUDE := /usr/include

# Flags
# Add -I. for local headers (like workload.hpp, *.skel.h)
# Add -pthread for std::thread
# Add debug flags (-g) and optimization flags (-O2) as needed
# Keep frame pointers for potential debugging/profiling (-fno-omit-frame-pointer)
COMMON_FLAGS := -Wall -Wextra -O2 -I. -g
CXXFLAGS := -std=c++17 $(COMMON_FLAGS) -pthread -O0 -fno-omit-frame-pointer -fno-optimize-sibling-calls
# Ensure main file compiled with g++ uses C++ flags
CFLAGS_FOR_MAIN := $(CXXFLAGS)
# BPF flags
CLANG_BPF_FLAGS := -g -O2 -target bpf -Wall -Werror
# Linker flags
LDFLAGS := -pthread -lelf -lz -lbpf # Ensure -pthread is also used for linking if needed by libraries

# Source files
C_SRC := self_profiler.c            # Main file (compiled as C++)
CXX_SRC := workload.cpp stack_unwinder.cpp # Other C++ sources
BPF_C_SRC := self_profiler.bpf.c      # BPF file (matches main file name)

# Object files derived from sources
C_OBJ := $(patsubst %.c,%.o,$(C_SRC))             # self_profiler.o
CXX_OBJ := $(patsubst %.cpp,%.o,$(CXX_SRC))       # workload.o stack_unwinder.o
BPF_OBJ := $(patsubst %.bpf.c,%.bpf.o,$(BPF_C_SRC)) # self_profiler.bpf.o

# Generated Headers
BPF_SKEL := $(patsubst %.bpf.c,%.skel.h,$(BPF_C_SRC)) # self_profiler.skel.h
CORE_HEADER := vmlinux.h

# Main target
all: $(APP_NAME)

# --- Generate vmlinux.h (CO-RE Header) ---
.PHONY: generate_core_header
generate_core_header: $(CORE_HEADER)

$(CORE_HEADER):
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
		echo "Error: /sys/kernel/btf/vmlinux not found. Ensure kernel was built with CONFIG_DEBUG_INFO_BTF=y"; exit 1; \
	fi
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "Generated $(CORE_HEADER)"

# --- Generate BPF Skeleton Header ---
# Depends on the BPF object file
$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@
	@echo "Generated BPF skeleton header: $@"

# --- Link the final application ---
# Depends on all necessary object files
$(APP_NAME): $(C_OBJ) $(CXX_OBJ)
	$(LD) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) # Use $^ to get all prerequisites (C_OBJ and CXX_OBJ)
	@echo "Linked executable: $@"

# --- Compile BPF code ---
# Depends on the BPF C source and the CO-RE header
$(BPF_OBJ): $(BPF_C_SRC) $(CORE_HEADER)
	$(CLANG) $(CLANG_BPF_FLAGS) -c $< -o $@
	@echo "Compiled BPF object: $@"

# --- Compile "C" main file (using g++) ---
# Depends on its source, the generated skeleton, CO-RE header, and any C++ headers it includes
$(C_OBJ): $(C_SRC) workload.hpp stack_unwinder.hpp $(BPF_SKEL) $(CORE_HEADER)
	$(CC) $(CFLAGS_FOR_MAIN) -c $< -o $@
	@echo "Compiled main source (as C++): $@"

# --- Compile C++ source files ---
# Use a pattern rule to compile any .cpp file into a .o file
# This rule correctly handles workload.cpp -> workload.o and stack_unwinder.cpp -> stack_unwinder.o
%.o: %.cpp workload.hpp # Add specific header dependencies if needed
	$(CXX) $(CXXFLAGS) -c $< -o $@
	@echo "Compiled C++ source: $<"

# Specify dependencies for stack_unwinder.o if different/more specific than workload.o
stack_unwinder.o: stack_unwinder.cpp stack_unwinder.hpp
# The pattern rule above will handle the compilation command

# --- Clean target ---
clean:
	rm -f $(APP_NAME) $(C_OBJ) $(CXX_OBJ) $(BPF_OBJ) $(BPF_SKEL) $(CORE_HEADER) core.* *~
	@echo "Cleaned build files."

.PHONY: all clean generate_core_header