#pragma once
#include <cstdint>
#include <vector>
#include "self_profiler_shared.h"

// BEGIN CHANGED CODE – expose a build-time toggle so you can
//   `CXXFLAGS+= -DWITH_LIBUNWIND` and link with `-lunwind`
#ifdef WITH_LIBUNWIND
#  define DWARF_UNWINDING 1
#else
#  define DWARF_UNWINDING 0
#endif
// END CHANGED CODE

// Simple helper: walk an RBP-framed stack living in |snapshot|.
bool UnwindStack(const uint8_t* snapshot,
                 uint32_t       snapshotSize,
                 const regs_x86_64& regs,
                 std::vector<uint64_t>& outFrames,
                 bool&           truncated); 