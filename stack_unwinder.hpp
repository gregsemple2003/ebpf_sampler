// stack_unwinder.hpp
#ifndef STACK_UNWINDER_HPP
#define STACK_UNWINDER_HPP

#include <vector>
#include <cstdint>

// Performs stack unwinding based on raw stack data.
// For now, this is a placeholder demonstrating RBP/frame pointer unwinding.
// Future implementation should use DWARF information.
//
// Args:
//   stack_data: Pointer to the raw stack memory captured by BPF.
//   stack_size: The number of valid bytes in stack_data.
//   initial_rbp: The value of the RBP register at the time of the sample.
//                NOTE: This is currently HARDCODED as we don't get registers yet.
//   initial_rip: The value of the RIP register at the time of the sample.
//                NOTE: This is currently HARDCODED.
//
// Returns:
//   A vector of instruction pointer addresses representing the call stack.
//   The first element is the instruction pointer at the time of the sample.
std::vector<uint64_t> unwind_stack_frame_pointers(
    const unsigned char* stack_data,
    uint32_t stack_size,
    uint64_t initial_rbp, // PROBLEM: We don't get registers easily with perf_buffer
    uint64_t initial_rip  // PROBLEM: We don't get registers easily with perf_buffer
);


#endif // STACK_UNWINDER_HPP