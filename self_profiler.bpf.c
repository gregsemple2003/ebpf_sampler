// self_profiler.bpf.c (Using per-cpu map for large buffers)

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// --- Target PID global variable ---
volatile __u32 target_pidns_inum = 0;
volatile __u32 target_tgid_host = 0;

// Max stack data size to capture (Bytes)
#define MAX_STACK_BUF_SIZE 8192 // 8 KB

// Event structure sent to user space
// Contains metadata and the raw stack data.
struct stack_event {
    // Metadata
    u32 pid; // TGID
    u32 tid; // PID
    u32 stack_size; // Actual size of stack data captured
    u8 truncated;  // Flag: 1 if stack was truncated, 0 otherwise
    u8 __padding[3]; // Explicit padding for alignment (optional but good practice)

    // Raw stack data (variable length, up to MAX_STACK_BUF_SIZE)
    // Ensure this is aligned, BPF might require 8-byte alignment for map values
    unsigned char stack_data[MAX_STACK_BUF_SIZE] __attribute__((aligned(8)));
};

// --- BPF Maps ---

// Map to send events to user space (perf ring buffer)
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32)); // Value size is ignored
} events SEC(".maps");

// Per-CPU map to hold the large stack_event buffer needed for processing
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));             // Key is just 0
    __uint(value_size, sizeof(struct stack_event)); // Value is our large event struct
    __uint(max_entries, 1);                   // Only need one entry (index 0)
} event_scratch_map SEC(".maps");


SEC("perf_event")
int do_stack_sample(struct bpf_perf_event_data* ctx) {
    // --- Get task and basic info ---
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    u64 id = bpf_get_current_pid_tgid();
    u32 tgid = id >> 32;
    u32 tid = (u32)id;
    __u32 curr_inum = 0;

    // --- PID Namespace Filtering ---
    curr_inum = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
    if (curr_inum != target_pidns_inum) {
        // Optional: Keep logging for rejected samples if needed for debugging
        // char comm[16] = {};
        // bpf_get_current_comm(comm, sizeof(comm));
        // bpf_printk("rejected sample (wrong ns), curr=%u, target=%u, comm=%s\n", curr_inum, target_pidns_inum, comm);
        return 0;
    }

    // Optional: Host TGID check
    //if (tgid != target_tgid_host) { ... return 0; }

    bpf_printk("accepted sample: tgid=%u tid=%u\n", tgid, tid);

    // --- Get pointer to per-CPU buffer from map ---
    u32 zero = 0; // Key for the per-cpu array map
    struct stack_event* event_ptr;

    event_ptr = bpf_map_lookup_elem(&event_scratch_map, &zero);
    if (!event_ptr) {
        bpf_printk("ERROR: Failed to get per-cpu buffer\n");
        return 0; // Cannot proceed without buffer
    }

    // --- Capture Raw User Stack directly into the map buffer ---
    // No large allocation on BPF stack here!
    long stack_size_long = bpf_get_stack(ctx, event_ptr->stack_data, MAX_STACK_BUF_SIZE, BPF_F_USER_STACK);
    bpf_printk("bpf_get_stack ret=%ld\n", stack_size_long);

    if (stack_size_long <= 0) {
        bpf_printk("bpf_get_stack failed or empty stack: %ld\n", stack_size_long);
        // Note: Don't return yet, we might want to clear the buffer or handle error differently.
        // For now, just don't send an event.
        return 0;
    }

    u32 stack_size = (u32)stack_size_long;

    // --- Populate Event Metadata directly in the map buffer ---
    // No struct copy, just assign fields in the map entry.
    event_ptr->pid = tgid;
    event_ptr->tid = tid;
    event_ptr->stack_size = stack_size;
    event_ptr->truncated = (stack_size >= MAX_STACK_BUF_SIZE);
    // event_ptr->__padding can be left uninitialized

    // --- Send Event to User Space (using the map buffer) ---
    // Calculate the actual size of the data to send: metadata + valid stack data
    // Use __builtin_offsetof as before
    u32 event_size = __builtin_offsetof(struct stack_event, stack_data) + event_ptr->stack_size;

    // Safety check against the map value size
    if (event_size > sizeof(struct stack_event)) {
        bpf_printk("Warning: Calculated event_size %u exceeds sizeof(struct stack_event) %zu. Clamping.\n", event_size, sizeof(struct stack_event));
        event_size = sizeof(struct stack_event);
        // Ensure stack_size reflects reality if clamped. This shouldn't be strictly needed if
        // __builtin_offsetof is correct, but adds safety.
        event_ptr->stack_size = event_size - __builtin_offsetof(struct stack_event, stack_data);
        event_ptr->truncated = 1; // Mark as truncated if clamped
    }

    // Output the event directly from the map buffer
    int ret = bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event_ptr, event_size);
    if (ret != 0) {
        bpf_printk("bpf_perf_event_output failed: %d\n", ret);
    }

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";