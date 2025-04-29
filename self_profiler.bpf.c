// self_profiler.bpf.c (Using BPF filter with target_pid)

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// --- Target PID global variable ---
// Value will be set by user-space via skeleton *before* loading.
volatile __u32 target_pidns_inum = 0;
volatile __u32 target_tgid_host = 0;      // host-namespace TGID

// Max stack depth to capture
#define MAX_STACK_DEPTH 127

// Map to store the stack traces
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(key_size, sizeof(u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(u64));
    __uint(max_entries, 10240);
} stack_traces SEC(".maps");

// Map to send events to user space
struct event {
    u32 stack_id;
    u32 pid; // TGID
    u32 tid; // PID
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

//static __always_inline bool same_pidns(void)
//{
//    struct task_struct* task = (struct task_struct*)bpf_get_current_task();
//    struct pid_namespace* curr = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
//    struct pid_namespace* want = (struct pid_namespace*)(u64)target_pidns;
//    return curr == want;
//}

SEC("perf_event")
int do_stack_sample(struct bpf_perf_event_data* ctx) {
    struct task_struct* task = (struct task_struct*)bpf_get_current_task();

    __u32 curr_inum = BPF_CORE_READ(task,
        nsproxy,
        pid_ns_for_children,
        ns.inum);

    /* reject: wrong namespace */
    if (curr_inum != target_pidns_inum)
    {
        char comm[16] = {};
        bpf_get_current_comm(comm, sizeof(comm));
        bpf_printk("rejected sample, curr_inum=%d, target_pidns_inum=%d, comm=%s\n", curr_inum, target_pidns_inum, comm);
        return 0;
    }

    ///* reject: wrong TGID even inside that namespace */
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    //if (tgid != target_tgid_host)
    //{
    //    char comm[16] = {};
    //    bpf_get_current_comm(comm, sizeof(comm));
    //    bpf_printk("rejected sample, tgid=%d, target_tgid_host=%d, comm=%s\n", tgid, target_tgid_host, comm);
    //    return 0;
    //}

    // TODO gsemple: remove this, unreliable and weird
    u64 id = bpf_get_current_pid_tgid();
    u32 tid = (u32)id;

    //struct task_struct* task = (struct task_struct*)bpf_get_current_task();
    //u64 pid_ns_ptr = (u64)BPF_CORE_READ(task, nsproxy, pid_ns_for_children);

    ///* first printk: TGID, TID, pid-namespace pointer  → 3 args */
    //bpf_printk("hit: tg=%u ti=%u ns=%llx\n", tgid, tid, pid_ns_ptr);

    /* second printk: task name  → 1 arg */
    //bpf_printk("comm=%s\n", comm);

    bpf_printk("accepted sample\n");

    // If we get here, the TGID matches the target
    s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    bpf_printk("stackid ret=%d, err=%d\n", stack_id, stack_id);
    if (stack_id < 0) {
        return 0;
    }

    struct event event_data = {};
    event_data.stack_id = (u32)stack_id;
    event_data.pid = tgid;
    event_data.tid = tid;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event_data, sizeof(event_data));

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";