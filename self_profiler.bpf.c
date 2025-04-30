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

// ------------------------------------------------------------------
// BEGIN CHANGED CODE
//
// 1.  Helpers ───────────────────────────────────────────────────────
#ifndef PT_REGS_FP          /* new kernels spell it FP, older BP   */
# define PT_REGS_FP PT_REGS_BP
#endif

#define MAX_STACK_SNAPSHOT 8192
#define CHUNK 256
#define MAX_CHUNKS   (MAX_STACK_SNAPSHOT / CHUNK)

// helpers + struct -------------------------------------------------
struct stack_snapshot_event {
    __u32 pid;
    __u32 tid;
    __u32 size;        /* bytes actually copied                    */
    __s32 err;         /* bpf_probe_read_user() return value       */
    __u64 rsp;
    __u64 rbp;
    __u8  truncated;
    __u8  _pad[7];     /* keep 8-byte alignment, header = 40 B     */
    __u8  data[MAX_STACK_SNAPSHOT];
};

/* Per-CPU scratch slot big enough for one snapshot.
 * We fill it, then dump through perf_event_output. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stack_snapshot_event);
} tmp_snapshot SEC(".maps");
// END CHANGED CODE

// Map to send events to user space
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
int do_stack_sample(struct bpf_perf_event_data *ctx)
{
    __u32 zero = 0;
    struct stack_snapshot_event *ev = bpf_map_lookup_elem(&tmp_snapshot, &zero);
    if (!ev)                      /* should never happen            */
        return 0;

    /* fill header -------------------------------------------------- */
    __u64 id  = bpf_get_current_pid_tgid();
    __u32 tid = id;
    __u32 tgid = id >> 32;

    ev->pid = tgid;
    ev->tid = tid;
    ev->rsp = PT_REGS_SP(&ctx->regs);   /* need address, not value   */
    ev->rbp = PT_REGS_FP(&ctx->regs);
    ev->truncated = 0;

    ev->err  = 0;        /* clear stale values from previous use */
    ev->size = 0;

    /* DEBUG ─ print the user-mode RSP/RBP we'll try to copy from */
    bpf_printk("sample: rsp=%llx rbp=%llx\n", ev->rsp, ev->rbp);

    /* copy loop ----------------------------------------------------- */
    __u32 copied = 0;

#pragma unroll
    for (int i = 0; i < MAX_CHUNKS; i++) {
        if (copied > MAX_STACK_SNAPSHOT - CHUNK)
            break;

        int ret = bpf_probe_read_user(ev->data + copied,
                                      CHUNK,
                                      (void *)(ev->rsp + copied));
        if (ret) {
            ev->truncated = 1;
            if (copied == 0)
                ev->err = ret;
            break;
        }
        copied += CHUNK;
    }

    ev->size = copied;

    /* ship it out -------------------------------------------------- */
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                          ev, sizeof(*ev));
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";