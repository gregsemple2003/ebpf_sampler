// self_profiler.bpf.c (Using BPF filter with target_pid)

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ------------------------------------------------------------------
// BEGIN CHANGED CODE
//
// 1.  Helpers ───────────────────────────────────────────────────────
#ifndef PT_REGS_FP          /* new kernels spell it FP, older BP   */
# define PT_REGS_FP PT_REGS_BP
#endif

// ─────────────────────────────────────────────────────────────
// BEGIN CHANGED CODE – single ring-buffer map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);          /* 8 MiB ring */
} events SEC(".maps");
// END CHANGED CODE
// ─────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────
/* BEGIN CHANGED CODE – new event struct  */
struct stack_sample_event {
    u64 tgid;
    u64 pid;
    u64 time_ns;
    u64 sp_remote;      /* stack-pointer at sample time          */
    u64 bp_remote;      /* NEW: frame-pointer (RBP) at sample    */
    u32 stack_size;    /* real bytes copied, ≤ 8192               */
    u32 flags;         /* bit 0 = 1 → stack truncated              */
    char stack[8192];  /* raw bytes – 2 × bpf_copy_from_user()     */
};
/* END CHANGED CODE */
// ─────────────────────────────────────────────────────────────

SEC("perf_event")
int do_stack_sample(struct bpf_perf_event_data *ctx)
{
    u64 id = bpf_get_current_pid_tgid();
    u32 pid = id;
    u32 tgid = id >> 32;

    struct stack_sample_event *ev;
    ev = bpf_ringbuf_reserve(&events, sizeof(*ev), 0);
    if (!ev)
        return 0;

    ev->tgid     = tgid;
    ev->pid      = pid;
    ev->time_ns  = bpf_ktime_get_ns();
    ev->flags    = 0;
    ev->stack_size = 0;

    unsigned long sp = PT_REGS_SP(&ctx->regs);
    unsigned long bp = PT_REGS_FP(&ctx->regs);   // x86-64 RBP

    ev->sp_remote = sp;
    ev->bp_remote = bp;          // NEW

    // ─────────────────────────────────────────────────────────────
    // BEGIN CHANGED CODE – count bytes correctly

    /* first 4 KiB */
    int ret = bpf_probe_read_user(ev->stack,
                                  4096,
                                  (const void *)sp);
    if (ret) {                     /* ret < 0 means EFAULT, etc. */
        bpf_ringbuf_discard(ev, 0);
        return 0;
    }
    ev->stack_size = 4096;

    /* second 4 KiB */
    ret = bpf_probe_read_user(ev->stack + 4096,
                              4096,
                              (const void *)(sp + 4096));
    if (ret)                     /* copy failed → truncated flag */
        ev->flags |= 1;
    else
        ev->stack_size += 4096;

    // END CHANGED CODE
    // ─────────────────────────────────────────────────────────────

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";