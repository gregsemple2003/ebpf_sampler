// self_profiler.bpf.c (Using BPF filter with target_pid)

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "include/self_profiler_shared.h"

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
    __uint(max_entries, 1 << 24);   // 16 MiB
} events SEC(".maps");
// END CHANGED CODE
// ─────────────────────────────────────────────────────────────

SEC("perf_event")
int do_stack_sample(struct bpf_perf_event_data* ctx)
{
    unsigned long sp = PT_REGS_SP(&ctx->regs);
    unsigned long bp = PT_REGS_FP(&ctx->regs);

    // BEGIN CHANGED CODE  ───────────── reserve first, then fill ───────────
    struct stack_sample_event* ev =
        bpf_ringbuf_reserve(&events,
            sizeof(*ev) + kMaxSnapshotBytes, 0);
    if (!ev)
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    ev->tgid = id >> 32;
    ev->pid = (__u32)id;
    ev->time_ns = bpf_ktime_get_ns();
    ev->regs = (struct regs_x86_64){
                      .rip = PT_REGS_IP(&ctx->regs),
                      .rsp = sp,
                      .rbp = bp,
                      .rbx = BPF_CORE_READ(&ctx->regs, bx),
                      .r12 = BPF_CORE_READ(&ctx->regs, r12),
                      .r13 = BPF_CORE_READ(&ctx->regs, r13),
                      .r14 = BPF_CORE_READ(&ctx->regs, r14),
                      .r15 = BPF_CORE_READ(&ctx->regs, r15),
    };
    ev->flags = 0;

    /* decide how many bytes of user stack to copy */
    __u32 bytes = kMaxSnapshotBytes;
    unsigned long bytes_to_page = 0x1000 - (sp & 0xFFF);
    if (bytes_to_page < bytes)
        bytes = bytes_to_page;

    ev->stack_size = bytes;

    if (bpf_probe_read_user(ev->stack, bytes, (void*)sp))
        ev->flags |= STACK_TRUNCATED;

    bpf_ringbuf_submit(ev, 0);
    return 0;
}


char LICENSE[] SEC("license") = "Dual BSD/GPL";