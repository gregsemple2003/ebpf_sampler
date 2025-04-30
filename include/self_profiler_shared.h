#pragma once

// BEGIN CHANGED CODE  ////////////////////////////////////////////////////////
// All external includes are gone.  We provide the four fixed-width aliases
// ourselves so the header works in both eBPF and user-space builds without
// glibc *or* kernel UAPI headers.

#if !defined(__SELF_PROFILER_U_TYPES)
#define __SELF_PROFILER_U_TYPES

/*  When cross-compiling for eBPF, Clang defines __TARGET_ARCH_<arch>.
    That's enough to decide we're in kernel/BPF land.                 */
#if defined(__TARGET_ARCH_X86)    || \
    defined(__TARGET_ARCH_ARM64)  || \
    defined(__TARGET_ARCH_ARM)    || \
    defined(__TARGET_ARCH_RISCV)  || \
    defined(__BPF__)

/*  Minimal kernel-style typedefs – no headers required.  */
typedef unsigned char         __u8;
typedef unsigned short        __u16;
typedef unsigned int          __u32;
typedef unsigned long long    __u64;

#else   /* -------- normal user-space build ---------- */

#  include <linux/types.h>       /* brings in __u8/__u16/__u32/__u64 */

#endif  /* build context */

#endif  /* __SELF_PROFILER_U_TYPES */
// END   CHANGED CODE  ////////////////////////////////////////////////////////

enum {                         /* bit-flags carried in |flags|      */
    STACK_TRUNCATED   = 1 << 0,/* not all bytes copied              */
};

enum { kMaxSnapshotBytes = 16 * 1024 };  /* ring-buffer upper bound */

struct regs_x86_64            /* enough for libunwind on x86-64    */
{
    __u64 rip, rsp, rbp;
    __u64 rbx, r12, r13, r14, r15;
};

struct stack_sample_event
{
    __u64 tgid;               /* process (namespace) id             */
    __u64 pid;                /* thread  id                         */
    __u64 time_ns;            /* bpf_ktime_get_ns()                 */
    struct regs_x86_64 regs;  /* start regs for DWARF unwinder      */
    __u32  stack_size;        /* bytes actually copied              */
    __u32  flags;             /* STACK_*                            */
    __u8   stack[];           /* flexible array — raw user bytes    */
} __attribute__((packed, aligned(8))); 