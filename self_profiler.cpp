// self_profiler.cpp (Implementing skeleton variable and system-wide events with verbose error logging)

// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

// C Standard Includes
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/resource.h>
#include <stdint.h>
#include <inttypes.h>
#include <assert.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/perf_event.h>
struct pid_namespace;  // forward-declare; no header needed

// C++ Standard Includes (for workload and threading)
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <memory>

// BPF Includes
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Generated BPF Skeleton Header
#include "self_profiler.skel.h"
#include "self_profiler_shared.h"

// Workload Header
#include "workload.hpp"
#include "dwarf_unwind.hpp"

// small RAII helpers
struct FdGuard {
    int fd = -1;
    ~FdGuard() { if (fd >= 0) close(fd); }
};

using LinkPtr = std::unique_ptr<bpf_link, decltype(&bpf_link__destroy)>;
using RingPtr = std::unique_ptr<ring_buffer, decltype(&ring_buffer__free)>;
using SkelPtr = std::unique_ptr<self_profiler_bpf, decltype(&self_profiler_bpf__destroy)>;

// --- Global Variables ---
static std::atomic<bool> keep_running(true);
static volatile bool exiting = false;
static pid_t target_pid = 0;

// --- Helper: Libbpf Print Function ---
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    // Print all libbpf messages for debugging
    fprintf(stderr, "LIBBPF: ");
    return vfprintf(stderr, format, args);
}

// --- Signal Handler ---
static void sig_handler(int sig) {
    fprintf(stderr, "\nCaught signal %d, initiating shutdown...\n", sig); // Log signal
    exiting = true;
    keep_running.store(false);
}

// --- Helper: Set Rlimit ---
static int bump_memlock_rlimit() {
    struct rlimit rlim_new = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "ERROR: Failed to increase RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return -1;
    }
    printf("Successfully bumped RLIMIT_MEMLOCK.\n");
    return 0;
}

// --- Ring Buffer Callback ---
static int handle_event(void* ctx, void* data, size_t size) {
    (void)ctx;
    const stack_sample_event* e = static_cast<const stack_sample_event*>(data);
    if (size < sizeof(stack_sample_event) || size < sizeof(stack_sample_event) + e->stack_size) return 0;

    // BEGIN CHANGED CODE – print event header
    std::printf(
        "Event: tgid=%llu pid=%llu time=%llu\n",
        static_cast<unsigned long long>(e->tgid),
        static_cast<unsigned long long>(e->pid),
        static_cast<unsigned long long>(e->time_ns));
    // END CHANGED CODE

    /* ---------- time the unwinder ---------------------------------- */
    auto t0 = std::chrono::high_resolution_clock::now();

    std::vector<uint64_t> frames;
    bool truncated = e->flags & STACK_TRUNCATED;
    UnwindDwarf(e->stack, e->stack_size, e->regs, frames, truncated);

    auto t1 = std::chrono::high_resolution_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0)
                .count();

    /* ------------ print sample ------------------------------------- */
    printf("\n--- Sample --- PID:%llu TID:%llu  Frames:%zu  "
           "unwind:%ld µs%s\n",
           e->tgid, e->pid, frames.size(),
           us, truncated ? " (TRUNC)" : "");

    for (size_t i = 0; i < frames.size(); ++i)
        printf("    #%zu 0x%llx\n",
               i, (unsigned long long)frames[i]);

    return 0;
}

// --- Main Function ---
int main(int argc, char** argv) {
    (void)argc; (void)argv; // Silence unused

    FdGuard               perf_fd;          // replaces int perf_fd
    LinkPtr               perf_link(nullptr, &bpf_link__destroy);
    RingPtr               rb      (nullptr, &ring_buffer__free);
    SkelPtr               skel    (nullptr, &self_profiler_bpf__destroy);
    int err = 0;
    int events_map_fd = -1;

    target_pid = getpid();
    printf("Self Profiler started. PID: %d\n", target_pid);

    // --- Basic Setup ---
    libbpf_set_print(libbpf_print_fn); // Use verbose libbpf printer
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit() != 0) return 1;

    // --- Open BPF Skeleton ---
    printf("Opening BPF skeleton...\n");
    skel.reset(self_profiler_bpf__open());
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        return 1;
    }
    printf("Skeleton opened.\n");

    // --- Load BPF Object ---
    printf("Loading BPF object...\n");
    err = self_profiler_bpf__load(skel.get());
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err));
        return 1;
    }
    printf("BPF object loaded.\n");

    // --- Get Map FDs (Events) ---
    printf("Finding map FDs...\n");
    events_map_fd = bpf_map__fd(skel->maps.events);
    if (events_map_fd < 0) {
        fprintf(stderr, "ERROR: Failed to get events map FD: %d (%s)\n",
            events_map_fd, strerror(errno));
        return 1;
    }
    printf("Found events map FD: %d\n", events_map_fd);

    // --- Create Ring Buffer ---
    printf("Setting up ring buffer...\n");
    rb.reset(ring_buffer__new(events_map_fd, handle_event, nullptr, nullptr));
    if (!rb) {
        fprintf(stderr, "ERROR: Failed to create ring buffer: %s\n", strerror(errno));
        return 1;
    }
    printf("Ring buffer ready - map populated.\n");

    // ─────────────────────────────────────────────────────────────
    // BEGIN CHANGED CODE – open one "any-CPU" sampling FD
    struct perf_event_attr attr = {};
    attr.type          = PERF_TYPE_SOFTWARE;
    attr.config        = PERF_COUNT_SW_CPU_CLOCK;
    attr.freq          = 1;
    attr.sample_freq   = 100;          // keep your old value
    attr.sample_type   = PERF_SAMPLE_RAW;
    attr.inherit       = 1;            // follow all threads of this process
    /* 'disabled' left at 0  → event auto-enables on open */

    perf_fd.fd = syscall(__NR_perf_event_open, &attr,
                      /*pid=*/getpid(),  /*cpu=*/-1,
                      /*group_fd=*/-1,   /*flags=*/0);
    if (perf_fd.fd < 0) {
        perror("perf_event_open");
        return 1;
    }
    // END CHANGED CODE
    // ─────────────────────────────────────────────────────────────

    // ─────────────────────────────────────────────────────────────
    // BEGIN CHANGED CODE – one bpf_link instead of a vector
    perf_link.reset(
        bpf_program__attach_perf_event(skel->progs.do_stack_sample,
                                       perf_fd.fd));
    if (!perf_link) {
        fprintf(stderr, "attach_perf_event failed\n");
        return 1;
    }
    // END CHANGED CODE
    // ─────────────────────────────────────────────────────────────

    // --- Start Workload Threads ---
    printf("Starting workload threads...\n");
    std::thread worker_thread(run_workload, std::ref(keep_running));
    std::thread main_workload_thread(run_workload, std::ref(keep_running));

    // --- Main Event Loop ---
    printf("Polling ring buffer... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = ring_buffer__poll(rb.get(), 100);
        if (err < 0) {
            if (err == -EINTR) {
                fprintf(stderr, "\nPolling interrupted by signal (EINTR).\n");
                // Signal handler already set exiting=true, loop will terminate
                continue;
            }
            fprintf(stderr, "\nERROR polling ring buffer: %d (%s)\n", err, strerror(-err));
            exiting = true; // Trigger exit on error
            break;
        }
        if (err == 0) { // Timeout
            printf("."); fflush(stdout);
        }
    }

    printf("\nPolling finished.\n");

    // --- Shutdown ---
    printf("Signaling workload threads to stop...\n");
    keep_running.store(false);

    if (main_workload_thread.joinable()) { main_workload_thread.join(); }
    printf("Main workload thread joined.\n");
    if (worker_thread.joinable()) { worker_thread.join(); }
    printf("Worker thread joined.\n");

    // Return standardized error code if err was set during init/poll
    return err < 0 ? -err : 0;
}