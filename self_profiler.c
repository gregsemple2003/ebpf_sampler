// self_profiler.c (Implementing skeleton variable and system-wide events with verbose error logging)

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
struct pid_namespace;  // forward-declare; no header needed

// C++ Standard Includes (for workload and threading)
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>

// BPF Includes
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/perf_event.h>

// Generated BPF Skeleton Header
#include "self_profiler.skel.h"

// Workload Header
#include "workload.hpp"

// --- BPF Data Structures (Must match BPF side) ---
struct event {
    uint32_t stack_id;
    uint32_t pid; // TGID
    uint32_t tid; // PID
};
#define MAX_STACK_DEPTH 127

// --- Global Variables ---
static std::atomic<bool> keep_running(true);
static volatile bool exiting = false;
static int stack_traces_fd = -1;
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

// --- Helper: Perf Event Open Syscall ---
static long perf_event_open_syscall(struct perf_event_attr* hw_event, pid_t pid,
    int cpu, int group_fd, unsigned long flags) {
    // No logging here, caller handles errors
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// --- Perf Buffer Callbacks (Global Functions) ---
static void handle_event(void* ctx, int cpu, void* data, uint32_t data_sz) {
    (void)ctx; (void)cpu;
    static uint64_t stack_addrs[MAX_STACK_DEPTH];

    fprintf(stderr, "\n[Callback] handle_event called\n");

    if (data_sz != sizeof(struct event)) {
        fprintf(stderr, "\n[Callback] ERROR: Received event data with unexpected size %u (expected: %zu)\n",
            data_sz, sizeof(struct event));
        return; // Exit callback on error
    }

    const struct event* e = (const struct event*)data;

    // BPF program now filters, so PID should always match target_pid
    // Add a check just in case, but log it as an unexpected error if it fails
    if (e->pid != target_pid) {
        fprintf(stderr, "\n[Callback] UNEXPECTED ERROR: Received event for wrong PID %u (target %d)\n",
            e->pid, target_pid);
        return; // Don't process unexpected PIDs
    }

    // Lookup stack trace
    if (stack_traces_fd < 0) {
        fprintf(stderr, "\n[Callback] ERROR: stack_traces map FD is not valid (%d)!\n", stack_traces_fd);
        return; // Exit callback on error
    }
    memset(stack_addrs, 0, sizeof(stack_addrs));
    int ret = bpf_map_lookup_elem(stack_traces_fd, &e->stack_id, stack_addrs);
    if (ret != 0) {
        // Log ENOENT as info, other errors as warning/error
        if (errno == ENOENT) {
            fprintf(stderr, "\n[Callback] INFO: Stack ID %u not found (ENOENT) for PID %u.\n", e->stack_id, e->pid);
        }
        else {
            fprintf(stderr, "\n[Callback] ERROR: Failed to lookup stack_id %u for PID %u: %s\n",
                e->stack_id, e->pid, strerror(errno));
        }
        return; // Exit callback on error
    }

    // Print Sample
    printf("\n--- Sample --- PID: %u TID: %u StackID: %u ---\n", e->pid, e->tid, e->stack_id);
    printf("  User Stack Trace:\n");
    int count = 0;
    for (int i = 0; i < MAX_STACK_DEPTH; ++i) {
        if (stack_addrs[i] == 0) break;
        if (stack_addrs[i] > 0x7FFFFFFFFFFFFFFFULL) continue;
        printf("    #%d: 0x%" PRIx64 "\n", count++, stack_addrs[i]);
    }
    if (count == 0) { // Log if lookup succeeded but stack was empty/invalid
        fprintf(stderr, "    INFO: No valid stack addresses found for stack_id %u\n", e->stack_id);
    }
    fflush(stdout); // Ensure printf is flushed
    fflush(stderr); // Ensure fprintf is flushed
}

static void handle_lost_events(void* ctx, int cpu, long long unsigned int lost_cnt) {
    (void)ctx;
    static std::atomic<uint64_t> total_lost(0);
    total_lost += lost_cnt;
    fprintf(stderr, "\n### LOST EVENTS ###: Lost %llu events on CPU %d (total lost: %llu)\n",
        lost_cnt, cpu, (unsigned long long)total_lost.load());
    fflush(stderr); // Ensure flush
}

// --- Main Function ---
int main(int argc, char** argv) {
    (void)argc; (void)argv; // Silence unused

    struct self_profiler_bpf* skel = NULL;
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer* pb = NULL;
    long sample_freq = 100;
    int err = 0;
    int num_cpus = 0;
    int* pmu_fds = NULL;
    struct bpf_link** links = NULL;
    std::thread worker_thread;
    std::thread main_workload_thread;
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
    skel = self_profiler_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        return 1;
    }
    printf("Skeleton opened.\n");

    printf("Setting target PID in skeleton...\n"); // must happen before load
    {
        struct stat st;
        if (stat("/proc/self/ns/pid", &st) == 0) {
            skel->bss->target_pidns_inum = static_cast<__u32>(st.st_ino);
        }
        skel->bss->target_tgid_host = static_cast<__u32>(getpid());  // host TGID

        printf("DEBUG: setting target_pidns_inum=%d, target_tgid_host=%d\n", skel->bss->target_pidns_inum, skel->bss->target_tgid_host);
    }

    // --- Load BPF Object ---
    printf("Loading BPF object...\n");
    err = self_profiler_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }
    printf("BPF object loaded.\n");

    // --- Get Map FDs (Events and Stack Traces) ---
    printf("Finding map FDs...\n");
    events_map_fd = bpf_map__fd(skel->maps.events);
    stack_traces_fd = bpf_map__fd(skel->maps.stack_traces);
    if (events_map_fd < 0 || stack_traces_fd < 0) {
        fprintf(stderr, "ERROR: Failed to get map FDs: events=%d, stack_traces=%d (%s)\n",
            events_map_fd, stack_traces_fd, strerror(errno));
        err = -errno;
        goto cleanup;
    }
    printf("Found map FDs: events=%d, stack_traces=%d\n", events_map_fd, stack_traces_fd);

    // --- Create Perf Buffer ---
    printf("Setting up perf buffer...\n");
    memset(&pb_opts, 0, sizeof(pb_opts));
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;
    pb = perf_buffer__new(events_map_fd, 8 /* page count */, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "ERROR: Failed to create perf buffer: %s\n", strerror(-err));
        err = -err;
        goto cleanup;
    }
    printf("Perf buffer ready - map populated.\n");


    // --- Open/Attach/Enable SYSTEM-WIDE Sampling Perf Events ---
    printf("Opening/Attaching/Enabling sampling perf events (system-wide)...\n");
    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "ERROR: Failed to get number of CPUs: %d\n", num_cpus);
        err = -1; // Or specific error
        goto cleanup;
    }

    pmu_fds = (int*)calloc(num_cpus, sizeof(int));
    links = (struct bpf_link**)calloc(num_cpus, sizeof(struct bpf_link*));
    if (!pmu_fds || !links) {
        fprintf(stderr, "ERROR: Failed to allocate memory for FDs/links\n");
        err = -ENOMEM;
        goto cleanup;
    }
    for (int i = 0; i < num_cpus; ++i) pmu_fds[i] = -1; // Initialize

    for (int cpu = 0; cpu < num_cpus; cpu++) {
        struct perf_event_attr attr = {};
        attr.type = PERF_TYPE_SOFTWARE;
        attr.size = sizeof(attr);
        attr.config = PERF_COUNT_SW_CPU_CLOCK;
        attr.sample_freq = sample_freq;
        attr.freq = 1;
        attr.inherit = 1;
        attr.exclude_kernel = 1;
        attr.disabled = 1; // OPEN DISABLED

        pmu_fds[cpu] = perf_event_open_syscall(&attr, /*pid=*/-1, cpu, -1, 0);
        if (pmu_fds[cpu] < 0) {
            fprintf(stderr, "ERROR: Failed to open system-wide perf event on CPU %d: %s\n", cpu, strerror(errno));
            err = -errno;
            goto cleanup;
        }

        // Attach BPF program to the disabled perf event FD
        links[cpu] = bpf_program__attach_perf_event(skel->progs.do_stack_sample, pmu_fds[cpu]);
        if (!links[cpu]) {
            err = -errno;
            fprintf(stderr, "ERROR: Failed to attach BPF to perf event on CPU %d: %s\n", cpu, strerror(-err));
            goto cleanup;
        }

        // Explicit enable AFTER attach
        if (ioctl(pmu_fds[cpu], PERF_EVENT_IOC_ENABLE, 0) < 0) {
            err = -errno;
            fprintf(stderr, "ERROR: Failed to enable perf event on CPU %d: %s\n", cpu, strerror(-err));
            goto cleanup;
        }
    }
    printf("Sampling perf events opened, attached, and enabled.\n");


    // --- Start Workload Threads ---
    printf("Starting workload threads...\n");
    worker_thread = std::thread(run_workload, std::ref(keep_running));
    main_workload_thread = std::thread(run_workload, std::ref(keep_running));


    // --- Main Event Loop ---
    printf("Polling perf buffer... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0) {
            if (err == -EINTR) {
                fprintf(stderr, "\nPolling interrupted by signal (EINTR).\n");
                // Signal handler already set exiting=true, loop will terminate
                continue; // Or break; depending on desired immediate exit behavior
            }
            fprintf(stderr, "\nERROR polling perf buffer: %d (%s)\n", err, strerror(-err));
            // Consider triggering exit on persistent poll errors?
            exiting = true; // Trigger exit on error
            break;
        }
        if (err == 0) { // Timeout
            printf("."); fflush(stdout);
        }
        // err > 0 => samples processed by callback
    }

    printf("\nPolling finished.\n");

    // --- Shutdown ---
    printf("Signaling workload threads to stop...\n");
    keep_running.store(false);

    if (main_workload_thread.joinable()) { main_workload_thread.join(); }
    printf("Main workload thread joined.\n");
    if (worker_thread.joinable()) { worker_thread.join(); }
    printf("Worker thread joined.\n");


cleanup:
    fprintf(stderr, "\nExiting... Performing cleanup.\n"); // Use stderr for exit messages
    // --- Cleanup --- (Order: perf buffer, links, FDs, skeleton)
    perf_buffer__free(pb); // Safe to call on NULL

    if (links) {
        for (int cpu = 0; cpu < num_cpus; ++cpu) {
            bpf_link__destroy(links[cpu]); // Safe on NULL
        }
        free(links);
        fprintf(stderr, "BPF links destroyed.\n");
    }
    if (pmu_fds) {
        for (int cpu = 0; cpu < num_cpus; ++cpu) {
            if (pmu_fds[cpu] >= 0) {
                ioctl(pmu_fds[cpu], PERF_EVENT_IOC_DISABLE, 0); // Best effort disable
                close(pmu_fds[cpu]);
            }
        }
        free(pmu_fds);
        fprintf(stderr, "Perf event FDs closed.\n");
    }

    self_profiler_bpf__destroy(skel); // Safe to call on NULL
    fprintf(stderr, "BPF skeleton destroyed.\n");
    fprintf(stderr, "Cleanup complete.\n");

    // Return standardized error code if err was set during init/poll
    return err < 0 ? -err : 0;
}