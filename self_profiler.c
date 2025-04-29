// self_profiler.c (Revert perf_event_open pid to getpid())

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
#include <stddef.h> // NECESSARY for offsetof

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

// Stack Unwinder Header
#include "stack_unwinder.hpp" // NECESSARY include

// --- BPF Data Structures (Must match BPF side EXACTLY) ---
#define MAX_STACK_BUF_SIZE 8192 // NECESSARY constant

// Event structure received from BPF - Ensure layout matches BPF definition
struct stack_event {
    // Metadata
    uint32_t pid; // TGID
    uint32_t tid; // PID
    uint32_t stack_size; // Actual size of stack data captured
    uint8_t truncated;  // Flag: 1 if stack was truncated, 0 otherwise
    uint8_t __padding[3]; // <<< ADDED explicit padding to match BPF struct alignment calculation

    // Raw stack data (variable length, up to MAX_STACK_BUF_SIZE)
    // Add alignment attribute to match BPF side
    unsigned char stack_data[MAX_STACK_BUF_SIZE] __attribute__((aligned(8)));
};

// --- Global Variables ---
static std::atomic<bool> keep_running(true);
static volatile bool exiting = false;
static pid_t target_pid = 0;

// --- Helper: Libbpf Print Function ---
static int libbpf_print_fn(enum libbpf_print_level level, const char* format, va_list args) {
    (void)level; // Mark unused explicitly for C++ warnings
    fprintf(stderr, "LIBBPF: ");
    return vfprintf(stderr, format, args);
}

// --- Signal Handler ---
static void sig_handler(int sig) {
    fprintf(stderr, "\nCaught signal %d, initiating shutdown...\n", sig);
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
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

// --- Perf Buffer Callbacks (Global Functions) ---
static void handle_event(void* ctx, int cpu, void* data, uint32_t data_sz) {
    (void)ctx; (void)cpu;

    fprintf(stderr, "\n[Callback] handle_event called (data_sz: %u)\n", data_sz);

    // --- Basic Validation ---
    size_t min_size = offsetof(struct stack_event, stack_data);
    if (data_sz < min_size) {
        fprintf(stderr, "\n[Callback] ERROR: Received event data too small (%u bytes, expected >= %zu bytes calculated with offsetof)\n",
            data_sz, min_size);
        return;
    }

    const struct stack_event* e = (const struct stack_event*)data;

    // --- Detailed Size Validation ---
    size_t required_data_size = min_size + e->stack_size;
    if (data_sz < required_data_size) {
        fprintf(stderr, "\n[Callback] ERROR: Received data_sz %u is smaller than required size %zu (offsetof %zu + stack_size %u). Event is malformed.\n",
            data_sz, required_data_size, min_size, e->stack_size);
        return;
    }

    // Check stack size against our internal buffer capacity (safety)
    if (e->stack_size > MAX_STACK_BUF_SIZE) {
        fprintf(stderr, "\n[Callback] ERROR: Received stack_size %u exceeds max static buffer %d.\n",
            e->stack_size, MAX_STACK_BUF_SIZE);
        return;
    }

    // --- Process Event ---
    printf("\n--- Sample --- PID: %u TID: %u Stack Size: %u bytes ---\n", e->pid, e->tid, e->stack_size);

    // Keep original PID check commented out
    // if (e->pid != (uint32_t)target_pid) {
    //    fprintf(stderr, "\n[Callback] UNEXPECTED ERROR: Received event for wrong PID %u (target %d)\n", e->pid, target_pid);
    // }

    if (e->truncated) {
        fprintf(stderr, "    WARNING: Stack trace was truncated by BPF (captured %u/%d bytes).\n", e->stack_size, MAX_STACK_BUF_SIZE);
    }

    const unsigned char* stack_data_ptr = e->stack_data;

    // --- Call Unwinder ---
    std::vector<uint64_t> stack_frames = unwind_stack_frame_pointers(stack_data_ptr, e->stack_size, 0, 0);

    // Print result of unwinding attempt
    if (!stack_frames.empty()) {
        printf("  Unwound Stack Trace (Placeholder - Frame Pointers):\n");
        int count = 0;
        for (uint64_t addr : stack_frames) {
            if (addr == 0) continue;
            printf("    #%d: 0x%" PRIx64 "\n", count++, addr);
        }
        if (count == 0) {
            printf("    (No frames unwound - likely requires register capture)\n");
        }
    }
    else {
        printf("  Unwound Stack Trace: (Unwinding failed or not implemented fully yet)\n");
    }

    fflush(stdout);
    fflush(stderr);
}

static void handle_lost_events(void* ctx, int cpu, long long unsigned int lost_cnt) {
    (void)ctx;
    static std::atomic<uint64_t> total_lost(0);
    total_lost += lost_cnt;
    fprintf(stderr, "\n### LOST EVENTS ###: Lost %llu events on CPU %d (total lost: %llu)\n",
        lost_cnt, cpu, (unsigned long long)total_lost.load());
    fflush(stderr);
}

// --- Main Function ---
int main(int argc, char** argv) {
    (void)argc; (void)argv;

    // --- Variable Declarations ---
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
    int perf_buffer_page_cnt = 128;
    struct perf_event_attr attr = {};
    // pid_t filter_pid = -1; // Removed, will use getpid() directly
    int group_fd = -1;
    unsigned long flags = 0;
    // --- End Variable Declarations ---

    target_pid = getpid();
    printf("Self Profiler started. PID: %d\n", target_pid);

    // --- Basic Setup ---
    libbpf_set_print(libbpf_print_fn);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (bump_memlock_rlimit() != 0) return 1;

    // --- Open BPF Skeleton ---
    printf("Opening BPF skeleton...\n");
    skel = self_profiler_bpf__open();
    if (!skel) {
        fprintf(stderr, "ERROR: Failed to open BPF skeleton\n");
        err = -1;
        goto cleanup;
    }
    printf("Skeleton opened.\n");

    // --- Set Target PID Info in Skeleton (Before Load) ---
    printf("Setting target PID in skeleton...\n"); // must happen before load
    {
        struct stat st;
        if (stat("/proc/self/ns/pid", &st) == 0) {
            skel->bss->target_pidns_inum = static_cast<__u32>(st.st_ino);
        }
        auto host_tgid = [&]() -> __u32 {
            FILE* fp = fopen("/proc/self/status", "r");
            __u32 parsed_tgid = 0;
            if (fp) {
                char line[256];
                while (fgets(line, sizeof(line), fp)) {
                    if (strncmp(line, "NSpid:", 6) == 0) {
                        fprintf(stderr, "DEBUG NSpid line = %s", line);
                        char* ptr = line + 6;
                        while (*ptr == '\t' || *ptr == ' ') ptr++;
                        parsed_tgid = static_cast<__u32>(strtoul(ptr, nullptr, 10));
                        break;
                    }
                }
                fclose(fp);
            }
            if (parsed_tgid == 0) {
                fprintf(stderr, "WARNING: Could not parse NSpid from /proc/self/status. Falling back to getpid().\n");
                return static_cast<__u32>(target_pid);
            }
            return parsed_tgid;
            }();
            skel->bss->target_tgid_host = host_tgid;
            printf("DEBUG: setting target_pidns_inum=%d, target_tgid_host=%d\n",
                skel->bss->target_pidns_inum, skel->bss->target_tgid_host);
    }


    // --- Load BPF Object ---
    printf("Loading BPF object...\n");
    err = self_profiler_bpf__load(skel);
    if (err) {
        fprintf(stderr, "ERROR: Failed to load BPF skeleton: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }
    printf("BPF object loaded.\n");

    // --- Get Map FDs (Events only) ---
    printf("Finding events map FD...\n");
    events_map_fd = bpf_map__fd(skel->maps.events);
    if (events_map_fd < 0) {
        fprintf(stderr, "ERROR: Failed to get events map FD: %d (%s)\n",
            events_map_fd, strerror(errno));
        err = -errno;
        goto cleanup;
    }
    printf("Found events map FD: %d\n", events_map_fd);

    // --- Create Perf Buffer ---
    printf("Setting up perf buffer (using %d pages)...\n", perf_buffer_page_cnt);
    memset(&pb_opts, 0, sizeof(pb_opts));
    pb_opts.sample_cb = handle_event;
    pb_opts.lost_cb = handle_lost_events;
    pb = perf_buffer__new(events_map_fd, perf_buffer_page_cnt, &pb_opts);
    err = libbpf_get_error(pb);
    if (err) {
        pb = NULL;
        fprintf(stderr, "ERROR: Failed to create perf buffer: %d (%s)\n", err, strerror(-err));
        goto cleanup;
    }
    printf("Perf buffer ready.\n");


    // --- Open/Attach/Enable Sampling Perf Events ---
    // Use getpid() as was originally intended in the first provided C file
    printf("Opening/Attaching/Enabling sampling perf events (PID: %d)...\n", target_pid);
    num_cpus = libbpf_num_possible_cpus();
    if (num_cpus <= 0) {
        fprintf(stderr, "ERROR: Failed to get number of CPUs: %d\n", num_cpus);
        err = (num_cpus == 0) ? -ENODEV : num_cpus;
        goto cleanup;
    }

    pmu_fds = (int*)calloc(num_cpus, sizeof(int));
    links = (struct bpf_link**)calloc(num_cpus, sizeof(struct bpf_link*));
    if (!pmu_fds || !links) {
        fprintf(stderr, "ERROR: Failed to allocate memory for FDs/links\n");
        err = -ENOMEM;
        goto cleanup;
    }
    for (int i = 0; i < num_cpus; ++i) pmu_fds[i] = -1;

    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_freq = sample_freq;
    attr.freq = 1;
    attr.inherit = 1; // Keep original inherit setting
    attr.exclude_kernel = 1;
    attr.disabled = 1;

    // Use target_pid (obtained from getpid()) in the perf_event_open call
    printf("Attaching to SW CPU Clock events (Freq: %ld Hz, PID %d, Inherit: %d)...\n", sample_freq, target_pid, attr.inherit);
    for (int cpu = 0; cpu < num_cpus; cpu++) {
        // *** REVERTED TO USING target_pid (getpid()) ***
        pmu_fds[cpu] = perf_event_open_syscall(&attr, target_pid, cpu, group_fd, flags);
        if (pmu_fds[cpu] < 0) {
            fprintf(stderr, "ERROR: Failed to open perf event for PID %d on CPU %d: %s (errno %d)\n", target_pid, cpu, strerror(errno), errno);
            if (errno == EPERM) fprintf(stderr, " Check /proc/sys/kernel/perf_event_paranoid setting.\n");
            else if (errno == ESRCH) fprintf(stderr, " Ensure PID %d exists when event is opened.\n", target_pid);
            err = -errno;
            goto cleanup;
        }

        links[cpu] = bpf_program__attach_perf_event(skel->progs.do_stack_sample, pmu_fds[cpu]);
        err = libbpf_get_error(links[cpu]);
        if (err) {
            fprintf(stderr, "ERROR: Failed to attach BPF to perf event on CPU %d: %s (err %d)\n", cpu, strerror(-err), err);
            goto cleanup;
        }

        if (ioctl(pmu_fds[cpu], PERF_EVENT_IOC_ENABLE, 0) < 0) {
            err = -errno;
            fprintf(stderr, "ERROR: Failed to enable perf event on CPU %d: %s (errno %d)\n", cpu, strerror(-err), -err);
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
                continue;
            }
            fprintf(stderr, "\nERROR polling perf buffer: %d (%s)\n", err, strerror(-err));
            exiting = true;
            break;
        }
        if (err == 0) {
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


cleanup:
    // --- Cleanup ---
    fprintf(stderr, "\nExiting... Performing cleanup.\n");
    perf_buffer__free(pb);

    if (links) {
        for (int cpu = 0; cpu < num_cpus; ++cpu) {
            if (links[cpu]) {
                bpf_link__destroy(links[cpu]);
            }
        }
        free(links);
    }
    if (pmu_fds) {
        for (int cpu = 0; cpu < num_cpus; ++cpu) {
            if (pmu_fds[cpu] >= 0) {
                ioctl(pmu_fds[cpu], PERF_EVENT_IOC_DISABLE, 0);
                close(pmu_fds[cpu]);
            }
        }
        free(pmu_fds);
    }

    self_profiler_bpf__destroy(skel);
    fprintf(stderr, "Cleanup complete.\n");

    return err < 0 ? -err : 0;
}