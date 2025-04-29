#include "workload.hpp"
#include <iostream>
#include <thread>
#include <chrono>
#include <vector>
#include <cmath> // For sqrt
#include <atomic> // Ensure included

// Use volatile to prevent compiler from optimizing away the busy loop
volatile double busy_work_result = 0.0;

void work_level7(std::atomic<bool>& running_flag) {
    // Perform some CPU-intensive work
    auto start_time = std::chrono::steady_clock::now();
    double temp_result = 0.0;
    // *** INCREASED LOOP COUNTS SIGNIFICANTLY ***
    // Aim to keep a core busy for a noticeable duration within one call
    // Adjust these based on your CPU speed if needed
    for (long i = 0; i < 500000 && running_flag.load(std::memory_order_relaxed); ++i) { // x10 outer loop
        // Keep inner loop doing some math
        for (int k = 0; k < 100; ++k) { // Add another inner loop
            temp_result += std::sqrt((double)(i * i + k + 1.0) / (i + k + 1.0));
            // Add simple volatile arithmetic to prevent optimization
            busy_work_result = temp_result * 1.00000001;
            temp_result = busy_work_result / 1.00000001;
        }
    }
    busy_work_result = temp_result; // Store final result
    (void)start_time; // Mark as used
}


void work_level6(std::atomic<bool>& running_flag) { if (running_flag.load(std::memory_order_relaxed)) work_level7(running_flag); }
void work_level5(std::atomic<bool>& running_flag) { if (running_flag.load(std::memory_order_relaxed)) work_level6(running_flag); }
void work_level4(std::atomic<bool>& running_flag) { if (running_flag.load(std::memory_order_relaxed)) work_level5(running_flag); }
void work_level3(std::atomic<bool>& running_flag) { if (running_flag.load(std::memory_order_relaxed)) work_level4(running_flag); }
void work_level2(std::atomic<bool>& running_flag) { if (running_flag.load(std::memory_order_relaxed)) work_level3(running_flag); }
void work_level1(std::atomic<bool>& running_flag) { if (running_flag.load(std::memory_order_relaxed)) work_level2(running_flag); }

// Runs the work function repeatedly until the flag is set
void run_workload(std::atomic<bool>& running_flag) {
    std::cout << "Workload thread " << std::this_thread::get_id() << " starting (CPU intensive)." << std::endl;
    while (running_flag.load(std::memory_order_relaxed)) {
        work_level1(running_flag);
        // *** REMOVE SLEEP to keep the thread constantly busy ***
        // std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::cout << "Workload thread " << std::this_thread::get_id() << " finished." << std::endl;
}