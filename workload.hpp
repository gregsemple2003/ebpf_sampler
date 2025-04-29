#ifndef WORKLOAD_HPP
#define WORKLOAD_HPP

#include <atomic>

// Function declarations for the workload
void work_level7(std::atomic<bool>& running_flag);
void work_level6(std::atomic<bool>& running_flag);
void work_level5(std::atomic<bool>& running_flag);
void work_level4(std::atomic<bool>& running_flag);
void work_level3(std::atomic<bool>& running_flag);
void work_level2(std::atomic<bool>& running_flag);
void work_level1(std::atomic<bool>& running_flag);

// Main function to run the work in a loop
void run_workload(std::atomic<bool>& running_flag);

#endif // WORKLOAD_HPP