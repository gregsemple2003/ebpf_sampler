#include <iostream>
#include <vector>
#include <numeric>   // For std::accumulate
#include <unistd.h>  // For getpid(), sleep()
#include <thread>    // For std::this_thread::sleep_for
#include <chrono>    // For std::chrono::milliseconds

// Use volatile to discourage excessive optimization/inlining

// Innermost function (Level 7 call from main) - contains the spin loop
volatile long function_g(volatile long input) {
    volatile long sum = input;
    // Spin loop - make it do enough work to be clearly visible
    for (volatile int i = 0; i < 50; ++i) { // Increased outer loop
        for (volatile int j = 0; j < 1000; ++j) { // Increased inner loop
            sum += j;
            sum = (sum * 17) % 999999937; // Some arbitrary work
        }
    }
    return sum;
}

// Chain of calls (Level 6 down to 1)
volatile long function_f(volatile long input) { return function_g(input + 1); }
volatile long function_e(volatile long input) { return function_f(input + 1); }
volatile long function_d(volatile long input) { return function_e(input + 1); }
volatile long function_c(volatile long input) { return function_d(input + 1); }
volatile long function_b(volatile long input) { return function_c(input + 1); }
volatile long function_a(volatile long input) { return function_b(input + 1); } // Level 1 call from main

int main() {
    pid_t pid = getpid();
    std::cout << "Starting deep stack slow program (PID: " << pid << ")" << std::endl;
    std::cout << "Run 'sudo ./simple_stack' in another terminal to trace." << std::endl;

    volatile long counter = 0;
    volatile long result = 0; // Store result to prevent optimizing away calls

    while (true) {
        if ((counter % 100000) == 0) { // Print milestone less often
            std::cout << "(PID " << pid << ") Deep Loop iteration milestone: " << counter << std::endl;
        }
        counter++;

        // Call the top of the function chain (main is Level 0)
        result = function_a(counter);

        // No sleep - keep CPU busy
    }

    std::cout << "Slow program finishing." << std::endl; // Unreachable
    return 0;
}