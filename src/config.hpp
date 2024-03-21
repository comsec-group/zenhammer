#include <cstdlib>

#pragma once

// Parameters for the dare_time function.
constexpr size_t DARE_ITERATIONS = 16;
constexpr size_t DARE_ACCESSES_PER_ITER = 32;

// Configuration for brute-forcing.
constexpr size_t BRUTE_FORCE_MAX_BITS = 10;
constexpr size_t BRUTE_FORCE_LSB = 6;
// Which percentage of all addresses in the cluster need to have the same value
// for the function to be considered "constant enough" over the entire cluster.
constexpr int BRUTE_FORCE_PASS_THRESHOLD_PERCENTAGE = 80;
