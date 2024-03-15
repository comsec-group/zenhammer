/*
 * Copyright (c) 2024 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <unistd.h>
#include <vector>

#include "Utilities/AsmPrimitives.hpp"

class DramAnalyzer {
 private:
  // Threshold for bank conflict.
  size_t threshold { (size_t)-1 };

  std::vector<std::vector<volatile char *>> banks;

  uint64_t row_function;

  volatile char *start_address;

  volatile char* get_random_address() const;

 public:
  explicit DramAnalyzer(volatile char *target);

  /// Finds threshold.
  void find_threshold();

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts();

  /// Measures the time between accessing two addresses.
  static uint64_t inline measure_time(volatile char *a1, volatile char *a2) {
    usleep(200);
    auto min_delta = (uint64_t)-1;
    for (size_t i = 0; i < DRAMA_ITERS; i++) {
      uint64_t before, after;
      before = rdtscp();
      lfence();
      for (size_t j = 0; j < DRAMA_ROUNDS; j++) {
        (void)*a1;
        (void)*a2;
        clflushopt(a1);
        clflushopt(a2);
        mfence();
      }
      after = rdtscp();
      auto delta = (after - before) / DRAMA_ROUNDS;
      if (delta < min_delta) {
        min_delta = delta;
      }
    }
    return min_delta;
  }

  /// Determine the number of possible activations within a refresh interval.
  size_t count_acts_per_trefi();

  size_t find_sync_ref_threshold();
  void check_sync_ref_threshold(size_t sync_ref_threshold);

  // Find which banks in another mapping corresponds to the banks of this mapping.
  // Returns a vector where vector[this_mapping_bank] = other_mapping_same_bank.
  std::vector<size_t> get_corresponding_banks_for_mapping(int other_mapping_id, volatile char* other_mapping_base) const;
};

#endif /* DRAMANALYZER */
