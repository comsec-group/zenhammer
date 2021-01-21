#ifndef BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"

class FuzzyHammerer {
// private:
 public:
  // counter for the number of different locations where we tried the current pattern
  static size_t cnt_pattern_probes;

  static HammeringPattern hammering_pattern;

  static void do_random_accesses(std::vector<volatile char *> random_rows, size_t duration_us);

  static void n_sided_frequency_based_hammering(Memory &memory,
                                                int acts,
                                                long runtime_limit,
                                                size_t probes_per_pattern);

  static void generate_pattern_for_ARM(int acts,
                                       int *rows_to_access,
                                       int max_accesses,
                                       size_t probes_per_pattern);
};

#endif //BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_
