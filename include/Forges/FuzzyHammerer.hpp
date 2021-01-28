#ifndef BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"

class FuzzyHammerer {
 public:
  // counter for the number of different locations where we tried the current pattern
  static size_t cnt_pattern_probes;

  // this and cnt_pattern_probes are a workaround for the generate_pattern_for_ARM as we there somehow need to keep
  // track of whether we need to generate new pattern or only randomize the mapping of an existing one
  static HammeringPattern hammering_pattern;

  static void do_random_accesses(const std::vector<volatile char *>& random_rows, size_t duration_us);

  static void n_sided_frequency_based_hammering(Memory &memory,
                                                int acts,
                                                long runtime_limit,
                                                size_t probes_per_pattern);

  static void generate_pattern_for_ARM(int acts,
                                       int *rows_to_access,
                                       int max_accesses,
                                       size_t probes_per_pattern);

  static void log_overall_statistics(const size_t probes_per_pattern,
                                     std::unordered_map<std::string,
                                                        std::unordered_map<std::string,
                                                                           int>> &map,
                                     int cur_round);
};

#endif //BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_
