#ifndef BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"

class FuzzyHammerer {
 public:
  // counter for the number of different locations where we tried the current pattern
  static size_t cnt_pattern_probes;

  // the number of successful hammering probes: if a pattern works on a location, we increase this counter, once for
  // each successful location
  static size_t num_successful_probes;

  // this and cnt_pattern_probes are a workaround for the generate_pattern_for_ARM as we there somehow need to keep
  // track of whether we need to generate new pattern or only randomize the mapping of an existing one
  static HammeringPattern hammering_pattern;

  // maps (pattern_id) -> (address_mapper_id -> number_of_detected_bit_flips) where 'number_of_detected_bit_flips'
  // refers to the number of bit flips we detected when hammering a pattern at a specific location
  // note: it does not consider the bit flips triggered during the reproducibility runs
  static std::unordered_map<std::string, std::unordered_map<std::string, int>> map_pattern_mappings_bitflips;

  static void do_random_accesses(const std::vector<volatile char *>& random_rows, size_t duration_us);

  static void n_sided_frequency_based_hammering(Memory &memory, int acts, long runtime_limit,
                                                size_t probes_per_pattern, bool sweep_best_pattern);

  static void generate_pattern_for_ARM(int acts,
                                       int *rows_to_access,
                                       int max_accesses,
                                       size_t probes_per_pattern);

  static void log_overall_statistics(size_t probes_per_pattern, size_t cur_round);

  static void probe_mapping_and_scan(PatternAddressMapper &mapper, Memory &memory, FuzzingParameterSet &fuzzing_params);
};

#endif //BLACKSMITH_SRC_FORGES_FUZZYHAMMERER_HPP_
