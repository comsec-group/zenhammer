#ifndef ZENHAMMER_SRC_FORGES_FUZZYHAMMERER_HPP_
#define ZENHAMMER_SRC_FORGES_FUZZYHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"
#include "ReplayingHammerer.hpp"

class FuzzyHammerer {
 public:
  CustomRandom cr;

  FuzzyHammerer();

  // counter for the number of generated patterns so far
  size_t cnt_generated_patterns;

  // counter for the number of different locations where we tried the current pattern
  size_t cnt_pattern_probes;

  // this and cnt_pattern_probes are a workaround for the generate_pattern_for_ARM as we there somehow need to keep
  // track of whether we need to generate new pattern or only randomize the mapping of an existing one
  HammeringPattern hammering_pattern;

  // maps (pattern_id) -> (address_mapper_id -> number_of_detected_bit_flips) where 'number_of_detected_bit_flips'
  // refers to the number of bit flips we detected when hammering a pattern at a specific location
  // note: it does not consider the bit flips triggered during the reproducibility runs
  std::unordered_map<std::string, std::unordered_map<std::string, int>> map_pattern_mappings_bitflips;

  void n_sided_frequency_based_hammering(DramAnalyzer &dramAnalyzer, Memory &memory, int acts,
                                                unsigned long runtime_limit, size_t probes_per_pattern,
                                                bool sweep_best_pattern);

//  static void test_location_dependence(ReplayingHammerer &rh, HammeringPattern &pattern);

  void probe_mapping_and_scan(PatternAddressMapper &mapper,
                              Memory &memory,
                              FuzzingParameterSet &fuzzing_params,
                              size_t num_dram_locations,
                              size_t ref_threshold);

  static void log_overall_statistics(size_t cur_round, const std::string &best_mapping_id,
                                     size_t best_mapping_num_bitflips, size_t num_effective_patterns);
};

#endif //ZENHAMMER_SRC_FORGES_FUZZYHAMMERER_HPP_
