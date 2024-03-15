/*
 * Copyright (c) 2024 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
#define BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_

#include <random>
#include <set>
#include <utility>
#include <unordered_set>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Fuzzer/Aggressor.hpp"
#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Fuzzer/BitFlip.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/CodeJitter.hpp"

class HammeringPattern;

class PatternAddressMapper {
 private:
  std::unordered_set<volatile char *> victim_rows;

  // the unique identifier of this pattern-to-address mapping
  std::string instance_id;

  // a randomization engine
  std::mt19937 gen;

 public:
  std::unique_ptr<CodeJitter> code_jitter;

  PatternAddressMapper();

  // copy constructor
  PatternAddressMapper(const PatternAddressMapper& other);

  // copy assignment operator
  PatternAddressMapper& operator=(const PatternAddressMapper& other);

  // information about the mapping (required for determining rows not belonging to this mapping)
  size_t min_row = 0;
  size_t max_row = 0;
  int bank_no = 0;

  // a global counter that makes sure that we test patterns on all banks equally often
  // it is incremented for each mapping and reset to 0 once we tested all banks (depending on num_probes_per_pattern
  // this may happen after we tested more than one pattern)
  static int bank_counter;

  // a mapping from aggressors included in this pattern to memory addresses (DRAMAddr)
  std::unordered_map<AGGRESSOR_ID_TYPE, DRAMAddr> aggressor_to_addr;

  // the bit flips that were detected while running the pattern with this mapping
  std::vector<std::vector<BitFlip>> bit_flips;

  // the reproducibility score of this mapping, e.g.,
  //    1   => 100%: was reproducible in all reproducibility runs executed,
  //    0.4 => 40%: was reproducible in 40% of all reproducibility runs executed
  int reproducibility_score = -1;

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  void randomize_addresses(FuzzingParameterSet &fuzzing_params,
                           const std::vector<AggressorAccessPattern> &agg_access_patterns,
                           bool verbose);

  void remap_aggressors(DRAMAddr &new_location);

  std::vector<volatile char*> export_pattern_with_fence_none(const HammeringPattern& pattern);
  std::vector<volatile char*> export_pattern_with_fence_all(const HammeringPattern& pattern);
  std::vector<volatile char*> export_pattern_with_fence_between_tuples(const HammeringPattern& pattern);
  std::vector<volatile char*> export_pattern_with_fence_between_tuple_iterations(const HammeringPattern& pattern);
  std::vector<volatile char*> export_pattern_with_fence_every_nth_access(const HammeringPattern& pattern, int n);
  std::vector<volatile char*> export_pattern_with_fence_per_base_period(const HammeringPattern& pattern, int fences_per_base_period);

  std::vector<volatile char*> export_pattern(const HammeringPattern& pattern, SCHEDULING_POLICY scheduling_policy);

  [[nodiscard]] const std::string &get_instance_id() const;

  std::string &get_instance_id();

  [[nodiscard]] const std::unordered_set<volatile char *> & get_victim_rows() const;

  std::vector<volatile char *> get_random_nonaccessed_rows(int row_upper_bound);

  void determine_victims(const std::vector<AggressorAccessPattern> &agg_access_patterns);

  std::string get_mapping_text_repr();

  [[nodiscard]] CodeJitter & get_code_jitter() const;

  void compute_mapping_stats(std::vector<AggressorAccessPattern> &agg_access_patterns, int &agg_intra_distance,
                             int &agg_inter_distance, bool uses_seq_addresses);

  void shift_mapping(int rows, const std::unordered_set<AggressorAccessPattern> &aggs_to_move);

  [[nodiscard]] size_t count_bitflips() const;
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const PatternAddressMapper &p);

void from_json(const nlohmann::json &j, PatternAddressMapper &p);

#endif

#endif //BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
