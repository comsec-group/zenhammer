#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <algorithm>
// #include <climits>
// #include <iomanip>
#include <iostream>
// #include <ostream>
// #include <iterator>
// #include <map>
// #include <random>
// #include <set>
// #include <sstream>
// #include <string>
// #include <unordered_map>
// #include <unordered_set>
// #include <utility>
// #include <vector>

#include "../include/CodeJitter.hpp"
#include "../include/HammeringPattern.hpp"
#include "../include/Range.hpp"

class PatternBuilder {
 public:
  std::mt19937 gen;

  /// A instance of the CodeJitter that is used to generate the ASM code for the produced hammering pattern.
  CodeJitter jitter;

  /// The number of consecutive segments an aggressor can appear in the pattern.
  /// For example, if agg_frequency = 1, then an aggressor pair (A1,A2) can only be repeated once N-times within an
  /// interval where N is the randomly chosen amplitude.
  Range agg_frequency;

  bool use_fixed_amplitude_per_aggressor;

  bool use_sequential_aggressors;

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval.
  int num_refresh_intervals;

  /// The numbers of aggressors to be picked from during random pattern generation.
  int num_aggressors;

  // int agg_inter_distance;

  Range agg_inter_distance;

  int agg_intra_distance;

  int num_activations_per_tREFI;

  int num_activations_per_tREFI_measured;

  int hammering_total_num_activations;

  int hammering_strategy;

  int hammering_reps_before_sync;

  int sync_after_every_nth_hammering_rep;

  size_t total_acts_pattern;

  Range amplitude;

  Range N_sided;

  std::discrete_distribution<int> N_sided_probabilities;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  volatile char* target_addr;

  volatile char* random_start_address;

  asmjit::StringLogger* logger;

  std::vector<volatile char*> aggressor_pairs;

  void encode_double_ptr_chasing(std::vector<volatile char*>& aggressors, volatile char** firstChase, volatile char** secondChase);

  std::string get_row_string(std::vector<volatile char*> aggs, u_int64_t row_function);

  std::string get_dist_string(std::unordered_map<int, int>& dist);

  /// default constructor that randomizes fuzzing parameters
  PatternBuilder(int num_activations, volatile char* target_address);

  // access the pattern that was previously created by calling generate_random_pattern
  int hammer_pattern();

  void cleanup();

  void randomize_parameters();

  int remove_aggs(int N);

  void jit_code();

  size_t count_aggs();

  void generate_frequency_based_pattern(HammeringPattern &hammering_pattern);
};

#endif /* PATTERNBUILDER */
