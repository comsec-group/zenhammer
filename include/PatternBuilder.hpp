#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>
#include <unordered_map>
#include <utility>

#include "../include/CodeJitter.hpp"

/// A range is equivalent to the mathematical notation [i,j] where i,j ∈ ℕ.
struct Range {
  int min;
  int max;
  std::uniform_int_distribution<> dist;

  Range() = default;

  Range(int min, int max) : min(min), max(max), dist(std::uniform_int_distribution<>(min, max)) {}

  Range(int min, int max, bool ensure_order) {
    int new_min = min;
    int new_max = max;
    if (ensure_order) {
      if (min >= max) {
        new_min = max;
        new_max = min;
      }
    }
    min = new_min;
    max = new_max;
    dist = std::uniform_int_distribution<>(new_min, new_max);
  }

  int get_random_number(std::mt19937& gen) {
    return dist(gen);
  }

  int get_random_number(int upper_bound, std::mt19937& gen) {
    if (max > upper_bound) dist = std::uniform_int_distribution<>(min, upper_bound);
    return dist(gen);
  }
};

class PatternBuilder {
 private:
  std::random_device rd;

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

 public:
  /// default constructor that randomizes fuzzing parameters
  PatternBuilder(int num_activations, volatile char* target_address);

  // access the pattern that was previously created by calling generate_random_pattern
  int hammer_pattern();

  void cleanup();

  void randomize_parameters();

  void generate_random_pattern(std::vector<uint64_t> bank_rank_masks[],
                               std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                               u_int64_t row_increment, int ba, volatile char** first_address, volatile char** last_address);

  int remove_aggs(int N);

  void jit_code();

  size_t count_aggs();

  void generate_frequency_based_pattern(
    std::vector<uint64_t> bank_rank_masks[], std::vector<uint64_t>& bank_rank_functions,
    u_int64_t row_function, u_int64_t row_increment, int bank_no,
    volatile char** first_address, volatile char** last_address);
};

#endif /* PATTERNBUILDER */
