#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>
#include <unordered_map>
#include <utility>

#include "../include/CodeJitter.hpp"

// Signature of the generated function.
typedef int (*JittedFunction)(void);

/// A range is equivalent to the mathematical notation [i,j] where i,j ∈ ℕ.
template <typename T>
struct Range {
 public:
  T min;
  T max;

  Range() = default;

  Range(T min, T max) : min(min), max(max) {}

  T get_random_number() {
    if (min > max)
      return -1;
    else if (min == max)
      return min;
    else
      return rand() % (max + 1 - min) + min;
  }

  T get_random_number(T max_limit) {
    T new_max = (max > max_limit) ? max_limit : max;
    return Range(min, new_max).get_random_number();
  }
};

class PatternBuilder {
 private:
  /// A instance of the CodeJitter that is used to generate the ASM code for the produced hammering pattern.
  CodeJitter jitter;

  /// The number of consecutive segments an aggressor can appear in the pattern.
  /// For example, if agg_frequency = 1, then an aggressor pair (A1,A2) can only be repeated once N-times within an
  /// interval where N is the randomly chosen amplitude.
  Range<int> agg_frequency;

  bool use_fixed_amplitude_per_aggressor;

  bool use_unused_pair_as_dummies;

  bool use_sequential_aggressors;

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval.
  int num_refresh_intervals;

  /// The numbers of aggressors to be picked from during random pattern generation.
  int num_aggressors;

  int agg_inter_distance;

  int agg_intra_distance;

  int num_activations_per_REF;

  int num_activations_per_REF_measured;

  int agg_rounds;

  int num_total_activations_hammering;

  int distance_to_dummy_pair;

  int hammering_strategy;

  size_t total_acts_pattern;

  Range<int> amplitude;

  Range<int> N_sided;

  std::discrete_distribution<int> N_sided_probabilities;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  volatile char* target_addr;

  volatile char* random_start_address;

  asmjit::StringLogger* logger;

  std::vector<volatile char*> aggressor_pairs;

  std::vector<volatile char*> dummy_pair;

  void get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices);

  void jit_hammering_code(size_t agg_rounds, uint64_t hammering_intervals);

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
};

#endif /* PATTERNBUILDER */
