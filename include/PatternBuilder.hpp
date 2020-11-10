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
struct Range {
 public:
  int min;
  int max;

  Range() = default;

  Range(int min, int max) : min(min), max(max) {}

  int get_random_number() {
    if (min > max)
      return -1;
    else if (min == max)
      return min;
    else
      return rand() % (max + 1 - min) + min;
  }

  int get_random_number(int max_limit) {
    int new_max = (max > max_limit) ? max_limit : max;
    return Range(min, new_max).get_random_number();
  }
};

class PatternBuilder {
 private:
  CodeJitter jitter;

  bool use_agg_only_once;

  bool use_fixed_amplitude_per_aggressor;

  bool use_unused_pair_as_dummies;

  bool use_sequential_aggressors;

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval
  int num_refresh_intervals;

  // the numbers of aggressors to be picked from during random pattern generation
  int num_aggressors;

  int agg_inter_distance;

  int agg_intra_distance;

  int num_activations;

  int agg_rounds;

  int hammer_rounds;

  Range amplitude;

  Range N_sided;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  volatile char* target_addr;

  volatile char* random_start_address;

  asmjit::StringLogger* logger;

  std::vector<volatile char*> aggressor_pairs;

  void get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices);

  void jit_hammering_code(size_t agg_rounds, uint64_t hammering_intervals);

  void encode_double_ptr_chasing(std::vector<volatile char*>& aggressors, volatile char** firstChase, volatile char** secondChase);

 public:
  /// default constructor that randomizes fuzzing parameters
  PatternBuilder(int num_activations, volatile char* target_address);

  // access the pattern that was previously created by calling generate_random_pattern
  void hammer_pattern();

  void cleanup();

  void randomize_parameters();

  void generate_random_pattern(std::vector<uint64_t> bank_rank_masks[],
                               std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                               u_int64_t row_increment, int num_activations, int ba,
                               volatile char** first_address, volatile char** last_address);
};

#endif /* PATTERNBUILDER */
