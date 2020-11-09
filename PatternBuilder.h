#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>
#include <unordered_map>
#include <utility>

enum class FLUSHING_STRATEGY {
  // flush an accessed aggressor as soon as it has been accessed (i.e., pairs are flushed in-between)
  EARLIEST_POSSIBLE
};

static std::string to_string(FLUSHING_STRATEGY strategy) {
  std::unordered_map<FLUSHING_STRATEGY, std::string> map =
      {{FLUSHING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"}};
  return map.at(strategy);
}

enum class FENCING_STRATEGY {
  // add the fence right before the next access of the aggressor if it has been flushed before
  LATEST_POSSIBLE
};

static std::string to_string(FENCING_STRATEGY strategy) {
  std::unordered_map<FENCING_STRATEGY, std::string> map =
      {{FENCING_STRATEGY::LATEST_POSSIBLE, "LATEST_POSSIBLE"}};
  return map.at(strategy);
}

// Signature of the generated function.
typedef int (*JittedFunction)(void);

///
struct Range {
 public:
  int min;
  int max;

  Range() = default;

  Range(int min, int max) : min(min), max(max) {}

  int get_random_number() {
    if (min > max) {
      return -1;
    } else {
      return (min == max) ? min : rand() % (max + 1 - min) + min;
    }
  }

  int get_random_number(int max_limit) {
    int new_max = (max > max_limit) ? max_limit : max;
    return Range(min, new_max).get_random_number();
  }
};

class PatternBuilder {
 private:
  /// runtime for JIT code execution
  asmjit::JitRuntime rt;

  /// hammering function that was generated at runtime
  JittedFunction fn;

  bool use_agg_only_once;

  bool use_fixed_amplitude_per_aggressor;

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

  void randomize_parameters();

  void encode_double_ptr_chasing(std::vector<volatile char*>& aggressors, volatile char** firstChase, volatile char** secondChase);

 public:
  /// default constructor that randomizes fuzzing parameters
  PatternBuilder(int num_activations, volatile char* target_address);

  // access the pattern that was previously created by calling generate_random_pattern
  void hammer_pattern();

  void cleanup_and_rerandomize();

  void generate_random_pattern(std::vector<uint64_t> bank_rank_masks[],
                               std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                               u_int64_t row_increment, int num_activations, int ba,
                               volatile char** first_address, volatile char** last_address);
};

#endif /* PATTERNBUILDER */
