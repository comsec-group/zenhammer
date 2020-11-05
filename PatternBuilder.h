#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>
#include <utility>

// Signature of the generated function.
typedef int (*JittedFunction)(void);

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

  // int get_random_even_number() {
  //   int new_max = ((max % 2) == 0) ? max : (max - 1);
  //   int n2 = Range(min, new_max / 2).get_random_number() * 2;
  //   return n2;
  // }

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

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval
  const int duration_full_refresh = 64;

  int num_refresh_intervals;

  int num_hammering_pairs;

  int num_nops;

  Range multiplicator_hammering_pairs;

  Range multiplicator_nops;

  int agg_inter_distance;

  int agg_intra_distance;

  int num_activations;

  int agg_rounds;

  volatile char* target_addr;

  volatile char* random_start_address;

  asmjit::StringLogger* logger;

  std::vector<volatile char*> aggressor_pairs;

  std::vector<volatile char*> nops;

  void get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices);

  void jit_hammering_code(size_t agg_rounds, uint64_t hammering_intervals);

  void randomize_parameters();

 public:
  /// default constructor that randomizes fuzzing parameters
  PatternBuilder(int num_activations, volatile char* target_address);

  // Total duration of hammering period in us: pi = num_refresh_intervals * duration_full_refresh;
  int get_total_duration_pi(int num_ref_intervals);

  // access the pattern that was previously created by calling generate_random_pattern
  void hammer_and_improve_params();

  void cleanup_and_rerandomize();

  std::pair<volatile char*, volatile char*>
  generate_random_pattern(std::vector<uint64_t> bank_rank_masks[],
                          std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                          u_int64_t row_increment, int num_activations, int ba);
};

#endif /* PATTERNBUILDER */
