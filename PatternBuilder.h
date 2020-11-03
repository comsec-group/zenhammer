#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>
#include <utility>

// Signature of the generated function.
typedef int (*JittedFunction)(void);

/// Takes iterators (start, end) and returns a random element.
/// Taken from https://stackoverflow.com/a/16421677/3017719.
template <typename Iter>
Iter select_randomly(Iter start, Iter end) {
  static std::random_device rd;
  static std::mt19937 gen(rd());
  std::uniform_int_distribution<> dis(0, std::distance(start, end) - 1);
  std::advance(start, dis(gen));
  return start;
}

struct Range {
  int min;
  int max;

  Range();

  Range(int min, int max) : min(min), max(max) {}

  int get_random_number() {
    return (min == max) ? min : rand() % (max + 1 - min) + min;
  }

  int get_random_even_number() {
    int new_max = ((max % 2) == 0) ? max : (max - 1);
    int n2 = Range(min, new_max / 2).get_random_number() * 2;
    return n2;
  }

  int get_random_number(int max_limit) {
    int new_max = (max > max_limit) ? max_limit : max;
    if (min == new_max) {
      return min;
    } else if (new_max < min) {
      printf("[-] Could not determine random number in malformed range (%d,%d). Exiting.\n", min, new_max);
      exit(1);
    } else {
      return rand() % (new_max + 1 - min) + min;
    }
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

  int multiplicator_hammering_pairs;

  int multiplicator_nops;

  int agg_inter_distance;

  int agg_intra_distance;

  int num_activations;

  int agg_rounds;

  asmjit::StringLogger* logger;

  void get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices);

  void jit_hammering_code(size_t agg_rounds, uint64_t hammering_intervals);

  void randomize_parameters();

 public:
  std::vector<volatile char*> aggressor_pairs;

  std::vector<volatile char*> nops;

  /// default constructor that initializes ranges with default values
  PatternBuilder(int num_activations);

  // Total duration of hammering period in us: pi = num_refresh_intervals * duration_full_refresh;
  int get_total_duration_pi(int num_ref_intervals);

  void access_pattern();

  void cleanup_and_rerandomize();

  std::pair<volatile char*, volatile char*>
  generate_random_pattern(volatile char* target, std::vector<uint64_t> bank_rank_masks[],
                          std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                          u_int64_t row_increment, int num_activations, int ba);
};

#endif /* PATTERNBUILDER */
