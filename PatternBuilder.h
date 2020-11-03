#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>

// Signature of the generated function.
typedef int (*JittedFunction)(int);

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

/// A wrapper for achieving the same as %02d in printf would do.
/// Taken from https://stackoverflow.com/a/2839616/3017719.
struct FormattedNumber {
  FormattedNumber() {}
  FormattedNumber(char f, int w) : fill(f), width(w) {}
  char fill = '0';
  int width = 2;
};

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
    printf("[DEBUG] new_max: %d\n", new_max);
    int n2 = Range(min, new_max / 2).get_random_number() * 2;
    printf("[DEBUG] n2: %d\n", n2);
    return n2;
  }

  int get_random_number(int max_limit) {
    int new_max = (max > max_limit) ? max_limit : max;
    if (min == new_max) {
      return min;
    } else if (new_max < min) {
      printf("[-] Could not determine random number in malformed range (%d,%d). Skipping choice.\n", min, new_max);
      return -1;
    }
    return rand() % (new_max + 1 - min) + min;
  }
};

/**
 * @brief
 * Generates hammering patterns by taking the following parameters into account
 *
 */
class PatternBuilder {
 private:
  // runtime for JIT code execution
  asmjit::JitRuntime rt;

  // hammering function that was generated at runtime
  JittedFunction fn;

  // MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval
  const int duration_full_refresh = 64;

  Range num_refresh_intervals;

  Range num_hammering_pairs;

  Range num_nops;

  Range multiplicator_hammering_pairs;

  Range multiplicator_nops;

  asmjit::StringLogger* logger;

  void get_random_indices(int max, size_t num_indices, std::vector<size_t>& indices);

 public:
  std::vector<volatile char*> aggressor_pairs;

  std::vector<volatile char*> nops;

  // default constructor that initializes params with default values
  PatternBuilder();

  void print_patterns(int num_patterns, int accesses_per_pattern);

  // Total duration of hammering period in us: pi = num_refresh_intervals * duration_full_refresh;
  int get_total_duration_pi(int num_ref_intervals);

  void access_pattern(int acts);

  void cleanup_pattern();

  void generate_random_pattern(volatile char* target, std::vector<uint64_t> bank_rank_masks[],
                               std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                               u_int64_t row_increment, int num_activations, int ba);

  void jit_hammering_code(size_t agg_rounds);
};

#endif /* PATTERNBUILDER */
