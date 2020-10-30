#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <iostream>
#include <iterator>
#include <random>

// Signature of the generated function.
typedef int (*Func)(void);

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
    return rand() % (max + 1 - min) + min;
  }

  int get_random_number(int max_limit) {
    int new_max = (max > max_limit) ? max_limit : max;
    // Check if the resulting range is valid, i.e., min <= max.
    if (new_max < min) {
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
  // runtime designed for JIT code execution
  asmjit::JitRuntime rt;
  Func fn;

  // Memory controller issues a REFRESH every 7.8us to ensure that all cells are
  // refreshed within a 64ms interval (= duration_full_refresh).
  const int duration_full_refresh = 50;

  Range num_refresh_intervals;

  Range num_hammering_pairs;

  Range num_nops;

  Range multiplicator_hammering_pairs;

  Range multiplicator_nops;

  int* alphabeticus;

 public:
  std::vector<volatile char*> aggressor_pairs;

  std::vector<volatile char*> nops;

  volatile char *d1 = nullptr;
  volatile char *d2 = nullptr;

  asmjit::StringLogger *logger;

  int activations;

  // default constructor that initializes params with default values
  PatternBuilder();

  void print_patterns(int num_patterns, int accesses_per_pattern);

  // Total duration of hammering period in us, i.e.,
  //    pi = num_refresh_intervals * duration_full_refresh;
  int get_total_duration_pi(int num_ref_intervals);

  // void write_patterns(std::string filename);

  void get_access_pattern();

  void access_pattern();

  void cleanup_pattern();

  void generate_random_pattern(volatile char* target, std::vector<uint64_t> bank_rank_masks[],
                               std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                               u_int64_t row_increment, int num_activations, int ba);

  void print_pattern();
};

#endif /* PATTERNBUILDER */
