#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#ifdef ENABLE_JITTING
#include <asmjit/asmjit.h>
#endif

#include <algorithm>
#include <iostream>
#include <random>

#include "Utilities/Range.hpp"
#include "Aggressor.hpp"
#include "AggressorAccessPattern.hpp"

class PatternBuilder {
 private:
  std::mt19937 gen;

 public:
  /// default constructor that randomizes fuzzing parameters
  explicit PatternBuilder();

  void generate_frequency_based_pattern(FuzzingParameterSet &fuzzing_params, std::vector<Aggressor> &accesses,
                                        std::vector<AggressorAccessPattern> &agg_access_patterns);

  size_t get_random_gaussian(std::vector<int> &list);

  static void remove_smaller_than(std::vector<int> &vec, int N);

  static int all_slots_full(size_t offset, size_t period, int pattern_length, std::vector<Aggressor> &aggs);

  static void fill_slots(size_t start_period,
                         size_t period,
                         size_t amplitude,
                         std::vector<Aggressor> &aggressors,
                         std::vector<Aggressor> &accesses,
                         size_t pattern_length);
};

#endif /* PATTERNBUILDER */
