#ifndef PATTERNBUILDER
#define PATTERNBUILDER

#include <asmjit/asmjit.h>

#include <algorithm>
#include <iostream>
#include <random>

#include "Fuzzer/CodeJitter.hpp"
#include "Fuzzer/HammeringPattern.hpp"
#include "Utilities/Range.hpp"

class PatternBuilder {
 private:
  HammeringPattern &pattern;

 public:
  /// default constructor that randomizes fuzzing parameters
  explicit PatternBuilder(HammeringPattern &hammering_pattern);

  void generate_frequency_based_pattern(FuzzingParameterSet &fuzzing_params);
};

#endif /* PATTERNBUILDER */
