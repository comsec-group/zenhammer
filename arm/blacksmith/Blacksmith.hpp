#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory.hpp"
#include "DramAnalyzer.hpp"

// (ugly hack) last created HammeringPattern
HammeringPattern hammering_pattern;

// (ugly hack) last created HammeringPattern
const size_t MAX_TRIALS_PER_PATTERN = 5;
size_t trials_per_pattern = 0;

void generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
