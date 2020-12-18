#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include "Memory.hpp"
#include "DramAnalyzer.hpp"

#include <vector>
#include <Fuzzer/Aggressor.hpp>
#include <Fuzzer/AggressorAccessPattern.hpp>

std::vector<Aggressor> accesses;
std::vector<AggressorAccessPattern> agg_access_patterns;

const size_t MAX_TRIALS_PER_PATTERN = 5;
size_t trials_per_pattern = 0;

void generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
