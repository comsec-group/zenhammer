#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory.hpp"
#include "DramAnalyzer.hpp"

// (ugly hack) last created HammeringPattern
HammeringPattern hammering_pattern;

// how often we try the same pattern at a different location (i.e., other DRAM rows)
size_t PROBES_PER_PATTERN = NUM_BANKS/4;

// how often we repeat hammering the same pattern at the same location
int REPS_PER_PATTERN = 1;

size_t trials_per_pattern = 0;

int main(int argc, char **argv);

void print_metadata();

void generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses);

void hammer(std::vector<volatile char *> &aggressors);

void hammer_sync(std::vector<volatile char *> &aggressors, int acts,
                 volatile char *d1, volatile char *d2);

void n_sided_frequency_based_hammering(Memory &memory, DramAnalyzer &dram_analyzer, int acts);

void n_sided_hammer(Memory &memory, DramAnalyzer &dram_analyzer, int acts);

size_t count_acts_per_ref(const std::vector<std::vector<volatile char *>> &banks);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
