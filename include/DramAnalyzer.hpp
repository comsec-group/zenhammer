#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <inttypes.h>
#include <vector>

#include "Utilities/AsmPrimitives.hpp"

volatile char *normalize_addr_to_bank(volatile char *cur_addr, std::vector<uint64_t> &cur_bank_rank,
                                      std::vector<uint64_t> &bank_rank_functions);

uint64_t get_row_increment(uint64_t row_function);

std::vector<uint64_t> get_bank_rank(std::vector<volatile char *> &target_bank,
                                    std::vector<uint64_t> &bank_rank_functions);

uint64_t get_row_index(const volatile char *addr, uint64_t row_function);

void find_functions(std::vector<volatile char *> *banks,
                    uint64_t &row_function,
                    std::vector<uint64_t> &bank_rank_functions,
                    bool superpage_on);

uint64_t test_addr_against_bank(volatile char *addr, std::vector<volatile char *> &bank);

void find_bank_conflicts(volatile char *target, std::vector<volatile char *> *banks);

/// Measures the time between accessing two addresses.
static int inline measure_time(volatile char *a1, volatile char *a2) {
  uint64_t before, after;
  before = rdtscp();
  lfence();
  for (size_t i = 0; i < DRAMA_ROUNDS; i++) {
    *a1;
    *a2;
    clflushopt(a1);
    clflushopt(a2);
    mfence();
  }
  after = rdtscp();
  return (int) ((after - before)/DRAMA_ROUNDS);
}

#endif /* DRAMANALYZER */
