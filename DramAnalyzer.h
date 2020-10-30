#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <inttypes.h>

#include <vector>

volatile char* normalize_addr_to_bank(volatile char* cur_addr, std::vector<uint64_t>& cur_bank_rank,
                                      std::vector<uint64_t>& bank_rank_functions);

uint64_t get_row_increment(uint64_t row_function);

std::vector<uint64_t> get_bank_rank(std::vector<volatile char*>& target_bank,
                                    std::vector<uint64_t>& bank_rank_functions);

uint64_t get_row_index(volatile char* addr, uint64_t row_function);

void find_functions(volatile char* target, std::vector<volatile char*>* banks, uint64_t& row_function,
                    std::vector<uint64_t>& bank_rank_functions);

uint64_t test_addr_against_bank(volatile char* addr, std::vector<volatile char*>& bank);

void find_bank_conflicts(volatile char* target, std::vector<volatile char*>* banks);

#endif /* DRAMANALYZER */
