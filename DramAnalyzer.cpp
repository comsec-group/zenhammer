#include "DramAnalyzer.h"

#include <inttypes.h>
#include <stdlib.h>

#include <algorithm>
#include <cmath>
#include <vector>

#include "GlobalDefines.h"
#include "utils.h"

volatile char* normalize_addr_to_bank(volatile char* cur_addr, std::vector<uint64_t>& cur_bank_rank,
                                      std::vector<uint64_t>& bank_rank_functions) {
  volatile char* normalized_addr = cur_addr;
  for (size_t i = 0; i < cur_bank_rank.size(); i++) {
    // apply the bank/rank function on the given address
    uint64_t mask = ((uint64_t)normalized_addr) & bank_rank_functions[i];

    // check whether we need to normalize the address
    bool normalize = (cur_bank_rank[i] == ((mask == 0) || (mask == bank_rank_functions[i])));

    // continue with next iteration if no normalization is required
    if (!normalize) continue;

    // normalize address
    for (int b = 0; b < 64; b++) {
      if (bank_rank_functions[i] & BIT_SET(b)) {
        normalized_addr = (volatile char*)(((uint64_t)normalized_addr) ^ BIT_SET(b));
        break;
      }
    }
  }

  return normalized_addr;
}

uint64_t get_row_increment(uint64_t row_function) {
  for (size_t i = 0; i < 64; i++) {
    if (row_function & BIT_SET(i)) return BIT_SET(i);
  }
  printf("[-] no bit set for row function\n");
  return 0;
}

std::vector<uint64_t> get_bank_rank(std::vector<volatile char*>& target_bank,
                                    std::vector<uint64_t>& bank_rank_functions) {
  std::vector<uint64_t> bank_rank;
  auto addr = target_bank.at(0);
  for (size_t i = 0; i < bank_rank_functions.size(); i++) {
    uint64_t mask = ((uint64_t)addr) & bank_rank_functions[i];
    if ((mask == bank_rank_functions[i]) || (mask == 0)) {
      bank_rank.push_back(0);
    } else {
      bank_rank.push_back(1);
    }
  }
  return bank_rank;
}

// Gets the row index for a given address by considering the given row function.
uint64_t get_row_index(volatile char* addr, uint64_t row_function) {
  uint64_t cur_row = (uint64_t)addr & row_function;
  for (size_t i = 0; i < 64; i++) {
    if (row_function & (1 << i)) {
      return (cur_row >> i);
    }
  }
  return cur_row;
}

/*
 * Assumptions:
 *  1) row selection starts from higher bits than 13 (8K DRAM pages)
 *  2) single DIMM system (only bank/rank bits)
 *  3) Bank/Rank functions use at most 2 bits
 */
void find_functions(volatile char* target, std::vector<volatile char*>* banks, uint64_t& row_function,
                    std::vector<uint64_t>& bank_rank_functions) {
  size_t num_expected_fns = std::log2(NUM_BANKS);
  int num_tries = 0;
  do {
    int max_bits;
    row_function = 0;
    max_bits = (USE_SUPERPAGE) ? 30 : 21;

    for (int ba = 6; ba < NUM_BANKS; ba++) {
      auto addr = banks[ba].at(0);

      for (int b = 6; b < max_bits; b++) {
        // flip the bit at position b in the given address
        auto test_addr = (volatile char*)((uint64_t)addr ^ BIT_SET(b));
        auto time = test_addr_against_bank(test_addr, banks[ba]);
        if (time > THRESH) {
          if (b > 13) {
            row_function = row_function | BIT_SET(b);
          }
        } else {
          // it is possible that flipping this bit changes the function
          for (int tb = 6; tb < b; tb++) {
            auto test_addr2 = (volatile char*)((uint64_t)test_addr ^ BIT_SET(tb));
            time = test_addr_against_bank(test_addr2, banks[ba]);
            if (time > THRESH) {
              if (b > 13) {
                row_function = row_function | BIT_SET(b);
              }
              uint64_t new_function = 0;
              new_function = BIT_SET(b) | BIT_SET(tb);
              auto iter = std::find(bank_rank_functions.begin(), bank_rank_functions.end(), new_function);
              if (iter == bank_rank_functions.end()) {
                bank_rank_functions.push_back(new_function);
              }
            }
          }
        }
      }
    }
    num_tries++;
  } while (num_tries < 10 && bank_rank_functions.size() != num_expected_fns);
  if (num_tries == 10) {
    fprintf(stderr,
            FRED "[-] Found %zu bank/rank functions for %d banks but there should be only %zu functions. "
            "Giving up after %d tries. Exiting." NONE,
            bank_rank_functions.size(), NUM_BANKS, num_expected_fns, num_tries);
    exit(1);
  }
}

uint64_t test_addr_against_bank(volatile char* addr, std::vector<volatile char*>& bank) {
  uint64_t cumulative_times = 0;
  int times = 0;
  for (auto const& other_addr : bank) {
    if (addr != other_addr) {
      times++;
      auto ret = measure_time(addr, other_addr);
      cumulative_times += ret;
    }
  }
  return (times == 0) ? 0 : cumulative_times / times;
}

void find_bank_conflicts(volatile char* target, std::vector<volatile char*>* banks) {
  srand(time(0));
  int nr_banks_cur = 0;
  while (nr_banks_cur < NUM_BANKS) {
  reset:
    auto a1 = target + (rand() % (MEM_SIZE / 64)) * 64;
    auto a2 = target + (rand() % (MEM_SIZE / 64)) * 64;
    auto ret1 = measure_time(a1, a2);
    auto ret2 = measure_time(a1, a2);

    if ((ret1 > THRESH) && (ret2 > THRESH)) {
      bool all_banks_set = true;
      for (size_t i = 0; i < NUM_BANKS; i++) {
        if (banks[i].empty()) {
          all_banks_set = false;
        } else {
          auto bank = banks[i];
          ret1 = measure_time(a1, bank[0]);
          ret2 = measure_time(a2, bank[0]);
          if ((ret1 > THRESH) || (ret2 > THRESH)) {
            // possibly noise if only exactly one is true,
            // i.e., (ret1 > THRESH) or (ret2 > THRESH)
            goto reset;
          }
        }
      }

      // stop if we already determined all bank functions
      if (all_banks_set) return;

      // store bank functions
      for (size_t i = 0; i < NUM_BANKS; i++) {
        auto bank = &banks[i];
        if (bank->empty()) {
          bank->push_back(a1);
          bank->push_back(a2);
          nr_banks_cur++;
          break;
        }
      }
    }
  }
}
