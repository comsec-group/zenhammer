#include "DramAnalyzer.hpp"

#include <cassert>
#include <cinttypes>
#include <cstdlib>
#include <algorithm>
#include <cmath>
#include <vector>
#include <unordered_set>
#include <DRAMAddr.hpp>

#include "GlobalDefines.hpp"
#include "Utilities/AsmPrimitives.hpp"

volatile char *DramAnalyzer::normalize_addr_to_bank(volatile char *cur_addr, size_t bank_no) {
  volatile char *normalized_addr = cur_addr;
  for (size_t i = 0; i < bank_rank_masks.at(bank_no).size(); i++) {
    // apply the bank/rank function on the given address
    uint64_t mask = ((uint64_t) normalized_addr) & bank_rank_functions[i];

    // check whether we need to normalize the address
    bool normalize = (bank_rank_masks.at(bank_no)[i]==((mask==0) || (mask==bank_rank_functions[i])));

    // continue with next iteration if no normalization is required
    if (!normalize) continue;

    // normalize address
    for (int b = 0; b < 64; b++) {
      if (bank_rank_functions[i] & BIT_SET(b)) {
        normalized_addr = (volatile char *) (((uint64_t) normalized_addr) ^ BIT_SET(b));
        break;
      }
    }
  }

  return normalized_addr;
}

uint64_t DramAnalyzer::get_row_increment() const {
  for (size_t i = 0; i < 64; i++) {
    if (row_function & BIT_SET(i)) return BIT_SET(i);
  }
  printf("[-] No bit set for row function\n");
  return 0;
}

std::vector<uint64_t> DramAnalyzer::get_bank_rank(std::vector<volatile char *> &target_bank) {
  std::vector<uint64_t> bank_rank;
  auto addr = target_bank.at(0);
  for (unsigned long fn : bank_rank_functions) {
    uint64_t mask = ((uint64_t) addr) & fn;
    auto value = ((mask==fn) || (mask==0)) ? 0 : 1;
    bank_rank.push_back(value);
  }
  return bank_rank;
}

// Gets the row index for a given address by considering the given row function.
uint64_t DramAnalyzer::get_row_index(const volatile char *addr) const {
  uint64_t cur_row = (uint64_t) addr & row_function;
  for (size_t i = 0; i < 64; i++) {
    if (row_function & (1UL << i)) {
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
void DramAnalyzer::find_functions(bool superpage_on) {
  size_t num_expected_fns = std::log2(NUM_BANKS);

  // this method to determine the bank/rank functions doesn't somehow work very reliable on some nodes (e.g., cn003),
  // because of that we need to choose a rather large maximum number of tries
  const int max_num_tries = 30;
  int num_tries = 0;

  do {
    bank_rank_functions.clear();
    int max_bits = (superpage_on) ? 30 : 21;
    row_function = 0;

    for (int ba = 6; ba < NUM_BANKS; ba++) {
      auto addr = banks.at(ba).at(0);

      for (int b = 6; b < max_bits; b++) {
        // flip the bit at position b in the given address
        auto test_addr = (volatile char *) ((uint64_t) addr ^ BIT_SET(b));
        auto time = test_addr_against_bank(test_addr, banks.at(ba));

        if (time > THRESH) {
          if (b > 13) {
            row_function = row_function | BIT_SET(b);
          }
          continue;
        }

        // it is possible that flipping this bit changes the function
        for (int tb = 6; tb < b; tb++) {
          auto test_addr2 = (volatile char *) ((uint64_t) test_addr ^ BIT_SET(tb));
          time = test_addr_against_bank(test_addr2, banks.at(ba));
          if (time <= THRESH) {
            continue;
          }
          if (b > 13) {
            row_function = row_function | BIT_SET(b);
          }
          uint64_t new_function = BIT_SET(b) | BIT_SET(tb);
          auto iter = std::find(bank_rank_functions.begin(), bank_rank_functions.end(), new_function);
          if (iter==bank_rank_functions.end()) {
            bank_rank_functions.push_back(new_function);
          }
        }
      }
    }
    num_tries++;
  } while (num_tries < max_num_tries // && bank_rank_functions.size()!=num_expected_fns
      );

  // TODO: Fix this
//  // we cannot continue if we couldn't determine valid bank/rank functions
//  if (bank_rank_functions.size()!=num_expected_fns) {
//    printf(
//        "[-] Found %zu bank/rank functions for %d banks, expected were %zu functions. ",
//        bank_rank_functions.size(), NUM_BANKS, num_expected_fns);
//    exit(1);
//  }

  printf("[+] Row function 0x%" PRIx64 ", row increment 0x%" PRIx64 ", and %lu bank/rank functions: ",
         row_function, get_row_increment(), bank_rank_functions.size());
  for (size_t j = 0; j < bank_rank_functions.size(); j++) {
    printf("0x%" PRIx64 " ", bank_rank_functions[j]);
    if (j==(bank_rank_functions.size() - 1)) printf("\n");
  }
}

uint64_t DramAnalyzer::test_addr_against_bank(volatile char *addr, std::vector<volatile char *> &bank) {
  uint64_t cumulative_times = 0;
  int times = 0;
  for (auto const &other_addr : bank) {
    if (addr!=other_addr) {
      times++;
      auto ret = measure_time(addr, other_addr);
      cumulative_times += ret;
    }
  }
  return (times==0) ? 0 : cumulative_times/times;
}

void DramAnalyzer::find_bank_conflicts() {
  srand(time(nullptr));
  int nr_banks_cur = 0;
  int remaining_tries = NUM_BANKS*128;  // experimentally determined, may be unprecise
  while (nr_banks_cur < NUM_BANKS) {
    reset:
    auto a1 = start_address + (rand()%(MEM_SIZE/64))*64;
    auto a2 = start_address + (rand()%(MEM_SIZE/64))*64;
    auto ret1 = measure_time(a1, a2);
    auto ret2 = measure_time(a1, a2);

    if ((ret1 > THRESH) && (ret2 > THRESH)) {
      bool all_banks_set = true;
      for (size_t i = 0; i < NUM_BANKS; i++) {
        if (banks.at(i).empty()) {
          all_banks_set = false;
        } else {
          auto bank = banks.at(i);
          ret1 = measure_time(a1, bank[0]);
          ret2 = measure_time(a2, bank[0]);
          if ((ret1 > THRESH) || (ret2 > THRESH)) {
            // possibly noise if only exactly one is true,
            // i.e., (ret1 > THRESH) or (ret2 > THRESH)
            goto reset;
          }
        }
      }

      // stop if we already determined addresses for each bank
      if (all_banks_set) return;

      // store addresses found for each bank
      assert(banks.at(nr_banks_cur).empty() && "Bank not empty");
      banks.at(nr_banks_cur).push_back(a1);
      banks.at(nr_banks_cur).push_back(a2);
      nr_banks_cur++;
    }
    if (remaining_tries==0) {
      fprintf(stderr,
              "[-] Could not find all bank/rank functions. Is the number of banks (%d) defined correctly?\n",
              (int) NUM_BANKS);
      exit(1);
    }
    remaining_tries--;
  }

  printf("[+] Found bank conflicts.\n");
  for (auto &bank : banks) {
    find_targets(bank, NUM_TARGETS);
  }
  printf("[+] Populated addresses from different banks.\n");
}

void DramAnalyzer::find_targets(std::vector<volatile char *> &target_bank, size_t size) {
  // create an unordered set of the addresses in the target bank for a quick lookup
  // std::unordered_set<volatile char*> tmp; tmp.insert(target_bank.begin(), target_bank.end());
  std::unordered_set<volatile char *> tmp(target_bank.begin(), target_bank.end());
  target_bank.clear();
  size_t num_repetitions = 5;
  srand(time(nullptr));
  while (tmp.size() < size) {
    auto a1 = start_address + (rand()%(MEM_SIZE/64))*64;
    if (tmp.count(a1) > 0) continue;
    uint64_t cumulative_times = 0;
    for (size_t i = 0; i < num_repetitions; i++) {
      for (const auto &addr : tmp) {
        cumulative_times += measure_time(a1, addr);
      }
    }
    cumulative_times /= num_repetitions;
    if ((cumulative_times/tmp.size()) > THRESH) {
      tmp.insert(a1);
      target_bank.push_back(a1);
    }
  }
}

DramAnalyzer::DramAnalyzer(volatile char *target) : start_address(target) {
  banks = std::vector<std::vector<volatile char *>>(NUM_BANKS, std::vector<volatile char *>());
  bank_rank_masks = std::vector<std::vector<uint64_t>>(NUM_BANKS, std::vector<uint64_t>());
}

const std::vector<std::vector<volatile char *>> &DramAnalyzer::get_banks() const {
  return banks;
}

void DramAnalyzer::find_bank_rank_masks() {
  for (size_t j = 0; j < NUM_BANKS; j++) {
    bank_rank_masks[j] = get_bank_rank(banks.at(j));
  }
}

std::vector<uint64_t> DramAnalyzer::get_bank_rank_functions() {
  return bank_rank_functions;
}

