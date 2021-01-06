#include "DramAnalyzer.hpp"

#include <cassert>
#include <cinttypes>
#include <cstdlib>
#include <algorithm>
#include <utility>
#include <vector>
#include <unordered_set>
#include <sstream>

#include "GlobalDefines.hpp"

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
  Logger::log_error("No bit set for row function.");
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

struct FunctionSet {
  uint64_t row_func{};
  std::vector<uint64_t> br_functions;

  FunctionSet() = default;

  FunctionSet(uint64_t row_fn, std::vector<uint64_t> bank_rank_fn)
      : row_func(row_fn), br_functions(std::move(bank_rank_fn)) {}

  std::string get_string() {
    std::stringstream ss;
    for (auto &f : br_functions) ss << f << "|";
    ss << row_func;
    return ss.str();
  }

  void pretty_print() {
    Logger::log_info("Found candidate bank/rank and row function:");
    Logger::log_data(string_format("Row function 0x%" PRIx64, row_func));
    std::stringstream ss;
    ss << "Bank/rank functions (" << br_functions.size() << "): ";
    for (auto bank_rank_function : br_functions) {
      ss << "0x" << std::hex << bank_rank_function << " ";
    }
    Logger::log_data(ss.str());
  }
};

/*
 * Assumptions:
 *  1) row selection starts from higher bits than 13 (8K DRAM pages)
 *  2) single DIMM system (only bank/rank bits)
 *  3) Bank/Rank functions use at most 2 bits
 */
void DramAnalyzer::find_functions(bool superpage_on) {
//  size_t num_expected_fns = std::log2(NUM_BANKS);

  // this method to determine the bank/rank functions doesn't somehow work very reliable on some nodes (e.g., cn003),
  // because of that we need to choose a rather large maximum number of tries
  const int max_num_tries = 20;
  int num_tries = 0;

  std::unordered_map<std::string, FunctionSet> candidates;
  std::unordered_map<std::string, int> candidates_count;
  int max_count = 0;

  do {
    bank_rank_functions.clear();
    row_function = 0;
    int max_bits = (superpage_on) ? 30 : 21;

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

    FunctionSet fs(row_function, bank_rank_functions);
    int count = (candidates_count.count(fs.get_string()) > 0) ? candidates_count[fs.get_string()] + 1 : 1;
    max_count = std::max(count, max_count);
    candidates[fs.get_string()] = fs;
    candidates_count[fs.get_string()] = count;
    fs.pretty_print();

    // stop if guesses seem to be correct
    if ((num_tries==3 && candidates.size()==1) || (num_tries > 4 && max_count > 0.7*candidates.size())) {
      break;
    }

  } while (num_tries < max_num_tries);

  // use the row_function/bank_rank_functions that was determined most of the time as the function ('best guess')
  std::string best_str;
  for (const auto& candidate_pair : candidates_count) {
    if (candidate_pair.second == max_count) {
      best_str = candidate_pair.first;
      break;
    }
  }
  row_function = candidates[best_str].row_func;
  bank_rank_functions = candidates[best_str].br_functions;

  Logger::log_info("Found bank/rank and row function:");
  Logger::log_data(string_format("Row function: 0x%" PRIx64, row_function));
  Logger::log_data(string_format("Row increment: 0x%" PRIx64, get_row_increment()));
  std::stringstream ss;
  ss << "Bank/rank functions (" << bank_rank_functions.size() << "): ";
  for (auto bank_rank_function : bank_rank_functions) {
    ss << "0x" << std::hex << bank_rank_function << " ";
  }
  Logger::log_data(ss.str());
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
  int remaining_tries = NUM_BANKS*256;  // experimentally determined, may be unprecise
  while (nr_banks_cur < NUM_BANKS && remaining_tries > 0) {
    reset:
    remaining_tries--;
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
      Logger::log_error(string_format(
          "Could not find conflicting address sets. Is the number of banks (%d) defined correctly?",
          (int) NUM_BANKS));
      exit(1);
    }
  }

  Logger::log_info("Found bank conflicts.");
  for (auto &bank : banks) {
    find_targets(bank, NUM_TARGETS);
  }
  Logger::log_info("Populated addresses from different banks.");
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

void DramAnalyzer::load_known_functions(int num_ranks) {
  if (num_ranks==1) {
    bank_rank_functions = std::vector<uint64_t>({0x2040, 0x24000, 0x48000, 0x90000});
    row_function = 0x3ffe0000;
  } else if (num_ranks==2) {
    bank_rank_functions = std::vector<uint64_t>({0x2040, 0x44000, 0x88000, 0x110000, 0x220000});
    row_function = 0x3ffc0000;
  } else {
    Logger::log_error("Cannot load bank/rank and row function if num_ranks is not 1 or 2.");
    exit(1);
  }

  Logger::log_info("Loaded bank/rank and row function:");
  Logger::log_data(string_format("Row function 0x%" PRIx64, row_function));
  Logger::log_data(string_format("Row increment 0x%" PRIx64, get_row_increment()));
  std::stringstream ss;
  ss << "Bank/rank functions (" << bank_rank_functions.size() << "): ";
  for (auto bank_rank_function : bank_rank_functions) {
    ss << "0x" << std::hex << bank_rank_function << " ";
  }
  Logger::log_data(ss.str());
}
