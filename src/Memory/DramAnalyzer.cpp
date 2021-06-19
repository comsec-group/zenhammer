#include "Memory/DramAnalyzer.hpp"

#include <sys/mman.h>
#include <chrono>
#include <cassert>
#include <cstdlib>
#include <algorithm>
#include <unordered_set>

#include "GlobalDefines.hpp"
#include "Utilities/Logger.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"

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
      Logger::log_error(format_string(
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

DramAnalyzer::DramAnalyzer(volatile char *target) : row_function(0), start_address(target) {
  banks = std::vector<std::vector<volatile char *>>(NUM_BANKS, std::vector<volatile char *>());
  bank_rank_masks = std::vector<std::vector<uint64_t>>(NUM_BANKS, std::vector<uint64_t>());
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
  Logger::log_data(format_string("Row function 0x%" PRIx64, row_function));
  std::stringstream ss;
  ss << "Bank/rank functions (" << bank_rank_functions.size() << "): ";
  for (auto bank_rank_function : bank_rank_functions) {
    ss << "0x" << std::hex << bank_rank_function << " ";
  }
  Logger::log_data(ss.str());
}

size_t DramAnalyzer::count_acts_per_ref() {
  size_t skip_first_N = 50;
  volatile char *a = banks.at(0).at(0);
  volatile char *b = banks.at(0).at(1);
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before = 0, after = 0, count = 0, count_old = 0;
  *a;
  *b;

  auto compute_std = [](std::vector<uint64_t> &values, uint64_t running_sum, size_t num_numbers) {
    size_t mean = running_sum/num_numbers;
    uint64_t var = 0;
    for (const auto &num : values) {
      var += std::pow(num - mean, 2);
    }
    return std::sqrt(var/num_numbers);
  };

  for (size_t i = 0;; i++) {
    clflushopt(a);
    clflushopt(b);
    mfence();
    before = rdtscp();
    lfence();
    *a;
    *b;
    after = rdtscp();
    count++;
    if ((after - before) > 1000) {
      if (i > skip_first_N && count_old!=0) {
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 0 -> then stop collecting measurements
        if ((acts.size()%200)==0 && compute_std(acts, running_sum, acts.size())==0) break;
      }
      count_old = count;
    }
  }

  auto activations = (running_sum/acts.size());
  Logger::log_info("Determined the number of possible ACTs per refresh interval.");
  Logger::log_data(format_string("num_acts_per_tREFI: %lu", activations));

  return activations;
}
