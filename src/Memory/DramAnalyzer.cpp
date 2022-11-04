#include "Memory/DramAnalyzer.hpp"
#include "Memory/DRAMAddr.hpp"

#include <cassert>
#include <unordered_set>
#include <iostream>

void DramAnalyzer::find_bank_conflicts() {
  size_t nr_banks_cur = 0;
  int remaining_tries = NUM_BANKS*256;  // experimentally determined, may be unprecise
  while (nr_banks_cur < NUM_BANKS && remaining_tries > 0) {
    reset:
    remaining_tries--;
    auto a1 = start_address + (dist(gen)%(MEM_SIZE/64))*64;
    auto a2 = start_address + (dist(gen)%(MEM_SIZE/64))*64;
    auto ret1 = measure_time(a1, a2);
    auto ret2 = measure_time(a1, a2);

    if ((ret1 > CACHE_THRESH) && (ret2 > CACHE_THRESH)) {
      bool all_banks_set = true;
      for (size_t i = 0; i < NUM_BANKS; i++) {
        if (banks.at(i).empty()) {
          all_banks_set = false;
        } else {
          auto bank = banks.at(i);
          ret1 = measure_time(a1, bank[0]);
          ret2 = measure_time(a2, bank[0]);
          if ((ret1 > CACHE_THRESH) || (ret2 > CACHE_THRESH)) {
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
    find_targets(bank);
  }
  Logger::log_info("Populated addresses from different banks.");
}

void DramAnalyzer::find_targets(std::vector<volatile char *> &target_bank) {
  // create an unordered set of the addresses in the target bank for a quick lookup
  // std::unordered_set<volatile char*> tmp; tmp.insert(target_bank.begin(), target_bank.end());
  std::unordered_set<volatile char *> tmp(target_bank.begin(), target_bank.end());
  target_bank.clear();
  size_t num_repetitions = 5;
  while (tmp.size() < 10) {
    auto a1 = start_address + (dist(gen)%(MEM_SIZE/64))*64;
    if (tmp.count(a1) > 0) continue;
    uint64_t cumulative_times = 0;
    for (size_t i = 0; i < num_repetitions; i++) {
      for (const auto &addr : tmp) {
        cumulative_times += measure_time(a1, addr);
      }
    }
    cumulative_times /= num_repetitions;
    if ((cumulative_times/tmp.size()) > CACHE_THRESH) {
      tmp.insert(a1);
      target_bank.push_back(a1);
    }
  }
}

DramAnalyzer::DramAnalyzer(volatile char *target) :
//  row_function(0), start_address(target) {
  start_address(target) {
  std::random_device rd;
  gen = std::mt19937(rd());
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
  banks = std::vector<std::vector<volatile char *>>(NUM_BANKS, std::vector<volatile char *>());
}

//void DramAnalyzer::load_known_functions(int num_ranks) {
//  if (num_ranks==1) {
//    bank_rank_functions = std::vector<uint64_t>({0x2040, 0x24000, 0x48000, 0x90000});
//    row_function = 0x3ffe0000;
//  } else if (num_ranks==2) {
//    bank_rank_functions = std::vector<uint64_t>({0x2040, 0x44000, 0x88000, 0x110000, 0x220000});
//    row_function = 0x3ffc0000;
//  } else {
//    Logger::log_error("Cannot load bank/rank and row function if num_ranks is not 1 or 2.");
//    exit(1);
//  }
//
//  Logger::log_info("Loaded bank/rank and row function:");
//  Logger::log_data(format_string("Row function 0x%" PRIx64, row_function));
//  std::stringstream ss;
//  ss << "Bank/rank functions (" << bank_rank_functions.size() << "): ";
//  for (auto bank_rank_function : bank_rank_functions) {
//    ss << "0x" << std::hex << bank_rank_function << " ";
//  }
//  Logger::log_data(ss.str());
//}

size_t DramAnalyzer::count_acts_per_ref() {
  size_t skip_first_N = 50;
//  volatile char *a = banks.at(0).at(0);
//  volatile char *b = banks.at(0).at(1);

  volatile char *a = (volatile char*)DRAMAddr(0, 2, 0).to_virt();
  volatile char *b = (volatile char*)DRAMAddr(1, 2, 0).to_virt();

  Logger::log_debug(format_string("pointers used for count_acts_per_ref: %p\n%p", a, b));

  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before, after, count = 0, count_old = 0;
  (void)*a;
  (void)*b;

  auto compute_std = [](std::vector<uint64_t> &values, uint64_t running_sum, size_t num_numbers) {
    double mean = static_cast<double>(running_sum)/static_cast<double>(num_numbers);
    double var = 0;
    for (const auto &num : values) {
      if (static_cast<double>(num) < mean) continue;
      var += std::pow(static_cast<double>(num) - mean, 2);
    }
    auto val = std::sqrt(var/static_cast<double>(num_numbers));
    return val;
  };

  size_t cnt200s = 0;
  for (size_t i = 0;; i++) {
    clflushopt(a);
    clflushopt(b);
    mfence();
    before = rdtscp();
    lfence();
    (void)*a;
    (void)*b;
    after = rdtscp();
    count++;
    if ((after - before) > 700) {
      if (i > skip_first_N && count_old!=0) {
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
//        std::cout << value << "\n";
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 1 -> then stop collecting measurements
        if ((acts.size()%200)==0) {
          cnt200s++;
          if (cnt200s == 5)
            break;
//          std::cout << std::endl;
          if (compute_std(acts, running_sum, acts.size())<3.0) {
            break;
          }
        }
      }
      count_old = count;
    }
  }

  auto activations = (running_sum/acts.size());
  Logger::log_info("Determined the number of possible ACTs per refresh interval.");
  Logger::log_data(format_string("num_acts_per_tREFI: %lu", activations));

  return activations;
}
