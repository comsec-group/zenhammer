#include "Memory/DramAnalyzer.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Memory/ConflictCluster.hpp"
#include "Utilities/CustomRandom.hpp"
#include "Utilities/Helper.hpp"

#include <cassert>
#include <unordered_set>
#include <iostream>

void DramAnalyzer::find_bank_conflicts() {
  size_t nr_banks_cur = 0;
  int remaining_tries = NUM_BANKS*256;  // experimentally determined, may be unprecise
  while (nr_banks_cur < NUM_BANKS && remaining_tries > 0) {
    reset:
    remaining_tries--;
    auto a1 = start_address + (dist(cr.gen)%(MEM_SIZE/64))*64;
    auto a2 = start_address + (dist(cr.gen)%(MEM_SIZE/64))*64;
    auto ret1 = measure_time(a1, a2);
    auto ret2 = measure_time(a1, a2);

    if ((ret1 > BK_CONF_THRESH) && (ret2 > BK_CONF_THRESH)) {
      bool all_banks_set = true;
      for (size_t i = 0; i < NUM_BANKS; i++) {
        if (banks.at(i).empty()) {
          all_banks_set = false;
        } else {
          auto bank = banks.at(i);
          ret1 = measure_time(a1, bank[0]);
          ret2 = measure_time(a2, bank[0]);
          if ((ret1 > BK_CONF_THRESH) || (ret2 > BK_CONF_THRESH)) {
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
    auto a1 = start_address + (dist(cr.gen)%(MEM_SIZE/64))*64;
    if (tmp.count(a1) > 0) continue;
    uint64_t cumulative_times = 0;
    for (size_t i = 0; i < num_repetitions; i++) {
      for (const auto &addr : tmp) {
        cumulative_times += measure_time(a1, addr);
      }
    }
    cumulative_times /= num_repetitions;
    if ((cumulative_times/tmp.size()) > BK_CONF_THRESH) {
      tmp.insert(a1);
      target_bank.push_back(a1);
    }
  }
}

DramAnalyzer::DramAnalyzer(volatile char *target, ConflictCluster &cc) :
//  row_function(0), start_address(target) {
  start_address(target),
  cc(cc),
  has_exp_cfg(false),
  exp_cfg(ExperimentConfig())
  {
  cr = CustomRandom();
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
  banks = std::vector<std::vector<volatile char *>>(NUM_BANKS, std::vector<volatile char *>());
}

size_t DramAnalyzer::count_acts_per_ref() {
  if (!has_exp_cfg) {
      exp_cfg = ExperimentConfig(execution_mode::ALTERNATING, 8000, 2, 8, true, true);
      has_exp_cfg = true;
  }
  return count_acts_per_ref(exp_cfg);
}

// TODO: (future work) use REFab detection and then remove this distribution from (any_bgbk,any_bgbk) distribution to get REFsb only
size_t DramAnalyzer::count_acts_per_ref(ExperimentConfig &experiment_cfg) {
  if (!has_exp_cfg) {
      this->exp_cfg = experiment_cfg;
      has_exp_cfg = true;
  }
  Logger::log_info("Determining the number of activations per REF(sb|ab) interval...");

  uint64_t t_start;
  uint64_t t_end;

  const size_t NUM_ADDR_PAIRS_TO_BE_TESTED = 4;
  const size_t NUM_ACCESSES_PER_MEASUREMENT_RND = 2;

  uint64_t total_ref_timing = 0;
  uint64_t total_num_over_th = 0;
  uint64_t total_cnt_acts = 0;

  for (size_t it_addr_pair = 1; it_addr_pair <= NUM_ADDR_PAIRS_TO_BE_TESTED; ++it_addr_pair) {
//    std::vector<uint64_t> timing;
//    timing.resize(exp_cfg.num_measurement_rounds, 0);

    auto addr_pair = cc.get_simple_dram_addresses(exp_cfg.num_sync_rows, exp_cfg.row_distance,
        exp_cfg.row_origin_same_bg, exp_cfg.row_origin_same_bk);

    std::vector<volatile char *> addresses;
    addresses.reserve(addr_pair.size());

    // get vaddr, then bring array into cache
    for (size_t k = 0; k < addr_pair.size(); ++k) {
      addresses.push_back(addr_pair[k].vaddr);
      *addresses[k];
      clflushopt(addresses[k]);
//      std::cout << "# addr[" << k << "]: "
//                << addr_pair[k].bg << ","
//                << addr_pair[k].bk << ","
//                << addr_pair[k].row_id
//                << std::endl;
    }
    sfence();

//    uint64_t total_cnt_timing = 0;
    uint64_t cur_timing;
    if (exp_cfg.exec_mode == execution_mode::ALTERNATING) {
      // initial value for continuous timing measurement
      size_t i_last = 0;
      t_end = rdtscp();
      lfence();
      // we keep this loop very short and tight to not negatively affect performance
      size_t addr_idx = 0;
      for (size_t i = 0; i < exp_cfg.num_measurement_rounds; i++) {
        sfence();
        for (size_t j = addr_idx; j < (addr_idx + NUM_ACCESSES_PER_MEASUREMENT_RND); j++) {
          *addresses[j];
          clflushopt(addresses[j]);
        }
        t_start = t_end;
        lfence();
        t_end = rdtscp();
        cur_timing = (t_end - t_start);
//        timing[i] = cur_timing;
//        total_cnt_timing += cur_timing;
        if (cur_timing > MIN_REF_THRESH && (i-i_last) > 10) {
          total_ref_timing += cur_timing;
          total_num_over_th++;
          total_cnt_acts += i-i_last;
          i_last = i;
          lfence();
          t_end = rdtscp();
        }
        lfence();
        addr_idx = (addr_idx + NUM_ACCESSES_PER_MEASUREMENT_RND) % exp_cfg.num_sync_rows;
      }
    } else if (exp_cfg.exec_mode == execution_mode::BATCHED) {
        Logger::log_error("execution_mode::BATCHED is unsupported!");
        exit(EXIT_FAILURE);
//      t_end = rdtscp();
//      lfence();
//      assert(exp_cfg.num_sync_rows == 4 && NUM_ACCESSES_PER_MEASUREMENT_RND == 2 && "BATCHED mode failed!");
//      const size_t half = exp_cfg.num_measurement_rounds/2;
//      for (size_t i = 0; i < exp_cfg.num_measurement_rounds; i++) {
//        sfence();
//        for (size_t j = 0; j < NUM_ACCESSES_PER_MEASUREMENT_RND; j++) {
//          auto addr_idx = (((i > half)<<1)+j)%exp_cfg.num_sync_rows;
//          *addresses[addr_idx];
//          clflushopt(addresses[addr_idx]);
//        }
//        t_start = t_end;
//        lfence();
//        t_end = rdtscp();
////        timing[i] = t_end - t_start;
//        lfence();
//      }
    }

//    std::cout << "AVG_timing: " << total_cnt_timing/exp_cfg.num_measurement_rounds << std::endl;
//    auto total_cnt2 = std::accumulate(timing.begin(), timing.end(), 0ULL);
//    std::cout << "AVG_timing2: " << total_cnt2/exp_cfg.num_measurement_rounds << std::endl;
  }

  auto avg_acts = ((total_cnt_acts/total_num_over_th)>>1)<<1;
//  std::cout << "AVG_acts: " << avg_acts << std::endl;
  ref_threshold_low = (MIN_REF_THRESH+(total_ref_timing/total_num_over_th))/2;
//  std::cout << "total_ref_timing: " << ref_threshold_low << std::endl;

  return avg_acts;
}

size_t DramAnalyzer::get_ref_threshold() const {
  return ref_threshold_low;
}

int inline DramAnalyzer::measure_time(volatile char *a1, volatile char *a2) {
    const size_t NUM_DRAMA_ROUNDS = 1000;
    uint64_t before, after;
    before = rdtscp();
    lfence();
    for (size_t i = 0; i < NUM_DRAMA_ROUNDS; i++) {
        (void)*a1;
        (void)*a2;
        clflushopt(a1);
        clflushopt(a2);
        mfence();
    }
    after = rdtscp();
    return (int) ((after - before)/NUM_DRAMA_ROUNDS);
}
