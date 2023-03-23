#include "Memory/DramAnalyzer.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Memory/ConflictCluster.hpp"
#include "Utilities/CustomRandom.hpp"
#include "Utilities/Helper.hpp"

#include <cassert>
#include <unordered_set>
#include <iostream>

// note that setting LOG_TIMING 1 affects the generated avg acts-per-ref value
#define LOG_TIMING 0

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

DramAnalyzer::DramAnalyzer(volatile char *target, ConflictCluster &cc)
    : start_address(target),
      cc(cc) {
  cr = CustomRandom();
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
  banks = std::vector<std::vector<volatile char *>>(NUM_BANKS, std::vector<volatile char *>());
}

size_t DramAnalyzer::count_acts_per_ref() {
  auto exp_cfg = ExperimentConfig();
  exp_cfg.exec_mode = execution_mode::ALTERNATING;
  exp_cfg.num_measurement_reps = 10'000;
  exp_cfg.num_measurement_rounds = 10;
  exp_cfg.num_accesses_per_round = 2;
  exp_cfg.num_sync_rows = 2;
  exp_cfg.row_distance = 4;
  exp_cfg.min_ref_thresh = 750;
  exp_cfg.row_origin_same_bg = true;
  exp_cfg.row_origin_same_bk = true;
  return count_acts_per_ref(exp_cfg);
}

// TODO: (future work) use REFab detection and then remove this distribution from (any_bgbk,any_bgbk) distribution to
// get REFsb only
size_t DramAnalyzer::count_acts_per_ref(const ExperimentConfig &exp_cfg) {
  Logger::log_info("Determining the number of activations per REF(sb|ab) interval...");

  if (exp_cfg.exec_mode == execution_mode::BATCHED) {
    // BATCHED means ACCESS all addresses, then FLUSH all addresses (2 loops)
    Logger::log_error("execution_mode::BATCHED is unsupported!");
    exit(EXIT_FAILURE);
  }

  uint64_t t_start;
  uint64_t t_end;
  uint64_t total_ref_timing = 0;
  uint64_t total_num_over_th = 0;
  uint64_t total_cnt_act_rnds = 0;
  uint64_t cur_timing;

  size_t i_diff;
  size_t addr_idx;

#if LOG_TIMING
  FILE *f = fopen("logfile_timing", "w");
  if (f == nullptr) {
    exit(EXIT_FAILURE);
  }
  auto BUFFERSIZE = 2*(1<<20);  // 2 KiB
  char buf[BUFFERSIZE];
  setvbuf(f, buf, _IOFBF, BUFFERSIZE);
#endif

  std::vector<volatile char *> addresses;
  addresses.reserve(exp_cfg.num_sync_rows);

  for (size_t it_addr_pair = 1; it_addr_pair <= exp_cfg.num_measurement_rounds; ++it_addr_pair) {
      auto addr_pair = cc.get_simple_dram_addresses(
        exp_cfg.num_sync_rows, 
        exp_cfg.row_distance,
        exp_cfg.row_origin_same_bg, 
        exp_cfg.row_origin_same_bk);

      // get vaddr, then bring array into cache (but not address array is pointing to)
      addresses.clear();
      printf("# addr_pair = %ld\n", it_addr_pair-1);
      for (size_t k = 0; k < addr_pair.size(); ++k) {
        addresses.push_back(addr_pair[k].vaddr);
        *addresses[k];
        clflushopt(addresses[k]);
        printf("addr[%ld] = 0x%p, bg=%ld, bk=%ld, row=%ld\n", 
          k, addr_pair[k].vaddr, addr_pair[k].bg, addr_pair[k].bk, addr_pair[k].row_id);
      }
      printf("---\n");

      // make sure flushing finished before we start
      sfence();

      if (exp_cfg.exec_mode == execution_mode::ALTERNATING) {
        i_diff = 0;
        addr_idx = 0;
        // initial value for continuous timing measurement
        t_end = rdtscp();
        lfence();
        // we keep this loop very short and tight to not negatively affect performance
        for (size_t i = 0; i < exp_cfg.num_measurement_reps; i++, i_diff++) {
          // make sure flushing finished before starting next round
          sfence();
          const size_t max = (addr_idx + exp_cfg.num_accesses_per_round);
          for (; addr_idx < max; addr_idx++) {
            // ACCESS, FLUSH
            *addresses[addr_idx];
            clflushopt(addresses[addr_idx]);
          }         
          // stop timing measurement and compare with last value
          t_start = t_end;
          lfence();
          t_end = rdtscp();
          cur_timing = (t_end - t_start);
#if LOG_TIMING
          fprintf(f, "%ld,\n", cur_timing);
#endif
          // check if a REF happened within the last 
          // NUM_ACCESSES_PER_MEASUREMENT_RND accesses
          if (cur_timing > exp_cfg.min_ref_thresh) {
            total_ref_timing += cur_timing;
            total_num_over_th++;
            // total_cnt_act_rnds += (i - i_last);
            total_cnt_act_rnds += i_diff;
            i_diff = 0;
            // this 'if' caused some delay, update t_end to take this into account
            lfence();
            t_end = rdtscp();
          }
          addr_idx = (addr_idx % exp_cfg.num_sync_rows);
        }
      }
  }

  // 
  auto avg_acts = (((total_cnt_act_rnds*exp_cfg.num_accesses_per_round) / total_num_over_th) >> 1) << 1;
  std::cout << "AVG(acts): " << avg_acts << std::endl;

  ref_threshold_low = (exp_cfg.min_ref_thresh + (total_ref_timing / total_num_over_th)) / 2;
  std::cout << "total_ref_timing: " << ref_threshold_low << std::endl;

#if LOG_TIMING
  fclose(f);
#endif

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
