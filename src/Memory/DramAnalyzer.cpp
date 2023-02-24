#include "Memory/DramAnalyzer.hpp"
#include "Memory/DRAMAddr.hpp"
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
  start_address(target), cc(cc) {
  cr = CustomRandom();
  dist = std::uniform_int_distribution<>(0, std::numeric_limits<int>::max());
  banks = std::vector<std::vector<volatile char *>>(NUM_BANKS, std::vector<volatile char *>());
}


// TODO: do analysis of timing results above threshold to determine REF threshold range
// TODO: (future work) use REFab detection and then remove this distribution from (any_bgbk,any_bgbk) distribution to get REFsb only
size_t DramAnalyzer::count_acts_per_ref() {
  Logger::log_info("Determining the number of activations per REF(sb|ab) interval...");

  uint64_t t_start;
  uint64_t t_end;

  const size_t NUM_ADDR_PER_PAIR = 2;
  const size_t NUM_ADDR_PAIRS = 5;
  const size_t NUM_ROUNDS = 500'000;

  std::unordered_map<size_t, size_t> numacts_count;
  std::unordered_map<size_t, std::vector<uint64_t>> actcnt2timingth;
  std::vector<uint64_t> timing_all;

  for (size_t it_addr_pair = 1; it_addr_pair <= NUM_ADDR_PAIRS; ++it_addr_pair) {
    std::vector<uint64_t> timing;
    timing.resize(NUM_ROUNDS,0);

    auto addr_pair = cc.get_simple_dram_address_same_bgbk(NUM_ADDR_PER_PAIR);
    std::vector<volatile char*> addresses;
    // bring array into cache
    for (size_t k = 0; k < addr_pair.size(); ++k) {
      addresses.push_back(addr_pair[k].vaddr);
      *addresses[k];
      clflushopt(addresses[k]);
    }
    sfence();
    // -1 because we always access two in each round
    const size_t addresses_sz = addresses.size()-1;

    // we keep this loop very short and tight to not negatively affect performance
    t_end = rdtscp();
    lfence();
    size_t addr_pair_idx = 0;
    for (size_t i = 0; i < NUM_ROUNDS; i++) {
      t_start = t_end;

      if (NUM_ADDR_PER_PAIR==2)
          sfence();

      *addresses[addr_pair_idx];
      clflushopt(addresses[addr_pair_idx]);

      *addresses[addr_pair_idx+1];
      clflushopt(addresses[addr_pair_idx+1]);

      lfence();
      t_end = rdtscp();
      timing[i] = t_end - t_start;

      addr_pair_idx = (addr_pair_idx + 2) % addresses_sz;
    }

    // compute the threshold that tells us whether a REF happened
    statistics stats_iteration{};
    calculate_statistics(timing, stats_iteration);
    uint64_t threshold = static_cast<uint64_t>(static_cast<double>(stats_iteration.avg) * 1.15);
    Logger::log_debug_data(format_string("pair #%d: %s, threshold=%ld",
                                         it_addr_pair, stats_iteration.to_string().c_str(), threshold));

    // go through all timing results and check after how many accesses we could observe a peak
    size_t num_acts_cnt = 0;
    for (size_t i = 0; i < NUM_ROUNDS; i++) {
//      std::cout << acts[i] << "\n";
      if (timing[i] > threshold && timing[i] < threshold+static_cast<uint64_t>(stats_iteration.std)) {
        // do not consider outlier
        actcnt2timingth[num_acts_cnt].push_back(timing[i]);
        numacts_count[num_acts_cnt]++;
//        std::cout << num_acts_cnt << "," << timing[i] << "\n";
        num_acts_cnt = 0;
      } else {
//        std::cout << "0," << timing[i] << "\n";
        // +2 because we do 2 accesses between measurements
        num_acts_cnt += 2;
      }
    }

    // accumulate timing results from all tested address pairs
    timing_all.insert(timing_all.end(), timing.begin(), timing.end());
  }

  // we need to place values with their counts as pairs in a new vector before we can determine the value with the
  // highest count
  std::vector<std::pair<size_t, size_t>> pairs;
  pairs.reserve(numacts_count.size());
  for (auto & itr : numacts_count) {
    // we ignore single-digit counts as we are assuming we can do more accesses between two consecutive REFs
    if (itr.first < 10)
      continue;
    pairs.emplace_back(itr.first, itr.second);
  }

  // sort the pairs by their value in descending order
  sort(pairs.begin(), pairs.end(), [=](auto& a, auto& b) { return a.second > b.second;});
//  size_t cnt = 0;
//  for (const auto &p : pairs) {
//    std::cout << p.first << ": " << p.second << std::endl;
//    if (cnt++ > 10) break;
//  }
  // this is the most frequent ACT cnt value
  auto num_acts_per_ref = pairs.at(0).first;
  Logger::log_data(format_string("num_acts_per_ref=%lu", num_acts_per_ref));

  // compute statistics for the most frequent ACT cnt value
  statistics stats_mf{};
  calculate_statistics(actcnt2timingth[num_acts_per_ref], stats_mf);
  Logger::log_debug_data(stats_mf.to_string());

  // compute statistics for all timing values below the threshold
  decltype(timing_all) timing_all_below;
  for (auto it = timing_all.begin(); it != timing_all.end(); ++it) {
    if (*it < stats_mf.median)
      timing_all_below.push_back(*it);
  }
  statistics stats_all_below_th;
  calculate_statistics(timing_all_below, stats_all_below_th);
//  Logger::log_debug_data(stats_all_below_th.to_string());

  th_low = static_cast<uint64_t>((stats_all_below_th.median + stats_mf.min)/2);
  Logger::log_data(format_string("ref_th_low=%d", th_low));

  return num_acts_per_ref;
}

size_t DramAnalyzer::get_ref_threshold() {
  return th_low;
}
