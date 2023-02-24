#include "Memory/DramAnalyzer.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Utilities/CustomRandom.hpp"

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

// TODO: do multiple rounds with different (random) address pairs
// TODO: do analysis of timing results above threshold to determine REF threshold range
// TODO: (future work) use REFab detection and then remove this distribution from (any_bgbk,any_bgbk) distribution to get REFsb only
size_t DramAnalyzer::count_acts_per_ref() {
  Logger::log_info("Determining the number of activations per REF(sb|ab) interval...");

  uint64_t t_start;
  uint64_t t_end;
  
  const size_t NUM_ADDR_PAIRS = 2;
  const size_t NUM_ROUNDS = 500'000;

  std::vector<uint64_t> acts;
  acts.reserve(NUM_ROUNDS*NUM_ADDR_PAIRS);

  std::unordered_map<size_t, size_t> numacts_count;

  for (size_t it_addr_pair = 1; it_addr_pair <= NUM_ADDR_PAIRS; ++it_addr_pair) {
    auto addr_pair = cc.get_simple_dram_address_same_bgbk(2);
    auto sa_a = addr_pair.at(0);
    auto sa_b = addr_pair.at(1);
    volatile char *a = sa_a.vaddr;
    volatile char *b = sa_b.vaddr;

    Logger::log_debug(format_string("Pointers used for count_acts_per_ref: %p,%p", a, b));
    Logger::log_debug_data(format_string("%p (bg=%d, bk=%d, row=%d)", sa_a.vaddr, sa_a.bg, sa_a.bk, sa_a.row_id));
    Logger::log_debug_data(format_string("%p (bg=%d, bk=%d, row=%d)", sa_b.vaddr, sa_b.bg, sa_b.bk, sa_b.row_id));

    auto compute_std = [](std::vector<uint64_t> &values, double mean, size_t num_numbers) {
      double var = 0;
      for (const auto &num : values) {
        if (static_cast<double>(num) < mean)
          continue;
        var += std::pow(static_cast<double>(num) - mean, 2);
      }
      auto val = std::sqrt(var / static_cast<double>(num_numbers));
      return val;
    };

    // we keep this loop very short and tight to not negatively affect performance
    t_end = rdtscp();
    lfence();
    for (size_t i = 0; i < NUM_ROUNDS; i++) {
      t_start = t_end;

      sfence();
      *a;
      clflushopt(a);

      *b;
      clflushopt(b);

      lfence();
      t_end = rdtscp();

      acts.push_back(t_end - t_start);
    }

    // compute the threshold that tells us whether a REF happened
    size_t min = *std::min_element(acts.begin(), acts.end());
    size_t max = *std::max_element(acts.begin(), acts.end());
    size_t sum = std::accumulate(acts.begin(), acts.end(), 0UL);
    size_t avg = sum / acts.size();
    auto std = compute_std(acts, static_cast<double>(avg), acts.size());
    auto threshold = static_cast<size_t>(static_cast<double>(avg) * 1.15);
    Logger::log_debug_data(format_string("sum=%d, min=%d, max=%d, avg=%d, std=%d => threshold=%d",
                                         sum, min, max, avg, std, threshold));

    // go through all timing results and check after how many accesses we could observe a peak
    size_t num_acts_cnt = 0;
    for (size_t i = 0; i < NUM_ROUNDS; i++) {
//      std::cout << acts[i] << "\n";
      if (acts[i] > threshold) {
        numacts_count[num_acts_cnt]++;
//        std::cout << num_acts_cnt << "," << acts[i] << "\n";
        num_acts_cnt = 0;
      } else {
        // +2 because we do 2 accesses between measurements
        num_acts_cnt += 2;
      }
    }

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
  size_t cnt = 0;
  for (const auto &p : pairs) {
//    std::cout << p.first << ": " << p.second << std::endl;
    cnt++;
    if (cnt > 10) break;
  }

  auto num_acts_per_ref = pairs.at(0).first;
  Logger::log_data(format_string("num_acts_per_ref=%lu", num_acts_per_ref));
  return num_acts_per_ref;
}
