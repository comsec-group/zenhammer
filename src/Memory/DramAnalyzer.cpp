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

DramAnalyzer::DramAnalyzer(volatile char *target)
    : start_address(target){
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
  exp_cfg.num_sync_rows = 32;
  exp_cfg.row_distance = 4;
  // exp_cfg.min_ref_thresh = 1000;
  exp_cfg.min_ref_thresh = 1260;
  exp_cfg.row_origin_same_bg = true;
  exp_cfg.row_origin_same_bk = true;
  return count_acts_per_ref(exp_cfg);
}

std::vector<uint64_t> DramAnalyzer::get_nth_highest_values(size_t N, std::vector<uint64_t> &values) {
  // compute frequencies
  std::map<uint64_t, std::size_t> freq;
  for(const auto& word : values) {
      freq[word]++;
  }
  
  // map -> vector
  std::vector<std::pair<uint64_t,uint64_t>> freq_as_vec(freq.begin(), freq.end());

  // partially sort the histogram based on the frequency count
  std::partial_sort(freq_as_vec.begin(), freq_as_vec.end(), freq_as_vec.begin() + N,
    [](const auto& lhs, const auto& rhs) {
        return lhs.second > rhs.second;    
    });

  // build the result vector containing the top-N values only
  std::vector<uint64_t> result;
  for (size_t i = 0; i < N; ++i) {
      // std::cout << freq_as_vec[i].first << " " << freq_as_vec[i].second << "x" << std::endl;  
      result.push_back(freq_as_vec[i].first);
  }

  return result;
}

size_t DramAnalyzer::count_acts_per_ref(const ExperimentConfig &exp_cfg) {
  Logger::log_info("Determining the number of activations per REF(sb|ab) interval...");

  size_t num_tries = 0;
  if (false) {
    retry:
    Logger::log_info(format_string("Trying it again.. try %d", num_tries));
    num_tries++;
  }

  // measurement parameters
  const size_t NUM_ADDRS = 2;
  size_t NUM_REPS = 5'000'000;

  std::vector<uint64_t> timing_values;
  timing_values.resize(NUM_REPS, 0);

  std::vector<volatile char*> addrs;
  for (size_t v = 0; v < NUM_ADDRS; ++v) {
    addrs.push_back((volatile char*)DRAMAddr(1, 0, 0, 0, v*2,  0).to_virt());
  }

  uint64_t tmp_before;
  uint64_t tmp_after;
  uint64_t cur;
  uint64_t cnt_higher_th = 0;
  uint64_t counted_reps = 0;

  // FILE* f2 = fopen("times2.txt", "w");
  sched_yield();
  for (size_t i = 0; i < NUM_REPS; i++) {
    sfence();
    tmp_before = rdtscp();
    lfence();
    for (size_t k = 0; k < NUM_ADDRS; ++k) {
      *addrs[k];
      clflushopt(addrs[k]);
    }
    lfence();
    tmp_after = rdtscp();
    for (size_t k = 0; k < NUM_ADDRS; ++k) {
      // clflushopt(addrs[k]);
    }
    cur = (tmp_after-tmp_before);
    timing_values[i] = cur;
    // fprintf(f2, "%ld\n", cur);
  }
  // fclose(f2);

  //
  // STEP 1: Figure out the REF threshold by taking the average of the two
  // peaks we can observe in timing accessing two same-<bg, bk> addresses.
  // 
  auto min_distance = 150; // cycles
  auto vec = get_nth_highest_values(5, timing_values);
  uint64_t highest= vec[0];
  uint64_t second_highest;
  bool second_highest_found = false;
  for (std::size_t i = 1; i < vec.size(); ++i) {
    auto candidate = vec[i];
    if (candidate < (highest-min_distance) || candidate > (highest+min_distance)) {
      second_highest = vec[i];
      second_highest_found = true;
    } else {
      highest = (highest+vec[i])/2; 
    }
    if (second_highest_found) {
      if (candidate < (second_highest-min_distance) || candidate > (second_highest+min_distance)) {
        second_highest = (second_highest+vec[i])/2; 
      } else {
        break;
      }
    }
  }
  auto REF_threshold = (highest+second_highest)/2;
  std::cout << std::dec << highest << " | " << second_highest  << " => " << REF_threshold << std::endl;

  // sometimes the measurement leads to weird/very high results, in this case
  // we just repeat
  if (REF_threshold > 1500)
    goto retry;

  // 
  // STEP 2: Use the threshold to determine the number of activations we can do
  // in a REF interval, i.e., between two consecutive REF commands.
  //
  
  std::vector<uint64_t> act_cnt;
  act_cnt.resize(NUM_REPS, 0);
 
  // FILE* f2 = fopen("times3.txt", "w");
  cnt_higher_th = 0;
  counted_reps = 0;
  
  sched_yield();
  for (size_t i = 0; i < NUM_REPS; i++) {
    sfence();
    tmp_before = rdtscp();
    lfence();
    for (size_t k = 0; k < NUM_ADDRS; ++k) {
      *addrs[k];
      clflushopt(addrs[k]);
    }
    lfence();
    tmp_after = rdtscp();
    if ((tmp_after-tmp_before) > REF_threshold) {
        act_cnt[cnt_higher_th] = (counted_reps*NUM_ADDRS);
        cnt_higher_th++;
        // fprintf(f2, "%ld, %ld\n", counted_reps*NUM_ADDRS, cur);
        counted_reps = 0;
    } else {
      counted_reps++;
    }
  }
  // fclose(f2);
  
  act_cnt.resize(cnt_higher_th-1);
  auto acts_per_ref = get_nth_highest_values(5, act_cnt);
  for (std::size_t i = 0; i < acts_per_ref.size(); ++i) {
      if (acts_per_ref[i] > 10)
        return acts_per_ref[i]; 
  }

  Logger::log_error("Could not determine reasonable ACTs/REF value. Using default (30).");
  Logger::log_data(format_string("REF threshold: %ld", REF_threshold));
  Logger::log_data(format_string("ACTs/REF (best): %ld", acts_per_ref[0]));

  return 30;
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
