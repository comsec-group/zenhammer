#include "Memory/DramAnalyzer.hpp"

#include "Fuzzer/CodeJitter.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Memory/DRAMConfig.hpp"

#include <cassert>
#include <random>
#include <unordered_set>

void DramAnalyzer::find_threshold() {
  assert(threshold == (size_t)-1 && "find_threshold() has not been called yet.");
  Logger::log_info("Generating histogram data to find bank conflict threshold.");
  constexpr size_t HISTOGRAM_MAX_VALUE = 4096;
  constexpr size_t HISTOGRAM_ENTRIES = 16384;

  std::vector<size_t> histogram(HISTOGRAM_MAX_VALUE, 0);
  size_t num_entries = 0;

  while (num_entries < HISTOGRAM_ENTRIES) {
    auto a1 = get_random_address();
    auto a2 = get_random_address();
    auto time = (size_t)measure_time(a1, a2);
    if (time < histogram.size()) {
      histogram[time]++;
      num_entries++;
    }
  }

  // Find threshold such that HISTOGRAM_ENTRIES / NUM_BANKS times are above it.
  threshold = HISTOGRAM_MAX_VALUE - 1;
  size_t num_entries_above_threshold = 0;
  while (num_entries_above_threshold < HISTOGRAM_ENTRIES / DRAMConfig::get().banks()) {
    num_entries_above_threshold += histogram[threshold];
    threshold--;
    assert(threshold > 0);
  }

  Logger::log_info(format_string("Found bank conflict threshold to be %zu.", threshold));
}

void DramAnalyzer::find_bank_conflicts() {
  size_t nr_banks_cur = 0;
  auto num_banks = DRAMConfig::get().banks();
  int remaining_tries = num_banks * 1024;  // experimentally determined, may be unprecise
  while (nr_banks_cur < num_banks && remaining_tries > 0) {
    reset:
    remaining_tries--;
    auto a1 = get_random_address();
    auto a2 = get_random_address();
    auto ret1 = measure_time(a1, a2);
    auto ret2 = measure_time(a1, a2);

    if ((ret1 > threshold) && (ret2 > threshold)) {
      bool all_banks_set = true;
      for (size_t i = 0; i < num_banks; i++) {
        if (banks.at(i).empty()) {
          all_banks_set = false;
        } else {
          auto bank = banks.at(i);
          ret1 = measure_time(a1, bank[0]);
          ret2 = measure_time(a2, bank[0]);
          if ((ret1 > threshold) || (ret2 > threshold)) {
            // possibly noise if only exactly one is true,
            // i.e., (ret1 > threshold) or (ret2 > threshold)
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
          "Could not find conflicting address sets. Is the number of banks (%zu) defined correctly?",
          DRAMConfig::get().banks()));
      exit(1);
    }
  }

  Logger::log_info("Found bank conflicts.");
}

DramAnalyzer::DramAnalyzer(volatile char *target) :
  row_function(0), start_address(target) {
  banks = std::vector<std::vector<volatile char *>>(DRAMConfig::get().banks(), std::vector<volatile char *>());
}

size_t DramAnalyzer::count_acts_per_trefi() {
  size_t skip_first_N = 50;
  // pick two random same-bank addresses
  volatile char *a = banks.at(0).at(0);
  volatile char *b = banks.at(0).at(1);

  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before;
  uint64_t after;
  uint64_t count = 0;
  uint64_t count_old = 0;

  // computes the standard deviation
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

  for (size_t i = 0;; i++) {
    // flush a and b from caches
    clflushopt(a);
    clflushopt(b);
    mfence();

    // get start timestamp and wait until we retrieved it
    before = rdtscp();
    lfence();

    // do DRAM accesses
    (void)*a;
    (void)*b;

    // get end timestamp
    after = rdtscp();

    count++;
    if ((after - before) > 1000) {
      if (i > skip_first_N && count_old!=0) {
        // multiply by 2 to account for both accesses we do (a, b)
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 1 -> then stop collecting measurements
        if ((acts.size()%200)==0 && compute_std(acts, running_sum, acts.size())<3.0) break;
      }
      count_old = count;
    }
  }

  auto activations = (running_sum/acts.size());
  Logger::log_info("Determined the number of possible ACTs per refresh interval.");
  Logger::log_data(format_string("num_acts_per_tREFI: %lu", activations));

  return activations;
}

size_t DramAnalyzer::find_sync_ref_threshold() {
  Logger::log_info("Finding sync REF threshold using using jitted code.");
  CodeJitter jitter;

  // Idea: Start with a threshold that is definitely too high, wait until there are no overruns (i.e., # ACTs is the
  // maximum, meaning no REF is detected) in any of the three sync attempts.

  // Prepare aggressors.
  constexpr size_t NUM_AGGRS = 32;
  std::vector<volatile char*> aggressors;
  for (size_t i = 0; i < NUM_AGGRS; i++) {
    aggressors.push_back((volatile char*)DRAMAddr(0, 2 * i, 0).to_virt());
  }

  // Prepare REF sync address.
  DRAMAddr initial_sync_addr(1, 0, 0);
  // NOTE: This needs to be in the same rank, but a different bank w.r.t. the aggressors.

  for (size_t sync_ref_threshold = 4000; sync_ref_threshold >= 800; sync_ref_threshold -= 200) {
    size_t total_synced_refs = 0;
    size_t missed_refs = 0;

    jitter.jit_ref_sync(FLUSHING_STRATEGY::EARLIEST_POSSIBLE, FENCING_STRATEGY::OMIT_FENCING,
                        aggressors, initial_sync_addr, sync_ref_threshold);

    // 32 iterations.
    for (size_t i = 0; i < 32; i++) {
      RefSyncData data;
      jitter.run_ref_sync(&data);
      if (data.first_sync_act_count == CodeJitter::SYNC_REF_NUM_AGGRS) {
        missed_refs++;
      }
      if (data.second_sync_act_count == CodeJitter::SYNC_REF_NUM_AGGRS) {
        missed_refs++;
      }
      if (data.last_sync_act_count == CodeJitter::SYNC_REF_NUM_AGGRS) {
        missed_refs++;
      }
      total_synced_refs += 3;
    }

    jitter.cleanup();

    Logger::log_data(format_string("sync_ref_threshold = %zu, missed_refs = %zu", sync_ref_threshold, missed_refs));

    // Allow one missed REF due to noise.
    if (missed_refs <= 1) {
      // Add a margin for safety.
      sync_ref_threshold -= 100;
      Logger::log_info(format_string("Choosing sync_ref_threshold = %zu.", sync_ref_threshold));
      return sync_ref_threshold;
    }
  }

  Logger::log_error("Error: Could not determine sync_ref_threshold.");
  exit(EXIT_FAILURE);
}

void DramAnalyzer::check_sync_ref_threshold(size_t sync_ref_threshold) {
  Logger::log_info(format_string("Checking sync REF threshold (%zu cycles) using using jitted code.", sync_ref_threshold));
  CodeJitter jitter;

  // The second sync should be independent of the number of aggressors. Take the average of the averages to check this.
  size_t second_sync_avg_min = -1;
  size_t second_sync_avg_max = 0;

  for (size_t num_aggrs = 0; num_aggrs <= 40; num_aggrs += 5) {
    // Prepare aggressors.
    std::vector<volatile char*> aggressors;
    for (size_t i = 0; i < num_aggrs; i++) {
      aggressors.push_back((volatile char*)DRAMAddr(0, 2 * i, 0).to_virt());
    }

    // Prepare REF sync address.
    DRAMAddr initial_sync_addr(1, 0, 0);
    // NOTE: This needs to be in the same rank, but a different bank w.r.t. the aggressors.

    jitter.jit_ref_sync(FLUSHING_STRATEGY::EARLIEST_POSSIBLE, FENCING_STRATEGY::OMIT_FENCING,
                        aggressors, initial_sync_addr, sync_ref_threshold);

    size_t total_runs = 0;
    size_t missed_refs = 0;

    size_t second_tsc_sum = 0;
    size_t last_tsc_sum = 0;

    uint32_t second_tsc_min = -1;
    uint32_t second_tsc_max = 0;
    uint32_t last_tsc_min = -1;
    uint32_t last_tsc_max = 0;

    // 32 iterations.
    for (size_t i = 0; i < 32; i++) {
      RefSyncData data;
      jitter.run_ref_sync(&data);
      if (data.first_sync_act_count == CodeJitter::SYNC_REF_NUM_AGGRS) {
        missed_refs++;
      }
      if (data.second_sync_act_count == CodeJitter::SYNC_REF_NUM_AGGRS) {
        missed_refs++;
      }
      if (data.last_sync_act_count == CodeJitter::SYNC_REF_NUM_AGGRS) {
        missed_refs++;
      }

      total_runs++;
      second_tsc_sum += data.second_sync_tsc_delta;
      last_tsc_sum += data.last_sync_tsc_delta;
      second_tsc_min = std::min(second_tsc_min, data.second_sync_tsc_delta);
      second_tsc_max = std::max(second_tsc_max, data.second_sync_tsc_delta);
      last_tsc_min = std::min(last_tsc_min, data.last_sync_tsc_delta);
      last_tsc_max = std::max(last_tsc_max, data.last_sync_tsc_delta);
    }

    jitter.cleanup();

    auto second_tsc_avg = second_tsc_sum / total_runs;
    auto last_tsc_avg = last_tsc_sum / total_runs;

    second_sync_avg_min = std::min(second_sync_avg_min, second_tsc_avg);
    second_sync_avg_max = std::max(second_sync_avg_max, second_tsc_avg);

    Logger::log_data(format_string(
      "num aggressors = %2zu, missed REFs = %2zu, second sync cycles (min:avg:max) = %5u:%5u:%5u, last sync cycles (avg) = %5u:%5u:%5u",
      num_aggrs, missed_refs, second_tsc_min, second_tsc_avg, second_tsc_max, last_tsc_min, last_tsc_avg, last_tsc_max));

    // Abort if there is more than one missed REF.
    if (missed_refs > 1) {
      Logger::log_error(format_string("Error: Too many missed REFs (%zu)!", missed_refs));
      exit(EXIT_FAILURE);
    }
  }

  Logger::log_info(format_string("Second sync cycle averages are between %zu and %zu.", second_sync_avg_min, second_sync_avg_max));
  if (second_sync_avg_max > 1.2 * second_sync_avg_min) {
    Logger::log_error("Second sync cycle averages are spread too widely.");
    exit(EXIT_FAILURE);
  }
}

// Find which banks in another mapping corresponds to the banks of this mapping.
// Returns a vector where vector[this_mapping_bank] = other_mapping_same_bank.
std::vector<size_t> DramAnalyzer::get_corresponding_banks_for_mapping(int other_mapping_id, volatile char* other_mapping_base) const {
  std::random_device rd;
  std::default_random_engine gen(rd());
  std::uniform_int_distribution<size_t> dist(0, DRAMConfig::get().memory_size() - 1);

  std::vector<size_t> result;

  for (size_t this_mapping_bank = 0; this_mapping_bank < DRAMConfig::get().banks(); this_mapping_bank++) {
    Logger::log_info(format_string("Finding corresponding bank in other mapping for bank %zu.", this_mapping_bank));
    std::vector<size_t> corresponding_banks_other_mapping;
    auto this_mapping_addr = (volatile char*)DRAMAddr(this_mapping_bank, 0, 0).to_virt();
    for (size_t i = 0; i < 1024; i++) {
      auto other_mapping_addr = other_mapping_base + dist(gen);
      auto ret1 = measure_time(this_mapping_addr, other_mapping_addr);
      auto ret2 = measure_time(this_mapping_addr, other_mapping_addr);
      if ((ret1 > threshold) && (ret2 > threshold)) {
        auto other_mapping_dram_addr = DRAMAddr((void*)other_mapping_addr);
        assert(other_mapping_dram_addr.mapping_id == other_mapping_id);
        corresponding_banks_other_mapping.push_back(other_mapping_dram_addr.bank);
      }
    }

    // corresponding_banks_other_mapping now contains a list of bank indices that seem to match this bank.
    // Ideally, this would only be a single index. We find the most common one, for each bank, using a histogram.
    std::vector<size_t> hist(DRAMConfig::get().banks(), 0);
    for (auto bank : corresponding_banks_other_mapping) {
      hist.at(bank)++;
    }
    // Find the maximum and the argmax.
    size_t max = 0;
    size_t argmax = 0;
    for (size_t bank = 0; bank < hist.size(); bank++) {
      if (hist[bank] > max) {
        max = hist[bank];
        argmax = bank;
      }
    }
    auto percentage_of_max = 100.0 * (double)max / (double)corresponding_banks_other_mapping.size();
    Logger::log_data(format_string("Bank %zu has %5.1f%% of matches.", argmax, percentage_of_max));
    result.push_back(argmax);
  }
  assert(result.size() == DRAMConfig::get().banks());

  Logger::log_info("Got translation of banks to secondary mapping:");
  for (size_t bank = 0; bank < result.size(); bank++) {
    Logger::log_data(format_string("    %2zu -> %2zu", bank, result[bank]));
  }

  // Check that each corresponding bank is in the result exactly once.
  auto result_copy = result;
  std::sort(result_copy.begin(), result_copy.end());
  for (size_t i = 0; i < result_copy.size(); i++) {
    if (result_copy[i] != i) {
      Logger::log_error("Error: Translation does not contain each bank exactly once.");
      exit(EXIT_FAILURE);
    }
  }

  return result;
}

volatile char* DramAnalyzer::get_random_address() const {
  static std::random_device rd;
  static std::default_random_engine gen(rd());
  static std::uniform_int_distribution<size_t> dist(0, DRAMConfig::get().memory_size() - 1);
  return start_address + dist(gen);
}
