#include "Fuzzer/PatternBuilder.hpp"
#include "../include/DramAnalyzer.hpp"

PatternBuilder::PatternBuilder(int num_activations, volatile char *target_address)
    : num_activations_per_tREFI_measured(num_activations), target_addr(target_address) {
  std::random_device rd;
  gen = std::mt19937(rd());  // standard mersenne_twister_engine seeded some random data
}

int PatternBuilder::remove_aggs(int N) {
  while (N > 1 && !aggressor_pairs.empty()) {
    aggressor_pairs.pop_back();
    N--;
  }
  return aggressor_pairs.size();
}

std::discrete_distribution<int> build_distribution(Range range_N_sided, std::unordered_map<int, int> probabilities) {
  std::vector<int> dd;
  for (int i = 0; i <= range_N_sided.max; i++) {
    dd.push_back((probabilities.count(i) > 0) ? probabilities.at(i) : 0);
  }
  return std::discrete_distribution<int>(dd.begin(), dd.end());
}

std::string PatternBuilder::get_dist_string(std::unordered_map<int, int> &dist) {
  std::stringstream ss;
  int N = 0;
  for (const auto &d : dist) N += d.second;
  for (const auto &d : dist) ss << d.first << "-sided: " << d.second << "/" << N << ", ";
  return ss.str();
}

void PatternBuilder::randomize_parameters() {
  printf(FCYAN "[+] Randomizing fuzzing parameters:\n");

  // === DYNAMIC FUZZING PARAMETERS ====================================================
  // specify ranges of valid values that are used to randomize during pattern generation

  // following values are randomized for each added aggressor
  amplitude = Range(1, 12);
  N_sided = Range(2, 2);
  agg_inter_distance = Range(2, 16);

  // === SEMI-DYNAMIC FUZZING PARAMETERS ====================================================
  // are only randomized once when calling this function

  num_aggressors = Range(12, 56).get_random_number(gen);
  agg_intra_distance = 2;
  random_start_address = target_addr + (Range(MB(100), MEM_SIZE - MB(100)).get_random_number(gen)/PAGE_SIZE)*PAGE_SIZE;
  use_sequential_aggressors = true;  // TODO: Make this random again (bool)(Range(0, 1).get_random_number(gen));
  agg_frequency = Range(1, 16);       // TODO: Set back to (1,10)
  num_refresh_intervals = Range(1, 8).get_random_number(gen);  // TODO: Set back to (1,8)
  sync_after_every_nth_hammering_rep = Range(1, num_refresh_intervals).get_random_number(gen);

  hammer_sync_reps = Range(3, 42).get_random_number(gen);

  //  hammer_sync_reps = Range(3, 24).get_random_number(gen);
  // hammer_sync_reps = num_activations_per_tREFI_measured / num_aggressors;
  // hammer_sync_reps = num_refresh_intervals;

  // e.g., (1,4) means each aggressor is accessed at least once (1,-) and at most 4 times (-, 4) in a sequence
//  auto th = num_activations_per_tREFI_measured*0.25;
//  num_activations_per_tREFI_measured =
//      Range(num_activations_per_tREFI_measured - th, num_activations_per_tREFI_measured + th).get_random_number(gen);
  num_activations_per_tREFI_measured = Range(8, 44).get_random_number(gen);
  num_activations_per_tREFI = (num_activations_per_tREFI_measured/2)*2;
  // std::vector<int> options = {20, 30, 40, 75, 85, 90, 100, 110, 115, 160, 175, 180};
  // num_activations_per_tREFI = options.at(Range(0, options.size()).get_random_number());
  // num_activations_per_tREFI = num_aggressors;

  // === STATIC FUZZING PARAMETERS ====================================================
  // fix values/formulas that must be configured before running this program

  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;
  fencing_strategy = FENCING_STRATEGY::LATEST_POSSIBLE;
  use_fixed_amplitude_per_aggressor = false;

  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then it translates to: pick a 1-sided pair with 20% probability and a
  // 2-sided pair with 80% probability
  // std::unordered_map<int, int> distribution = {{1, 2}, {2, 8}};
  std::unordered_map<int, int> distribution = {{2, 1}};
  N_sided_probabilities = build_distribution(N_sided, distribution);

//  total_acts_pattern = num_activations_per_tREFI*num_refresh_intervals;
  total_acts_pattern = Range(22, 124).get_random_number(gen);
  // total_acts_pattern = num_aggressors* Range(1,4).get_random_number(gen);
  // total_acts_pattern = num_aggressors;

  // hammering_total_num_activations is derived as follow:
  //  REF interval: 7.8 μs (tREFI), retention time: 64 ms => 8,000 - 10,000 REFs per interval
  //  num_activations_per_tREFI: ≈100                     => 10,000 * 100 = 1M activations * 3 = 3M ACTfs
//  hammering_total_num_activations = 50000000;  // TODO uncomment me
  hammering_total_num_activations = Range(24000, 330000).get_random_number(gen);
//  hammering_total_num_activations = Range(5000, 150000).get_random_number(gen);
  // hammering_total_num_activations = num_activations_per_tREFI * num_refresh_intervals;
  // hammering_total_num_activations = HAMMER_ROUNDS / std::max((size_t)1, (num_activations_per_tREFI_measured / total_acts_pattern));
  // hammering_total_num_activations = Range({20000000, 28000000}).get_random_number(gen);

  // ========================================================================================================

  printf("    agg_frequency: (%d,%d)\n", agg_frequency.min, agg_frequency.max);
  printf("    agg_inter_distance: (%d,%d)\n", agg_inter_distance.min, agg_inter_distance.max);
  printf("    agg_intra_distance: %d\n", agg_intra_distance);
  printf("    amplitude: (%d,%d)\n", amplitude.min, amplitude.max);
  printf("    fencing_strategy: %s\n", get_string(fencing_strategy).c_str());
  printf("    flushing_strategy: %s\n", get_string(flushing_strategy).c_str());
  printf("    hammer_sync_reps: %d\n", hammer_sync_reps);
  printf("    N_sided dist.: %s\n", get_dist_string(distribution).c_str());
  printf("    N_sided: (%d,%d)\n", N_sided.min, N_sided.max);
  printf("    num_activations_per_tREFI_measured: %d\n", num_activations_per_tREFI_measured);
  printf("    num_activations_per_tREFI: %d\n", num_activations_per_tREFI);
  printf("    num_aggressors: %d\n", num_aggressors);
  printf("    num_refresh_intervals: %d\n", num_refresh_intervals);
  printf("    hammering_total_num_activations: %d\n", hammering_total_num_activations);
  printf("    random_start_address: %p\n", random_start_address);
  printf("    total_acts_pattern: %zu\n", total_acts_pattern);
  printf("    use_fixed_amplitude_per_aggressor: %s\n", (use_fixed_amplitude_per_aggressor ? "true" : "false"));
  printf("    use_sequential_aggressors: %s\n", (use_sequential_aggressors ? "true" : "false"));
  printf(NONE);  // revert back color
}

void PatternBuilder::generate_frequency_based_pattern(HammeringPattern &hammering_pattern) {
  // initialize vars required for pattern generation
  auto pattern_length_mult = Range(1, 8).get_random_number(gen);
  const size_t pattern_length = num_activations_per_tREFI * pattern_length_mult;
  hammering_pattern.accesses = std::vector<Aggressor>(pattern_length, Aggressor());

  hammering_pattern.base_period = num_activations_per_tREFI * Range(1, pattern_length_mult).get_random_number(gen);
  size_t cur_period = hammering_pattern.base_period;

  auto empty_slots_exist =
      [](size_t offset, int base_period, int &next_offset, std::vector<Aggressor> &pattern) -> bool {
        for (size_t i = offset; i < pattern.size(); i += base_period) {
          // printf("[DEBUG] Checking index %zu: %s\n", i, pattern[i].to_string().c_str());
          if (pattern[i].id==ID_PLACEHOLDER_AGG) {
            next_offset = i;
            // printf("[DEBUG] Empty slot found at idx: %zu\n", i);
            return true;
          }
        }
        // printf("[DEBUG] No empty slot found\n");
        return false;
      };

  // generate sets of aggressor sets
  // we do not need to consider there that an aggressor could be part of an aggressor pair and at the same time be
  // accessed as a single aggressor only; this will be handled later by mapping multiple Aggressor objects to the same
  // address
  std::vector<std::vector<Aggressor>> pairs;
  for (size_t i = 0; i < (size_t) num_aggressors;) {
    const int N = N_sided_probabilities(gen);
    std::vector<Aggressor> data;
    data.reserve(N);
    for (int j = 0; j < N; j++) {
      data.emplace_back(i + j);
    }
    pairs.push_back(data);
    i += N;
  }

  auto get_N_sided_agg = [&](size_t N) -> std::vector<Aggressor> {
    std::shuffle(pairs.begin(), pairs.end(), gen);
    for (auto &agg_set : pairs) {
      if (agg_set.size()==N) return agg_set;
    }
    // TODO Future Work: Make sure we have at least one pair for each N of N-sided because this is the assumption made
    //  by callers of get_N_sided_agg - there is always at least one N-sided pair for each N in the range.
    fprintf(stderr, "[-] Couldn't get a N-sided aggressor pair but this shouldn't have happened.\n");
    exit(1);
  };

  size_t next_idx = 0;
  auto get_next_agg = [&]() -> std::vector<Aggressor> {
    auto ret_value = pairs.at(next_idx);
    next_idx = (next_idx + 1UL)%pairs.size();
    return ret_value;
  };

  const size_t expected_acts = std::max((size_t) 1, pattern_length/hammering_pattern.base_period);

  // generate the pattern
  // iterate over all slots in the base period
  for (size_t i = 0; i < hammering_pattern.base_period; ++i) {
    // check if this slot was already filled up by (an) amplified aggressor(s)
    if (hammering_pattern.accesses[i].id!=ID_PLACEHOLDER_AGG) continue;

    // choose a random amplitude
    auto amp = (size_t) amplitude.get_random_number(gen);

    // repeat until the current time slot k is filled up in each k+i*base_period
    int next_offset = i;
    size_t collected_acts = 0;
    int cur_N = N_sided.get_random_number(gen);
    cur_period = hammering_pattern.base_period;

    do {
      // define the period to use for the next agg(s)*
      // note: 8 is a randomly chosen value to not make frequencies ever-growing high
      cur_period = cur_period*Range(1, expected_acts, true).get_random_number(gen); // TODO: Uncomment
//      cur_period = hammering_pattern.base_period;
      collected_acts += (pattern_length/cur_period);

      // agg can be a single agg or a N-sided pair
      auto agg = get_N_sided_agg(cur_N); // TODO: Uncomment and use to replace next line
//      auto agg = get_next_agg();
//      std::cout << "aggressors: ";
//      for (auto &a : agg) std::cout << a.to_string() << " ";
//      std::cout << std::endl;

      // if there's only one aggressor then successively accessing it multiple times does not trigger any activations
      if (agg.size()==1) amp = 1;

      // generates an AggressorAccess for each added aggressor set
      std::unordered_map<int, Aggressor> off_agg_map;
      for (size_t l = 0; l < agg.size(); l++) off_agg_map[l] = agg[l];
      hammering_pattern.agg_access_patterns.emplace_back(cur_period, amp, off_agg_map);

      // fill the pattern with the given aggressors
      // - period
      for (size_t j = 0; j*cur_period < hammering_pattern.accesses.size(); j++) {
        // - amplitude
        for (size_t m = 0; m < amp; m++) {
          // - aggressors
          for (size_t k = 0; k < agg.size(); k++) {
            auto idx = (j*cur_period) + next_offset + (m*agg.size()) + k;
//            printf("filling agg: %s, idx: %zu\n", agg[k].to_string().c_str(), idx);
            if (idx >= hammering_pattern.accesses.size()) goto exit_loops;
            hammering_pattern.accesses[idx] = agg[k];
          }
        }
      }
      exit_loops:
      static_cast<void>(0);  // no-op required for goto
    } while (empty_slots_exist(i, hammering_pattern.base_period, next_offset, hammering_pattern.accesses));
  }
}

