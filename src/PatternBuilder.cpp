#include "../include/PatternBuilder.hpp"

#include "../include/Aggressor.hpp"
#include "../include/AggressorAccessPattern.hpp"
#include "../include/DRAMAddr.hpp"
#include "../include/DramAnalyzer.hpp"
#include "../include/GlobalDefines.hpp"
#include "../include/HammeringPattern.hpp"
#include "../include/utils.hpp"

PatternBuilder::PatternBuilder(int num_activations, volatile char* target_address)
    : num_activations_per_tREFI_measured(num_activations), target_addr(target_address) {
  std::random_device rd;
  gen = std::mt19937(rd());  // standard mersenne_twister_engine seeded some random data
}

size_t PatternBuilder::count_aggs() {
  return aggressor_pairs.size();
}

int PatternBuilder::remove_aggs(int N) {
  while (N > 1 && aggressor_pairs.size() > 0) {
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

std::string PatternBuilder::get_dist_string(std::unordered_map<int, int>& dist) {
  std::stringstream ss;
  int N = 0;
  for (const auto& d : dist) N += d.second;
  for (const auto& d : dist) ss << d.first << "-sided: " << d.second << "/" << N << ", ";
  return ss.str();
}

void PatternBuilder::randomize_parameters() {
  printf(FCYAN "[+] Randomizing fuzzing parameters:\n");

  // === DYNAMIC FUZZING PARAMETERS ====================================================
  // specify ranges of valid values that are used to randomize during pattern generation

  // following values are randomized for each added aggressor
  amplitude = Range(1, 3);  // TODO: Add way to hammer aggressors in pair with different amplitudes!
  N_sided = Range(2, 2);
  agg_inter_distance = Range(1, 15);

  // === SEMI-DYNAMIC FUZZING PARAMETERS ====================================================
  // are only randomized once when calling this function

  // num_aggressors = Range(23, 32).get_random_number(gen); // TODO: Start from (3, x)
  num_aggressors = Range(23, 35).get_random_number(gen);
  agg_intra_distance = 2;
  random_start_address = target_addr + (Range(MB(100), MEM_SIZE - MB(100)).get_random_number(gen) / PAGE_SIZE) * PAGE_SIZE;
  use_sequential_aggressors = true;                            // (bool)(Range(0, 1).get_random_number(gen));  // TODO: Make this random again
  agg_frequency = Range(1, 2);                                 // TODO: Set back to (1,10)
  num_refresh_intervals = Range(1, 8).get_random_number(gen);  // TODO: Set back to (1,8)
  sync_after_every_nth_hammering_rep = Range(1, num_refresh_intervals).get_random_number(gen);

  hammering_reps_before_sync = Range(3, 24).get_random_number(gen);
  // hammering_reps_before_sync = num_activations_per_tREFI_measured / num_aggressors;
  // hammering_reps_before_sync = num_refresh_intervals;

  // e.g., (1,4) means each aggressor is accessed at least once (1,-) and at most 4 times (-, 4) in a sequence
  num_activations_per_tREFI = num_activations_per_tREFI_measured;
  // std::vector<int> options = {20, 30, 40, 75, 85, 90, 100, 110, 115, 160, 175, 180};
  // num_activations_per_tREFI = options.at(Range(0, options.size()).get_random_number());
  // num_activations_per_tREFI = num_aggressors;

  // === STATIC FUZZING PARAMETERS ====================================================
  // fix values/formulas that must be configured before running this program

  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;
  fencing_strategy = FENCING_STRATEGY::OMIT_FENCING;
  use_fixed_amplitude_per_aggressor = false;

  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then it translates to: pick a 1-sided pair with 20% probability and a
  // 2-sided pair with 80% probability
  // std::unordered_map<int, int> distribution = {{1, 2}, {2, 8}};
  std::unordered_map<int, int> distribution = {{2, 1}};
  N_sided_probabilities = build_distribution(N_sided, distribution);

  total_acts_pattern = num_activations_per_tREFI * num_refresh_intervals;
  // total_acts_pattern = num_aggressors* Range(1,4).get_random_number(gen);
  // total_acts_pattern = num_aggressors;

  // hammering_total_num_activations is derived as follow:
  //  REF interval: 7.8 μs (tREFI), retention time: 64 ms => 8,000 - 10,000 REFs per interval
  //  num_activations_per_tREFI: ≈100                     => 10,000 * 100 = 1M activations * 3 = 3M ACTfs
  hammering_total_num_activations = 80000000;  // TODO uncomment me
  // hammering_total_num_activations = Range({21000, 350000}).get_random_number();
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
  printf("    hammering_reps_before_sync: %d\n", hammering_reps_before_sync);
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

int PatternBuilder::hammer_pattern() {
  auto return_value = jitter.hammer_pattern();
  // if (return_value > 0) {
  //   // hammering was successful, return_value indicates the number of activations before the final refresh
  //   return return_value / (hammering_total_num_activations / total_acts_pattern);
  // }
  // this indicates that no hammering happened
  return return_value;
}

void PatternBuilder::cleanup() {
  jitter.cleanup();
}

void PatternBuilder::encode_double_ptr_chasing(std::vector<volatile char*>& aggressors,
                                               volatile char** first_start, volatile char** second_start) {
  // ! ATTENTION: This function has not been tested yet and might still contain some bugs.

  printf("Running encode_double_ptr_chasing... ");

  const int container_size = 8192;            // byte = 8 kb
  const int num_slots = container_size / 64;  // byte => 128 slots
  std::unordered_map<volatile char*, int> occupied_slots;

  // a utility function that encodes a given address (address_to_encode) into a given target memory area (target)
  auto encode_into_slot = [&occupied_slots](volatile char* target, volatile char* address_to_encode) {
    // determine the target slot wherein the address should be encoded to
    int target_slot_no = (occupied_slots.count(target) > 0) ? occupied_slots[target] + 1 : 0;
    occupied_slots[target] = target_slot_no;

    // data structure for accessing addresses encoded into slots
    volatile char* slots[num_slots];

    // read currrent values from slots
    memcpy(slots, (const void*)target, sizeof(slots));

    // add new value
    slots[target_slot_no] = address_to_encode;

    // write back all values
    memcpy((void*)target, slots, sizeof(slots));
  };

  std::unordered_map<volatile char*, volatile char*> address_to_chase_mapping;

  // pointer to the address where the next element is to be encoded into
  volatile char* first_cur;
  volatile char* second_cur;

  // counts for the number of elements in each chase
  size_t elems_first = 0;
  size_t elems_second = 0;

  for (size_t i = 0; i < aggressors.size(); i++) {
    auto cur_agg = aggressors.at(i);

    // this check makes sure that if we have accessed the address before in any of the two chases, we need to add it
    // again to the same chase, otherwise it could be that the memory controller reorders these accesses and only
    // accesses the address once
    bool historical_preference = false;
    bool pref_first_chase = false;
    if (address_to_chase_mapping.count(cur_agg) > 0) {
      historical_preference = true;
      pref_first_chase = (address_to_chase_mapping.at(cur_agg) == *first_start);
    }

    if ((historical_preference && pref_first_chase) || (!historical_preference && elems_first <= elems_second)) {
      if (*first_start == nullptr) {
        *first_start = cur_agg;
        first_cur = *first_start;
      } else {
        encode_into_slot(first_cur, cur_agg);
        first_cur = cur_agg;
      }
      elems_first++;
      address_to_chase_mapping[cur_agg] = *first_start;
    } else {
      if (*second_start == nullptr) {
        *second_start = cur_agg;
        second_cur = *second_start;
      } else {
        encode_into_slot(second_cur, cur_agg);
        second_cur = cur_agg;
      }
      elems_second++;
      address_to_chase_mapping[cur_agg] = *second_start;
    }
  }
  printf("finished!\n");
}

std::string PatternBuilder::get_row_string(std::vector<volatile char*> aggs, u_int64_t row_function) {
  std::stringstream ss;
  ss << "|";
  for (const auto& agg : aggs) ss << get_row_index(agg, row_function) << "|";
  return ss.str();
}

void PatternBuilder::generate_frequency_based_pattern(HammeringPattern& hammering_pattern) {
  // initialize vars required for pattern generation
  // - periods
  // make sure num_activations_per_tREFI is even so that base_period and pattern_length are even too
  num_activations_per_tREFI = num_activations_per_tREFI_measured;
  const size_t pattern_length = num_activations_per_tREFI * Range(1, 8).get_random_number(gen);
  const size_t base_period = num_activations_per_tREFI;
  hammering_pattern.base_period = base_period;
  size_t cur_period = base_period;
  // - pattern
  hammering_pattern.accesses = std::vector<Aggressor>(pattern_length, Aggressor());

  auto empty_slots_exist = [](size_t offset, int base_period, int& next_offset, std::vector<Aggressor>& pattern) -> bool {
    for (size_t i = offset; i < pattern.size(); i += base_period) {
      // printf("[DEBUG] Checking index %zu: %s\n", i, pattern[i].to_string().c_str());
      if (pattern[i].id == ID_PLACEHOLDER_AGG) {
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
  for (size_t i = 0; i < (size_t)num_aggressors;) {
    const int N = N_sided_probabilities(gen);
    std::vector<Aggressor> data;
    for (int j = 0; j < N; j++) {
      data.push_back(Aggressor(i + j));
    }
    pairs.push_back(data);
    i += N;
  }

  auto get_N_sided_agg = [&](size_t N) -> std::vector<Aggressor> {
    std::shuffle(pairs.begin(), pairs.end(), gen);
    for (auto& agg_set : pairs) {
      if (agg_set.size() == N) return agg_set;
    }
    // TODO Future Work: Make sure we have at least one pair for each N of N-sided.
    fprintf(stderr, "[-] Couldn't get a N-sided aggressor pair but this shouldn't have happened.\n");
    exit(1);
  };

  const int expected_acts = pattern_length / base_period;

  // generate the pattern
  // iterate over all slots in the base period
  for (size_t i = 0; i < base_period; ++i) {
    // check if this slot was already filled up by (an) amplified aggressor(s)
    if (hammering_pattern.accesses[i].id != ID_PLACEHOLDER_AGG) continue;

    // choose a random aplitude
    auto amp = amplitude.get_random_number(gen);
    printf("[DEBUG] amp: %d\n", amp);

    // repeat until the current time slot k is filled up in each k+i*base_period
    int next_offset = i;
    int collected_acts = 0;
    int cur_N = N_sided.get_random_number(gen);
    cur_period = base_period;

    do {
      // define the period to use for the next agg(s)*
      // note: 8 is a randomly chosen value to not make frequencies ever-growing high
      int max_times_base_period = expected_acts - collected_acts;
      cur_period = cur_period * Range(1, expected_acts, true).get_random_number(gen);
      collected_acts += (pattern_length / cur_period);
      printf("[DEBUG] cur_period: %zu\n", cur_period);

      // agg can be a single agg or a N-sided pair
      auto agg = get_N_sided_agg(cur_N);
      // std::cout << "aggressors: ";
      // for (auto& a : agg) std::cout << a.to_string() << " ";
      // std::cout << std::endl;

      // if there's only one aggressor then successively accessing it multiple times does not trigger any activations
      if (agg.size() == 1) amp = 1;

      // generates an AggressorAccess for each added aggressor set
      std::unordered_map<int, Aggressor> off_agg_map;
      for (size_t i = 0; i < agg.size(); i++) off_agg_map[i] = agg[i];
      hammering_pattern.agg_access_patterns.emplace_back(cur_period, amp, off_agg_map);

      // fill the pattern with the given aggressors
      // - period
      for (size_t j = 0; j * cur_period < hammering_pattern.accesses.size(); j++) {
        // - amplitude
        for (size_t m = 0; m < (size_t)amp; m++) {
          // - aggressors
          for (size_t k = 0; k < agg.size(); k++) {
            auto idx = (j * cur_period) + next_offset + (m * agg.size()) + k;
            // printf("filling agg: %s, idx: %zu\n", agg[k].to_string().c_str(), idx);
            if (idx >= hammering_pattern.accesses.size()) goto exit_loops;
            hammering_pattern.accesses[idx] = agg[k];
          }
        }
      }
    exit_loops:
      static_cast<void>(0);  // no-op required for goto
    } while (empty_slots_exist(i, base_period, next_offset, hammering_pattern.accesses));
  }

  // print pattern to stdout
  // printf("[DEBUG] pattern.size: %zu\n", hammering_pattern.accesses.size());
  // printf("[DEBUG] hammering_pattern.accesses: ");
  // for (size_t i = 0; i < hammering_pattern.accesses.size(); i++) {
  //   std::cout << hammering_pattern.accesses[i].to_string() << " ";
  //   if (i % base_period == 0) std::cout << std::endl;
  // }
  // std::cout << std::endl;
}
void PatternBuilder::jit_code() {
  // generate jitted hammering code that hammers chosen addresses (but does not run it yet)
  jitter.jit_strict(hammering_total_num_activations,
                    hammering_reps_before_sync,
                    sync_after_every_nth_hammering_rep,
                    flushing_strategy,
                    fencing_strategy,
                    aggressor_pairs);
}
