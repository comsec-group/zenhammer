#include "../include/PatternBuilder.hpp"

#include <algorithm>
#include <climits>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "../include/DramAnalyzer.hpp"
#include "../include/GlobalDefines.hpp"
#include "../include/utils.hpp"

PatternBuilder::PatternBuilder(int num_activations, volatile char* target_address)
    : num_activations(num_activations), target_addr(target_address) {
}

void PatternBuilder::randomize_parameters() {
  printf(FCYAN "[+] Randomizing fuzzing parameters:\n");
  // STATIC FUZZING PARAMETERS
  // those static parameters must be configured before running this program and are not randomized
  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;
  fencing_strategy = FENCING_STRATEGY::LATEST_POSSIBLE;
  use_agg_only_once = false;
  use_fixed_amplitude_per_aggressor = false;
  use_unused_pair_as_dummies = true;

  // SEMI-DYNAMIC FUZZING PARAMETERS
  num_activations = Range(80, 110).get_random_number();
  // those parameters are only randomly selected once, i.e., when calling this function
  num_aggressors = Range(18, 22).get_random_number();
  agg_inter_distance = Range(2, 4).get_random_number();
  agg_intra_distance = Range(1, 2).get_random_number();
  // agg_rounds = Range(128, 2048).get_random_number();
  // agg_rounds = num_activations / num_aggressors;
  // if (agg_rounds == 0)
  agg_rounds = Range(2, 8).get_random_number();
  // agg_rounds = num_activations / (2 * num_aggressors);
  // hammer_rounds = Range(800, 1500).get_random_number();
  hammer_rounds = agg_rounds;
  num_refresh_intervals = Range(100000, 400000).get_random_number();
  // num_refresh_intervals = hammer_rounds / agg_rounds;
  random_start_address = target_addr + MB(100) + (((rand() % (MEM_SIZE - MB(200)))) / PAGE_SIZE) * PAGE_SIZE;
  use_sequential_aggressors = (bool)(Range(0, 1).get_random_number());
  distance_to_dummy_pair = Range(80,120).get_random_number();

  // DYNAMIC FUZZING PARAMETERS
  // these parameters specify ranges of valid values that are then randomly determined while generating the pattern
  amplitude = Range(1, 4);
  N_sided = Range(2, 3);

  printf("    agg_inter_distance: %d\n", agg_inter_distance);
  printf("    agg_intra_distance: %d\n", agg_intra_distance);
  printf("    agg_rounds: %d\n", agg_rounds);
  printf("    amplitude: (%d, %d)\n", amplitude.min, amplitude.max);
  printf("    fencing_strategy: %s\n", get_string(fencing_strategy).c_str());
  printf("    flushing_strategy: %s\n", get_string(flushing_strategy).c_str());
  printf("    hammer_rounds: %d\n", hammer_rounds);
  printf("    N_sided: (%d, %d)\n", N_sided.min, N_sided.max);
  printf("    num_activations: %d\n", num_activations);
  printf("    num_aggressors: %d\n", num_aggressors);
  printf("    num_refresh_intervals: %d\n", num_refresh_intervals);
  printf("    random_start_address: %p\n", random_start_address);
  printf("    use_agg_only_once: %s\n", use_agg_only_once ? "true" : "false");
  printf("    use_fixed_amplitude_per_aggressor: %s\n", (use_fixed_amplitude_per_aggressor ? "true" : "false"));
  printf("    use_unused_pair_as_dummies: %s\n", (use_unused_pair_as_dummies ? "true" : "false"));
  printf("    use_sequential_aggressors: %s\n", (use_sequential_aggressors ? "true" : "false"));
  printf(NONE);
}

void PatternBuilder::hammer_pattern() {
  printf("[+] Hammering using jitted code...\n");
  jitter.fn();
}

void PatternBuilder::cleanup() {
  // rt.release(fn);
  jitter.cleanup();
  aggressor_pairs.clear();
}

void PatternBuilder::get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices) {
  // use all numbers in range (0, ..., num_indices-1 = max) if there is only this one possibility
  indices.resize(num_indices);
  if (max == (num_indices - 1)) {
    std::iota(indices.begin(), indices.end(), 0);
    return;
  }
  // use random numbers between [0, num_indices-1] where num_indices-1 < max
  // use a set to avoid adding the same number multiple times
  std::set<size_t> nums;
  while (nums.size() < num_indices) {
    int candidate = rand() % max;
    if (nums.count(candidate) > 0) continue;
    nums.insert(candidate);
  }
  indices.insert(indices.end(), nums.begin(), nums.end());
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

void PatternBuilder::generate_random_pattern(
    std::vector<uint64_t> bank_rank_masks[], std::vector<uint64_t>& bank_rank_functions,
    u_int64_t row_function, u_int64_t row_increment, int num_activations, int bank_no,
    volatile char** first_address, volatile char** last_address) {
  // a dictionary with the different sizes of N_sided (key) and the sets of hammering pairs (values); this map is used
  // to store aggressor candidates and to determine whether there are still candidates remaining that fit into the
  // remaining allowed activations
  std::map<int, std::vector<std::vector<volatile char*>>> agg_candidates_by_size;

  // TODO: Use count_activations_per_refresh_interval instead of hard-coded machine-specific value (177)
  const size_t total_allowed_accesses = num_aggressors;

  // === utility functions ===========

  // a wrapper around normalize_addr_to_bank that eliminates the need to pass the two last parameters
  auto normalize_address = [&](volatile char* address) {
    return normalize_addr_to_bank(address, bank_rank_masks[bank_no], bank_rank_functions);
  };

  // a wrapper for the logic required to get an address to hammer (or dummy)
  auto add_aggressors = [&](volatile char** cur_next_addr, int N_sided, int agg_inter_distance, int agg_intra_distance,
                            std::vector<std::vector<volatile char*>>& addresses, bool print_agg = true) -> volatile char* {
    // generate a vector like {agg_inter_distance, agg_intra_distance, agg_intra_distance, ... , agg_intra_distance}
    std::vector<int> offsets = {agg_inter_distance};
    if (N_sided > 1) offsets.insert(offsets.end(), N_sided - 1, agg_intra_distance);

    std::vector<volatile char*> output;
    for (const auto& val : offsets) {
      *cur_next_addr = normalize_address(*cur_next_addr + (val * row_increment));
      if (print_agg) printf("%" PRIu64 " (%p) ", get_row_index(*cur_next_addr, row_function), *cur_next_addr);
      output.push_back(*cur_next_addr);
    }
    addresses.push_back(output);
    return *cur_next_addr;
  };

  auto valid_aggressors_exist = [&]() -> bool {
    int remaining_accesses = total_allowed_accesses - aggressor_pairs.size();
    for (const auto& size_aggs : agg_candidates_by_size) {
      if (size_aggs.first < remaining_accesses && !size_aggs.second.empty()) return true;
    }
    return false;
  };

  // ==================================

  printf("[+] Generating a random hammering pattern.\n");

  // sanity check
  if (aggressor_pairs.size() > 0) {
    fprintf(stderr,
            "[-] Cannot generate new pattern without prior cleanup. "
            "Invoke cleanup_and_rerandomize before requesting a new pattern.\n");
    exit(1);
  }

  // stores the pair with the lowest number of activations - this is the one that is hammered again at the end of the
  // refresh interval; in case of use_unused_pair_as_dummies==true we generate a dedicated dummy pair to ensure that it
  // is not hammered
  int dummy_pair_accesses = INT_MAX;
  std::vector<volatile char*> dummy_pair;

  // generate the hammering candidate aggressors
  volatile char* cur_next_addr = normalize_address(random_start_address);
  *first_address = cur_next_addr;
  printf("[+] Candidate aggressor rows: \n");
  for (int i = 0; i < num_aggressors; i++) {
    int N = N_sided.get_random_number();
    printf("    %d-sided: ", N);
    cur_next_addr = add_aggressors(&cur_next_addr, N, agg_inter_distance, agg_intra_distance, agg_candidates_by_size[N]);
    printf("\n");
  }
  *last_address = cur_next_addr;

  // define the maximum number of tries for pattern generation, otherwise in rare cases we won't be able to produce a
  // pattern that fills up the whole "total_accesses" and will get stuck in an endless loop
  const int max_tries = 20;
  int failed_tries = 0;

  // keeps track of the amplitude of each aggressor; is only used if use_fixed_amplitude_per_aggressor == true
  std::map<std::vector<volatile char*>, int> amplitudes_per_agg_pair;

  if (use_sequential_aggressors) {
    size_t N = N_sided.min;
    size_t set_idx = 0;
    while (aggressor_pairs.size() < total_allowed_accesses && valid_aggressors_exist()) {
      auto curr_agg_set = agg_candidates_by_size.at(N).at(set_idx);
      aggressor_pairs.insert(aggressor_pairs.end(), curr_agg_set.begin(), curr_agg_set.end());
      if (!agg_candidates_by_size.at(N).empty() && set_idx < agg_candidates_by_size.at(N).size() - 1) {
        set_idx++;
      } else if (N < (size_t)N_sided.max) {
        N++;
        set_idx = 0;
      } else {
        // restart again from the beginning
        N = N_sided.min;
        set_idx = 0;
      }
    }
  } else {
    // generate the hammering pattern
    while (aggressor_pairs.size() < total_allowed_accesses && valid_aggressors_exist() && failed_tries < max_tries) {
      int remaining_accesses = total_allowed_accesses - aggressor_pairs.size();

      // determine N of N-sided pair such that N still fits into the remaining accesses (otherwise we wouldn't be able to
      // access all aggressors of the pair once)
      int idx_size = rand() % (std::min(remaining_accesses, N_sided.max) + 1 - N_sided.min) + N_sided.min;
      size_t number_of_sets = agg_candidates_by_size.at(idx_size).size();
      if (number_of_sets == 0) {
        failed_tries++;
        continue;
      }

      // determine a random N-sided hammering pair
      int idx_set = rand() % number_of_sets;
      auto aggressor_set = agg_candidates_by_size.at(idx_size).at(idx_set);
      size_t num_elements_in_aggressor_set = aggressor_set.size();

      // determine the hammering amplitude, i.e., the number of sequential accesses of the aggressors in the pattern
      int M;
      if (use_fixed_amplitude_per_aggressor && amplitudes_per_agg_pair.count(aggressor_set) > 0) {
        // an amplitude has been defined for this aggressor pair before -> use same amplitude again
        M = amplitudes_per_agg_pair[aggressor_set];
      } else {
        // no amplitude is defined for this aggressor pair -> choose new amplitude that fits into remaining accesses
        size_t max_amplitude = (size_t)remaining_accesses / num_elements_in_aggressor_set;
        if (max_amplitude < 1 || (unsigned long)amplitude.min > max_amplitude) {
          failed_tries++;
          continue;
        }
        M = amplitude.get_random_number(max_amplitude);
        if (use_fixed_amplitude_per_aggressor) {
          amplitudes_per_agg_pair[aggressor_set] = M;
        }
      }

      // fill up the aggressor_pairs vector by repeating the aggressor pair M times
      while (M--) aggressor_pairs.insert(aggressor_pairs.end(), aggressor_set.begin(), aggressor_set.end());

      if (!use_unused_pair_as_dummies && num_elements_in_aggressor_set >= 2 && M < dummy_pair_accesses) {
        dummy_pair.clear();
        dummy_pair.insert(dummy_pair.end(), aggressor_set.begin(), aggressor_set.end());
        dummy_pair_accesses = M;
      }

      // if the flag 'use_agg_only_once' is set, then delete the aggressor pair from the map of candidates
      if (use_agg_only_once) {
        auto it = agg_candidates_by_size.at(idx_size).begin();
        std::advance(it, idx_set);
        agg_candidates_by_size.at(idx_size).erase(it);
      }

      // reset the number-of-tries counter
      failed_tries = 0;
    }
  }

  if (use_unused_pair_as_dummies) {
    std::vector<std::vector<volatile char*>> tmp;
    cur_next_addr = add_aggressors(&cur_next_addr, 2, distance_to_dummy_pair, agg_intra_distance, tmp, false);
    dummy_pair = std::move(tmp.front());
  }

  // print generated pattern
  printf("[+] Generated hammering pattern: ");
  for (const auto& a : aggressor_pairs) printf("%" PRIu64 " ", get_row_index(a, row_function));
  printf("\n");
  printf("[+] Dummy pair: ");
  for (const auto& a : dummy_pair) printf("%" PRIu64 " ", get_row_index(a, row_function));
  printf("\n");

  // TODO: Take list of aggressors and do double pointer chasing
  // volatile char* first_start = nullptr, second_start = nullptr;
  // encode_double_ptr_chasing(aggressor_pairs, &first_start, &second_start);

  // generate jitted hammering code that hammers these selected addresses
  jitter.jit_hammering_code_fenced(agg_rounds, num_refresh_intervals, aggressor_pairs, fencing_strategy, flushing_strategy, dummy_pair);
}
