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
    : num_activations_per_tREFI_measured(num_activations), target_addr(target_address) {
  // standard mersenne_twister_engine seeded with rd()
  gen = std::mt19937(rd());
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
  amplitude = Range(1, 2);  // TODO: Add way to hammer aggressors in pair with different amplitudes!
  N_sided = Range(1, 2);
  agg_inter_distance = Range(1, 15);

  // === SEMI-DYNAMIC FUZZING PARAMETERS ====================================================
  // are only randomized once when calling this function

  // num_aggressors = Range(23, 32).get_random_number(gen); // TODO: Start from (3, x)
  num_aggressors = Range(23, 35).get_random_number(gen);
  agg_intra_distance = 2;
  random_start_address = target_addr + (Range(MB(100), MEM_SIZE - MB(100)).get_random_number(gen) / PAGE_SIZE) * PAGE_SIZE;
  use_sequential_aggressors = true; // (bool)(Range(0, 1).get_random_number(gen));  // TODO: Make this random again
  agg_frequency = Range(1, 2);                                 // TODO: Set back to (1,10)
  num_refresh_intervals = Range(1, 3).get_random_number(gen);  // TODO: Set back to (1,8)
  sync_after_every_nth_hammering_rep = Range(1, num_refresh_intervals).get_random_number(gen);

  // hammering_reps_before_sync = Range(1, 4).get_random_number(gen);
  hammering_reps_before_sync = num_activations_per_tREFI_measured / num_aggressors;
  // hammering_reps_before_sync = num_refresh_intervals;

  // e.g., (1,4) means each aggressor is accessed at least once (1,-) and at most 4 times (-, 4) in a sequence
  // num_activations_per_tREFI = num_activations_per_tREFI_measured * 1.15;
  // std::vector<int> options = {20, 30, 40, 75, 85, 90, 100, 110, 115, 160, 175, 180};
  // num_activations_per_tREFI = options.at(Range(0, options.size()).get_random_number());
  num_activations_per_tREFI = num_aggressors;

  // === STATIC FUZZING PARAMETERS ====================================================
  // fix values/formulas that must be configured before running this program

  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;
  fencing_strategy = FENCING_STRATEGY::OMIT_FENCING;
  use_fixed_amplitude_per_aggressor = false;

  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then it translates to: pick a 1-sided pair with 20% probability and a
  // 2-sided pair with 80% probability
  std::unordered_map<int, int> distribution = {{1, 2}, {2, 8}};
  N_sided_probabilities = build_distribution(N_sided, distribution);

  // total_acts_pattern = num_activations_per_tREFI * num_refresh_intervals;
  // total_acts_pattern = num_aggressors* Range(1,4).get_random_number(gen);
  total_acts_pattern = num_aggressors;

  // hammering_total_num_activations is derived as follow:
  //  REF interval: 7.8 μs (tREFI), retention time: 64 ms => 8,000 - 10,000 REFs per interval
  //  num_activations_per_tREFI: ≈100                     => 10,000 * 100 = 1M activations * 3 = 3M ACTs
  // hammering_total_num_activations = 3000000; // TODO uncomment me
  // hammering_total_num_activations = Range({21000, 350000}).get_random_number();
  // hammering_total_num_activations = num_activations_per_tREFI * num_refresh_intervals;
  hammering_total_num_activations = HAMMER_ROUNDS / (num_activations_per_tREFI_measured / total_acts_pattern);
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

void PatternBuilder::generate_random_pattern(
    std::vector<uint64_t> bank_rank_masks[], std::vector<uint64_t>& bank_rank_functions,
    u_int64_t row_function, u_int64_t row_increment, int bank_no,
    volatile char** first_address, volatile char** last_address) {
  aggressor_pairs.clear();

  // a dictionary with the different sizes of N_sided (key) and the sets of hammering pairs (values); this map is used
  // to store aggressor candidates and to determine whether there are still candidates remaining that fit into the
  // remaining allowed activations
  std::map<int, std::vector<std::vector<volatile char*>>> agg_candidates_by_size;

  // === utility functions ===========

  // a wrapper around normalize_addr_to_bank that eliminates the need to pass the two last parameters
  auto normalize_address = [&](volatile char* address) {
    return normalize_addr_to_bank(address, bank_rank_masks[bank_no], bank_rank_functions);
  };

  // a wrapper for the logic required to get an address to hammer
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
    int remaining_accesses = total_acts_pattern - aggressor_pairs.size();
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

  // generate the candidate hammering aggressors
  std::default_random_engine generator;
  volatile char* cur_next_addr = normalize_address(random_start_address);
  *first_address = cur_next_addr;
  printf("[+] Candidate aggressor rows: \n");
  int num_aggressor_candidates = 0;
  while (num_aggressor_candidates < num_aggressors) {
    int N = N_sided_probabilities(generator);
    if (num_aggressor_candidates + N > num_aggressors) {
      // there's no way to fill up the gap -> stop here
      if (num_aggressor_candidates + N_sided.min > num_aggressors) break;
      // there are still suitable Ns to fill up remaining aggressors -> try finding suitable N
      continue;
    }
    printf("    %d-sided: ", N);
    cur_next_addr = add_aggressors(&cur_next_addr, N, agg_inter_distance.get_random_number(gen), agg_intra_distance, agg_candidates_by_size[N]);
    printf("\n");
    num_aggressor_candidates += N;
  }
  *last_address = cur_next_addr;

  // define the maximum number of tries for pattern generation, otherwise in rare cases we won't be able to produce a
  // pattern that fills up the whole "total_accesses" and will get stuck in an endless loop
  const int max_tries = 20;
  int failed_tries = 0;

  // keeps track of the amplitude of each aggressor; is only used if use_fixed_amplitude_per_aggressor == true
  std::map<std::vector<volatile char*>, int> amplitudes_per_agg_pair;

  if (use_sequential_aggressors) {
    // generate the hammering pattern using sequentially chosen N-sided aggressors where the sequentiality refers to the
    // order in which aggressors are chosen, i.e., aggressor1 row < aggressor2 row < ... < aggressorN row
    size_t N = N_sided.min;
    size_t set_idx = 0;
    printf("[+] Generated hammering pattern: ");
    while (aggressor_pairs.size() < total_acts_pattern && valid_aggressors_exist()) {
      auto curr_agg_set = agg_candidates_by_size.at(N).at(set_idx);
      aggressor_pairs.insert(aggressor_pairs.end(), curr_agg_set.begin(), curr_agg_set.end());
      // print pattern
      printf("(");
      for (size_t k = 0; k < curr_agg_set.size(); k++) {
        printf("%" PRIu64, get_row_index(curr_agg_set[k], row_function));
        if (k < curr_agg_set.size() - 1) printf(",");
      }
      printf(") ");
      // update the N and/or set_idx according to the data present in agg_candidates_by_size
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
    // a copy of the agg_candidates_by_size as we will remove elements from there but later must restore them
    std::map<int, std::vector<std::vector<volatile char*>>>
        backup_candidates(agg_candidates_by_size.begin(), agg_candidates_by_size.end());

    // a map that keeps track how often a specific aggressor pair was picked, uses a string built out of the aggressor's
    // row as key; note that a value of X means that the aggressor pair was picked X times whereas each time it can
    // appear in the pattern for a certain amplitude (i.e., number of repeated accesses)
    std::unordered_map<std::string, int> frequency_counts;

    int num_accesses_req_until_min_freq = num_aggressor_candidates * agg_frequency.min;
    // do not try to fulfill the agg_frequency.min in case that it is not feasible anyway
    // idea here: if (...) is true, then we set minimum_frequency_reached to False to intelligently pick the amplitude
    // of the aggressors; otherwise it won't work anyway and we thus set it directly to True
    bool minimum_frequency_reached =
        !(total_acts_pattern >= (size_t)num_accesses_req_until_min_freq) || (agg_frequency.min == 0);
    int num_times_each_agg_accessed = 0;

    printf("[+] Generated hammering pattern: ");

    // generate the hammering pattern using random N-sided aggressors picked from an arbitrary location within the
    // allocated superpage
    while (aggressor_pairs.size() < total_acts_pattern && valid_aggressors_exist() && failed_tries < max_tries) {
      int remaining_accesses = total_acts_pattern - aggressor_pairs.size();

      // determine N of N-sided pair such that N still fits into the remaining accesses (otherwise we wouldn't be able to
      // access all aggressors of the pair once)
      int idx_size = Range(N_sided.min, std::min(remaining_accesses, N_sided.max)).get_random_number(gen);

      size_t number_of_sets = agg_candidates_by_size.at(idx_size).size();
      if (number_of_sets == 0) {
        failed_tries++;
        continue;
      }

      // determine a random N-sided hammering pair
      int idx_set = Range(0, number_of_sets - 1).get_random_number(gen);
      auto& suitable_candidates = agg_candidates_by_size.at(idx_size);
      auto& aggressor_set = suitable_candidates.at(idx_set);
      frequency_counts[get_row_string(aggressor_set, row_function)]++;
      size_t num_elements_in_aggressor_set = aggressor_set.size();

      // determine the hammering amplitude, i.e., the number of sequential accesses of the aggressors in the pattern
      int M;
      if (use_fixed_amplitude_per_aggressor && amplitudes_per_agg_pair.count(aggressor_set) > 0) {
        // an amplitude has been defined for this aggressor pair before -> use same amplitude again
        M = amplitudes_per_agg_pair[aggressor_set];
      } else {
        // limit amplitude by considering how many aggressors still fit into the remaining accesses (if) or how many
        // we still need to access to fulfill agg_frequency.min (else)
        int M_max;
        if (minimum_frequency_reached) {
          // trivial case: we just need to make sure that M won't become too large to fit into remaining accesses
          M_max = std::min(remaining_accesses, amplitude.max);
        } else {
          // choose M in a way that we can access all aggressors at least agg_frequency.min times
          // M_max = std::min(remaining_accesses-num_accesses_req_until_min_freq, amplitude.max);
          M_max = std::min(remaining_accesses / num_accesses_req_until_min_freq, amplitude.max);
        }

        if (aggressor_set.size() == 1) {
          // if this is a single-sided aggressor then accessing it multiple times does not make any sense as repeated
          // accessed would be served by row buffer instead of generating new activation 
          M = 1;
        } else {
          // no amplitude is defined for this aggressor pair yet -> choose new amplitude that fits into rem. accesses
          M = amplitude.get_random_number(M_max, gen);
          if (M < 1 || amplitude.min > M) {
            failed_tries++;
            continue;
          }
        }

        // check if we need to store this amplitude for the next use of this aggressor
        if (use_fixed_amplitude_per_aggressor) {
          amplitudes_per_agg_pair[aggressor_set] = M;
        }
      }

      // print generated pattern
      printf("%dx(", M);
      for (size_t h = 0; h < aggressor_set.size(); h++) {
        printf("%" PRIu64, get_row_index(aggressor_set[h], row_function));
        if (h < aggressor_set.size() - 1) printf(" ");
      }
      printf(") ");

      // fill up the aggressor_pairs vector by repeating the aggressor pair M times
      while (M--) aggressor_pairs.insert(aggressor_pairs.end(), aggressor_set.begin(), aggressor_set.end());

      if (!minimum_frequency_reached || frequency_counts[get_row_string(aggressor_set, row_function)] == agg_frequency.max) {
        num_accesses_req_until_min_freq -= aggressor_set.size();
        suitable_candidates.erase(suitable_candidates.begin() + idx_set);

        if (!minimum_frequency_reached) {
          // printf("[DEBUG] agg_frequency not reached yet\n");
          // if all are empty -> restore backup and increase "num_all_accessed" counter
          // (all are empty if the aggressor_pairs is a multiple of the total candidates)
          bool all_empty = false;
          size_t total_size = 0;
          for (const auto& pair : agg_candidates_by_size) {
            for (const auto& vec : pair.second) {
              all_empty |= vec.empty();
              total_size += vec.size();
            }
          }

          if (all_empty || !valid_aggressors_exist()) {
            num_times_each_agg_accessed++;
            // if num_all_accessed counter equals the number of minimum accesses per agg -> set minimum_frequency_reached
            minimum_frequency_reached = (num_times_each_agg_accessed == agg_frequency.min) ? true : false;
            agg_candidates_by_size.clear();
            agg_candidates_by_size.insert(backup_candidates.begin(), backup_candidates.end());
          }
        }
      }

      // reset the number-of-tries counter
      failed_tries = 0;
    }
  }  // end: if (use_sequential_aggressors) { ... } else { ... }

  printf("[total: %zu aggs]\n", aggressor_pairs.size());

  // now trigger the code jitting
  jit_code();
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
