#include <unordered_set>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "DramAnalyzer.hpp"

PatternBuilder::PatternBuilder(HammeringPattern &hammering_pattern) : pattern(hammering_pattern) {

}

void PatternBuilder::generate_frequency_based_pattern(FuzzingParameterSet &fuzzing_params) {
  pattern.accesses = std::vector<Aggressor>(fuzzing_params.get_total_acts_pattern(), Aggressor());
  pattern.base_period = fuzzing_params.get_base_period();
  pattern.max_period = fuzzing_params.get_max_period();
  pattern.total_activations = fuzzing_params.get_total_acts_pattern();
  pattern.num_refresh_intervals = fuzzing_params.get_num_refresh_intervals();
  size_t cur_period = pattern.base_period;

  std::vector<std::vector<Aggressor>> pairs;

  // ---- some helper functions that are needed in the following ----------

  auto empty_slots_exist =
      [](size_t offset, int base_period, int &next_offset, std::vector<Aggressor> &aggressors) -> bool {
        for (size_t i = offset; i < aggressors.size(); i += base_period) {
          // printf("[DEBUG] Checking index %zu: %s\n", i, pattern[i].to_string().c_str());
          if (aggressors[i].id==ID_PLACEHOLDER_AGG) {
//            printf("[DEBUG] Empty slot found at idx: %zu\n", i);
            next_offset = i;
            return true;
          }
        }
        return false;
      };

  std::random_device rd;
  std::mt19937 gen = std::mt19937(rd());
  auto get_random_N_sided_agg = [&](size_t N) -> std::vector<Aggressor> {
    std::shuffle(pairs.begin(), pairs.end(), gen);
    for (auto &agg_set : pairs) {
      if (agg_set.size()==N) return agg_set;
    }
    fprintf(stderr, "[-] Couldn't get a N-sided aggressor pair but this shouldn't have happened.\n");
    exit(1);
  };

  size_t next_idx = 0;
  auto get_next_agg = [&pairs, &next_idx](size_t N) -> std::vector<Aggressor> {
    auto max_tries = pairs.size()+1;
    std::vector<Aggressor> ret_value;
    do {
      ret_value = pairs.at(next_idx);
      next_idx = (next_idx + 1UL)%pairs.size();
      max_tries--;
    } while (ret_value.size()!=N && max_tries > 0);
    return ret_value;
  };

  // ----------------------------------------------------------------------

  // generate aggressor sets
  // we do not need to consider there that an aggressor could be part of an aggressor pair and at the same time be
  // accessed as a single aggressor only; this will be handled later by mapping multiple Aggressor objects by their ID
  // to the same address


  int agg_id_cnt = 0;  // this equals the number of added aggressors

  int current_N = fuzzing_params.get_n_sided_range().min;
  for (; current_N < fuzzing_params.get_n_sided_range().max && agg_id_cnt < fuzzing_params.get_num_aggressors();
         ++current_N) {
    std::vector<Aggressor> data;
    data.reserve(current_N);
    for (int j = 0; j < current_N; j++) {
      data.emplace_back(agg_id_cnt++);
    }
    pairs.push_back(data);
  }

  for (size_t i = agg_id_cnt; i < (size_t) fuzzing_params.get_num_aggressors(); ++i) {
    const int N = fuzzing_params.get_random_N_sided();
    std::vector<Aggressor> data;
    data.reserve(N);
    for (int j = 0; j < N; j++) {
      data.emplace_back(agg_id_cnt++);
    }
    pairs.push_back(data);
    i += N;
  }

  // TODO: I am not sure if it makes sense to randomize the abstract aggressors too; I think it is sufficient if we
  //  have the 'use sequential addresses' logic in the PatternAddressMapping
  const bool use_seq_aggs = fuzzing_params.get_random_use_seq_addresses();
//  printf("[DEBUG] use_seq_aggs: %s\n", use_seq_aggs ? "true" : "false");

  // generate the pattern by iterating over all slots in the base period
  for (size_t i = 0; i < pattern.base_period; ++i) {
    // check if this slot was already filled up by (an) amplified aggressor(s)
    if (pattern.accesses[i].id!=ID_PLACEHOLDER_AGG) {
//      printf("[DEBUG] Skipping idx %zu because pattern.accesses[%zu].id!=-1\n", i, i);
      continue;
    }

    // repeat until the current time slot k is filled up in each k+i*base_period
    int next_offset = i;
    int cur_N = fuzzing_params.get_random_N_sided();
    cur_period = pattern.base_period;

    // choose a random amplitude
    auto cur_amplitude = (size_t) fuzzing_params.get_random_amplitude(fuzzing_params.get_base_period()/cur_N);

    do {
      // define the period to use for the next agg(s)
      cur_period = pattern.base_period*Range<size_t>(
          cur_period/pattern.base_period,
          fuzzing_params.get_max_period()/pattern.base_period).get_random_number(gen);

      // agg can be a single agg or a N-sided pair
      std::vector<Aggressor> agg = use_seq_aggs ? get_next_agg(cur_N) : get_random_N_sided_agg(cur_N);

      // if there's only one aggressor then successively accessing it multiple times does not trigger any activations
      if (agg.size()==1) {
        cur_amplitude = 1;
      }
//      printf("[DEBUG] cur_amplitude: %lu\n", cur_amplitude);

      // generates an AggressorAccess for this aggressor pair
      pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, agg, i);

      // fill the pattern with the given aggressors
      // - period
      for (size_t offt_period = 0; offt_period < pattern.accesses.size(); offt_period += cur_period) {
        // - amplitude
        for (size_t num_amplitude = 0; num_amplitude < cur_amplitude; num_amplitude++) {
          // - aggressors
          for (size_t idx_agg = 0; idx_agg < agg.size(); idx_agg++) {
            auto idx = offt_period + next_offset + (num_amplitude*agg.size()) + idx_agg;
//            printf("[DEBUG] filling agg: %s, idx: %zu\n", agg[idx_agg].to_string().c_str(), idx);
            if (idx >= pattern.accesses.size()) {
              goto exit_loops;
            }
            pattern.accesses[idx] = agg[idx_agg];
          }
        }
      }
      exit_loops:
      static_cast<void>(0);  // no-op required for goto
    } while (empty_slots_exist(i, pattern.base_period, next_offset, pattern.accesses));
  }
}

