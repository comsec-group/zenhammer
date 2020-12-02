#include <unordered_set>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "DramAnalyzer.hpp"

PatternBuilder::PatternBuilder(HammeringPattern &hammering_pattern) : pattern(hammering_pattern) {

}

void PatternBuilder::generate_frequency_based_pattern(FuzzingParameterSet &fuzzing_params) {
  pattern.accesses = std::vector<Aggressor>(fuzzing_params.get_total_acts_pattern(), Aggressor());
  pattern.base_period = fuzzing_params.get_base_period();
  size_t cur_period = pattern.base_period;

  std::vector<std::vector<Aggressor>> pairs;

  // ---- some helper functions that are needed in the following ----------

  auto empty_slots_exist =
      [](size_t offset, int base_period, int &next_offset, std::vector<Aggressor> &aggressors) -> bool {
        for (size_t i = offset; i < aggressors.size(); i += base_period) {
          // printf("[DEBUG] Checking index %zu: %s\n", i, pattern[i].to_string().c_str());
          if (aggressors[i].id==ID_PLACEHOLDER_AGG) {
            // printf("[DEBUG] Empty slot found at idx: %zu\n", i);
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
  auto get_next_agg = [&pairs, &next_idx]() -> std::vector<Aggressor> {
    auto ret_value = pairs.at(next_idx);
    next_idx = (next_idx + 1UL)%pairs.size();
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

  const size_t expected_acts = std::max((size_t) 1, fuzzing_params.get_total_acts_pattern()/pattern.base_period);

  // generate the pattern by iterating over all slots in the base period
  for (size_t i = 0; i < pattern.base_period; ++i) {
    // check if this slot was already filled up by (an) amplified aggressor(s)
    if (pattern.accesses[i].id!=ID_PLACEHOLDER_AGG) continue;

    // choose a random amplitude
    auto cur_amplitude = (size_t) fuzzing_params.get_random_amplitude();

    // repeat until the current time slot k is filled up in each k+i*base_period
    int next_offset = i;
    size_t collected_acts = 0;
    int cur_N = fuzzing_params.get_random_N_sided();
    cur_period = pattern.base_period;

    do {
      // define the period to use for the next agg(s)
      cur_period = cur_period*Range(1, expected_acts, true).get_random_number(gen);
      collected_acts += (fuzzing_params.get_total_acts_pattern()/cur_period);

      // agg can be a single agg or a N-sided pair
      std::vector<Aggressor> agg = (fuzzing_params.use_sequential_aggressor_addresses())
                                   ? get_next_agg()
                                   : get_random_N_sided_agg(cur_N);

      // if there's only one aggressor then successively accessing it multiple times does not trigger any activations
      if (agg.size()==1) cur_amplitude = 1;

      // generates an AggressorAccess for each added aggressor set
      std::unordered_map<int, Aggressor> off_agg_map;
      for (size_t l = 0; l < agg.size(); l++) off_agg_map[l] = agg[l];
      pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, off_agg_map);

      // fill the pattern with the given aggressors
      // - period
      for (size_t j = 0; j*cur_period < pattern.accesses.size(); j++) {
        // - amplitude
        for (size_t m = 0; m < cur_amplitude; m++) {
          // - aggressors
          for (size_t k = 0; k < agg.size(); k++) {
            auto idx = (j*cur_period) + next_offset + (m*agg.size()) + k;
            // printf("filling agg: %s, idx: %zu\n", agg[k].to_string().c_str(), idx);
            if (idx >= pattern.accesses.size()) {
              goto exit_loops;
            }
            pattern.accesses[idx] = agg[k];
          }
        }
      }
      exit_loops:
      static_cast<void>(0);  // no-op required for goto
    } while (empty_slots_exist(i, pattern.base_period, next_offset, pattern.accesses));
  }
}

