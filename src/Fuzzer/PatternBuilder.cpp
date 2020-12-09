#include <unordered_set>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "DramAnalyzer.hpp"

PatternBuilder::PatternBuilder(HammeringPattern &hammering_pattern) : pattern(hammering_pattern) {
  std::random_device rd;
  gen = std::mt19937(rd());
}

size_t PatternBuilder::get_random_gaussian(std::vector<int> &list) {
  size_t result{0};
  do {
    size_t mean = (list.size()%2==0) ? list.size()/2 - 1 : (list.size() - 1)/2;
    std::normal_distribution<> d(mean, 1);
    result = d(gen);
  } while (result >= list.size());
  return result;
}

void PatternBuilder::remove_smaller_than(std::vector<int> &vec, int N) {
  vec.erase(std::remove_if(vec.begin(), vec.end(), [&](const int &x) {
    return x < N;
  }), vec.end());
};

int PatternBuilder::all_slots_full(size_t offset, size_t period, int pattern_length, std::vector<Aggressor> &aggs) {
  for (size_t i = 0; i < aggs.size(); ++i) {
    auto idx = (offset + i*period)%pattern_length;
    if (aggs[idx].id==ID_PLACEHOLDER_AGG) return idx;
  }
  return -1;
};

void PatternBuilder::fill_slots(size_t start_period, size_t period, size_t amplitude, std::vector<Aggressor> &aggressors,
                                std::vector<Aggressor> &accesses, size_t pattern_length) {
  // in each period...
  for (size_t idx = start_period; idx < pattern_length; idx += period) {
    // .. for each amplitdue ...
    for (size_t j = 0; j < amplitude; ++j) {
      // .. fill in the aggressors
      for (size_t a = 0; a < aggressors.size(); ++a) {
        auto next_target = idx + (aggressors.size()*j) + a;
        if (next_target > pattern_length) return;
        accesses[next_target] = aggressors[a];
      }
    }
  }
}

void get_n_aggressors(size_t N, std::vector<Aggressor> &aggs, size_t &next_idx) {
  aggs.clear();
  const size_t end_idx = next_idx + N;
  while (next_idx < end_idx) {
    aggs.emplace_back(next_idx++);
  }
};

int PatternBuilder::random_range_step(int min_value, int max_value, int step) {
  return Range<int>(min_value/step, max_value/step).get_random_number(gen)*step;
}

void PatternBuilder::generate_frequency_based_pattern(FuzzingParameterSet &fuzzing_params) {
  size_t last_agg_idx = 0;
  int pattern_length = fuzzing_params.get_total_acts_pattern();
  auto base_period = (size_t) fuzzing_params.get_base_period();
  size_t num_base_periods = fuzzing_params.get_total_acts_pattern()/fuzzing_params.get_base_period();
  size_t cur_period = 0;
  pattern.accesses = std::vector<Aggressor>(fuzzing_params.get_total_acts_pattern(), Aggressor());

  // find x that are powers of two s.t. x < num_base_periods
  std::vector<int> allowed_multiplicators;
  for (int i = 0; std::pow(2, i) <= num_base_periods; ++i) {
    allowed_multiplicators.push_back(std::pow(2, i));
  }

  for (size_t k = 0; k < base_period; ++k) {
    if (pattern.accesses[k].id!=ID_PLACEHOLDER_AGG) continue;

    std::vector<int> cur_multiplicators(allowed_multiplicators.begin(), allowed_multiplicators.end());
    auto cur_m = cur_multiplicators.at(get_random_gaussian(cur_multiplicators));
    remove_smaller_than(cur_multiplicators, cur_m);
    cur_period = base_period*cur_m;

    // TODO: Use get_random_N_sided from fuzzing_params
    auto num_aggressors = ((base_period - k)==1) ? 1 : random_range_step(2, std::min(6UL, base_period - k), 2);
    auto cur_amplitude = fuzzing_params.get_random_amplitude((int) (base_period - k)/num_aggressors);

    std::vector<Aggressor> aggressors;
    get_n_aggressors(num_aggressors, aggressors, last_agg_idx);
    pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, aggressors, k);
    fill_slots(k, cur_period, cur_amplitude, aggressors, pattern.accesses, pattern_length);

    for (auto next_slot = all_slots_full(k, base_period, pattern_length, pattern.accesses);
         next_slot!=-1;
         next_slot = all_slots_full(k, base_period, pattern_length, pattern.accesses)) {
      auto cur_m2 = cur_multiplicators.at(get_random_gaussian(cur_multiplicators));
      remove_smaller_than(cur_multiplicators, cur_m2);
      cur_period = base_period*cur_m2;
      get_n_aggressors(num_aggressors, aggressors, last_agg_idx);
      pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, aggressors, next_slot);
      fill_slots(next_slot, cur_period, cur_amplitude, aggressors, pattern.accesses, pattern_length);
    }
  }
}

// OLD
//void PatternBuilder::generate_frequency_based_pattern_old(FuzzingParameterSet &fuzzing_params) {
//  pattern.accesses = std::vector<Aggressor>(fuzzing_params.get_total_acts_pattern(), Aggressor());
//  pattern.base_period = fuzzing_params.get_base_period();
//  pattern.max_period = fuzzing_params.get_max_period();
//  pattern.total_activations = fuzzing_params.get_total_acts_pattern();
//  pattern.num_refresh_intervals = fuzzing_params.get_num_refresh_intervals();
//  size_t cur_period = pattern.base_period;
//
//  std::vector<std::vector<Aggressor>> pairs;
//
//  // ---- some helper functions that are needed in the following ----------
//
//  auto empty_slots_exist =
//      [](size_t offset, int base_period, int &next_offset, std::vector<Aggressor> &aggressors) -> bool {
//        for (size_t i = offset; i < aggressors.size(); i += base_period) {
//          // printf("[DEBUG] Checking index %zu: %s\n", i, pattern[i].to_string().c_str());
//          if (aggressors[i].id==ID_PLACEHOLDER_AGG) {
////            printf("[DEBUG] Empty slot found at idx: %zu\n", i);
//            next_offset = i;
//            return true;
//          }
//        }
//        return false;
//      };
//
//  std::random_device rd;
//  std::mt19937 gen = std::mt19937(rd());
//  auto get_random_N_sided_agg = [&](size_t N) -> std::vector<Aggressor> {
//    if (N < (size_t) fuzzing_params.get_n_sided_range().min && N > (size_t) fuzzing_params.get_n_sided_range().max) {
//      fprintf(stderr, "[-] Given N in get_random_N_sided_agg is out of bounds of its valid range!\n");
//    }
//    std::shuffle(pairs.begin(), pairs.end(), gen);
//    for (auto &agg_set : pairs) {
//      if (agg_set.size()==N) return agg_set;
//    }
//    // this should never happen as we ensure that there's at least 1 aggressor set for each N in the given range
//    return {};
//  };
//
//  size_t next_idx = 0;
//  auto get_next_agg = [&pairs, &next_idx](size_t N) -> std::vector<Aggressor> {
//    auto max_tries = pairs.size() + 1;
//    std::vector<Aggressor> ret_value;
//    do {
//      ret_value = pairs.at(next_idx);
//      next_idx = (next_idx + 1UL)%pairs.size();
//      max_tries--;
//    } while (ret_value.size()!=N && max_tries > 0);
//    return ret_value;
//  };
//
//  // ----------------------------------------------------------------------
//
//  // generate aggressor sets
//  // we do not need to consider there that an aggressor could be part of an aggressor pair and at the same time be
//  // accessed as a single aggressor only; this will be handled later by mapping multiple Aggressor objects by their ID
//  // to the same address
//
//
//  int agg_id_cnt = 0;  // this equals the number of added aggressors
//
//  int current_N = fuzzing_params.get_n_sided_range().min;
//  for (; current_N < fuzzing_params.get_n_sided_range().max && agg_id_cnt < fuzzing_params.get_num_aggressors();
//         ++current_N) {
//    std::vector<Aggressor> data;
//    data.reserve(current_N);
//    for (int j = 0; j < current_N; j++) {
//      data.emplace_back(agg_id_cnt++);
//    }
//    pairs.push_back(data);
//  }
//
//  for (size_t i = agg_id_cnt; i < (size_t) fuzzing_params.get_num_aggressors(); ++i) {
//    const int N = fuzzing_params.get_random_N_sided();
//    std::vector<Aggressor> data;
//    data.reserve(N);
//    for (int j = 0; j < N; j++) {
//      data.emplace_back(agg_id_cnt++);
//    }
//    pairs.push_back(data);
//    i += N;
//  }
//
//  // TODO: I am not sure if it makes sense to randomize the abstract aggressors too; I think it is sufficient if we
//  //  have the 'use sequential addresses' logic in the PatternAddressMapping
//  const bool use_seq_aggs = fuzzing_params.get_random_use_seq_addresses();
////  printf("[DEBUG] use_seq_aggs: %s\n", use_seq_aggs ? "true" : "false");
//
//  // generate the pattern by iterating over all slots in the base period
//  for (size_t i = 0; i < pattern.base_period; ++i) {
//    // check if this slot was already filled up by (an) amplified aggressor(s)
//    if (pattern.accesses[i].id!=ID_PLACEHOLDER_AGG) {
////      printf("[DEBUG] Skipping idx %zu because pattern.accesses[%zu].id!=-1\n", i, i);
//      continue;
//    }
//
//    // repeat until the current time slot k is filled up in each k+i*base_period
//    int next_offset = i;
//    int cur_N = fuzzing_params.get_random_N_sided();
//    cur_period = pattern.base_period;
//
//    // choose a random amplitude
//    auto cur_amplitude = (size_t) fuzzing_params.get_random_amplitude(fuzzing_params.get_base_period()/cur_N);
//
//    do {
//      // define the period to use for the next agg(s)
//      cur_period = pattern.base_period*Range<size_t>(
//          cur_period/pattern.base_period,
//          fuzzing_params.get_max_period()/pattern.base_period).get_random_number(gen);
//
//      // agg can be a single agg or a N-sided pair
//      std::vector<Aggressor> agg = use_seq_aggs ? get_next_agg(cur_N) : get_random_N_sided_agg(cur_N);
//
//      // if there's only one aggressor then successively accessing it multiple times does not trigger any activations
//      if (agg.empty()) {
//        continue;
//      } else if (agg.size()==1) {
//        cur_amplitude = 1;
//      }
////      printf("[DEBUG] cur_amplitude: %lu\n", cur_amplitude);
//
//      // generates an AggressorAccess for this aggressor pair
//      pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, agg, next_offset);
//
//      // fill the pattern with the given aggressors
//      // - period
//      for (size_t offt_period = 0; offt_period < pattern.accesses.size(); offt_period += cur_period) {
//        // - amplitude
//        for (size_t num_amplitude = 0; num_amplitude < cur_amplitude; num_amplitude++) {
//          // - aggressors
//          for (size_t idx_agg = 0; idx_agg < agg.size(); idx_agg++) {
//            auto idx = offt_period + next_offset + (num_amplitude*agg.size()) + idx_agg;
////            printf("[DEBUG] filling agg: %s, idx: %zu\n", agg[idx_agg].to_string().c_str(), idx);
//            if (idx >= pattern.accesses.size()) {
//              goto exit_loops;
//            }
//            pattern.accesses[idx] = agg[idx_agg];
//          }
//        }
//      }
//      exit_loops:
//      static_cast<void>(0);  // no-op required for goto
//    } while (empty_slots_exist(i, pattern.base_period, next_offset, pattern.accesses));
//  }
//}

