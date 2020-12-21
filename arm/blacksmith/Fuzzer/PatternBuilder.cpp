#include <unordered_set>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "DramAnalyzer.hpp"

extern "C" {
#include "rh_misc.h"
}

PatternBuilder::PatternBuilder() {
  gen = std::mt19937(misc_get_us());
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

void PatternBuilder::fill_slots(size_t start_period,
                                size_t period,
                                size_t amplitude,
                                std::vector<Aggressor> &aggressors,
                                std::vector<Aggressor> &accesses,
                                size_t pattern_length) {
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

void PatternBuilder::generate_frequency_based_pattern(FuzzingParameterSet &fuzzing_params,
                                                      std::vector<Aggressor> &accesses,
                                                      std::vector<AggressorAccessPattern> &agg_access_patterns) {
  size_t last_agg_idx = 0;
  int pattern_length = fuzzing_params.get_total_acts_pattern();
  auto base_period = (size_t) fuzzing_params.get_base_period();
  size_t num_base_periods = fuzzing_params.get_total_acts_pattern()/fuzzing_params.get_base_period();
  size_t cur_period = 0;
  accesses = std::vector<Aggressor>(fuzzing_params.get_total_acts_pattern(), Aggressor());

  // find x that are powers of two s.t. x < num_base_periods
  std::vector<int> allowed_multiplicators;
  for (int i = 0; std::pow(2, i) <= num_base_periods; ++i) {
    allowed_multiplicators.push_back(std::pow(2, i));
  }
//  pattern.max_period = allowed_multiplicators.back()*base_period;

  for (size_t k = 0; k < base_period; ++k) {
    if (accesses[k].id!=ID_PLACEHOLDER_AGG) continue;

    std::vector<int> cur_multiplicators(allowed_multiplicators.begin(), allowed_multiplicators.end());
    auto cur_m = cur_multiplicators.at(get_random_gaussian(cur_multiplicators));
    remove_smaller_than(cur_multiplicators, cur_m);
    cur_period = base_period*cur_m;

    auto num_aggressors = ((base_period - k)==1) ? 1 : fuzzing_params.get_random_N_sided(base_period - k);
    auto cur_amplitude = fuzzing_params.get_random_amplitude((int) (base_period - k)/num_aggressors);

    std::vector<Aggressor> aggressors;
    get_n_aggressors(num_aggressors, aggressors, last_agg_idx);
    agg_access_patterns.emplace_back(cur_period, cur_amplitude, aggressors, k);
    fill_slots(k, cur_period, cur_amplitude, aggressors, accesses, pattern_length);

    for (auto next_slot = all_slots_full(k, base_period, pattern_length, accesses);
         next_slot!=-1;
         next_slot = all_slots_full(k, base_period, pattern_length, accesses)) {
      auto cur_m2 = cur_multiplicators.at(get_random_gaussian(cur_multiplicators));
      remove_smaller_than(cur_multiplicators, cur_m2);
      cur_period = base_period*cur_m2;
      get_n_aggressors(num_aggressors, aggressors, last_agg_idx);
      agg_access_patterns.emplace_back(cur_period, cur_amplitude, aggressors, next_slot);
      fill_slots(next_slot, cur_period, cur_amplitude, aggressors, accesses, pattern_length);
    }
  }
}
