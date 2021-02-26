#include <unordered_set>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Memory/DramAnalyzer.hpp"

PatternBuilder::PatternBuilder(HammeringPattern &hammering_pattern)
    : pattern(hammering_pattern), aggressor_id_counter(1) {
  std::random_device rd;
  gen = std::mt19937(rd());
}

size_t PatternBuilder::get_random_gaussian(std::vector<int> &list) {
  // this 'repeat until we produce a valid value' approach is not very effective
  size_t result;
  do {
    size_t mean = (list.size()%2==0) ? list.size()/2 - 1 : (list.size() - 1)/2;
    std::normal_distribution<> d(mean, 1);
    result = (size_t) d(gen);
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

void PatternBuilder::fill_slots(const size_t start_period,
                                const size_t period_length,
                                const size_t amplitude,
                                std::vector<Aggressor> &aggressors,
                                std::vector<Aggressor> &accesses,
                                size_t pattern_length) {

  // the "break"s are important here as the function we use to compute the next target index is not continuously
  // increasing, i.e., if we computed an invalid index in the innermost loop, increasing the loop in the middle may
  // produce an index that is still valid, therefore we need to "break" instead of returning directly

  // in each period_length...
  for (size_t period = start_period; period < pattern_length; period += period_length) {
    // .. for each amplitdue ...
    for (size_t amp = 0; amp < amplitude; ++amp) {
      if (period + (aggressors.size()*amp) >= pattern_length) break;
      // .. fill in the aggressors
      for (size_t agg_idx = 0; agg_idx < aggressors.size(); ++agg_idx) {
        auto next_target = period + (aggressors.size()*amp) + agg_idx;
        if (next_target >= pattern_length) break;
        accesses[next_target] = aggressors[agg_idx];
      }
    }
  }
}

void PatternBuilder::get_n_aggressors(size_t N, std::vector<Aggressor> &aggs, int max_num_aggressors) {
  // clean any existing aggressor in the given vector
  aggs.clear();

  // increment the ID cyclically until we added N aggressors
  for (size_t added_aggs = 0; added_aggs < N; aggressor_id_counter = ((aggressor_id_counter + 1)%max_num_aggressors)) {
    aggs.emplace_back((int) aggressor_id_counter);
    added_aggs++;
  }
};

std::vector<int> PatternBuilder::get_available_multiplicators(FuzzingParameterSet &fuzzing_params) {
  return get_available_multiplicators(fuzzing_params.get_num_base_periods());
}

std::vector<int> PatternBuilder::get_available_multiplicators(int num_base_periods) {
  // a multiplicator M is an integer such that
  //    [1] (M * base_period) is a valid frequency
  //    [2] M^2 is smaller-equal to num_base_periods
  std::vector<int> allowed_multiplicators;
  for (size_t i = 0; std::pow(2, i) <= num_base_periods; ++i) {
    allowed_multiplicators.push_back(std::pow(2, i));
  }
  return allowed_multiplicators;
}

void PatternBuilder::generate_frequency_based_pattern(FuzzingParameterSet &params,
                                                      int pattern_length,
                                                      size_t base_period) {
  std::vector<int> start_indices_prefilled_slots;
  auto cur_prefilled_slots_idx = 0;
  // this is a helper function that takes the current index (of base_period) and then returns the index of either the
  // next prefilled slot (if pattern was prefilled) or just returns the last index of the base period
  auto get_next_prefilled_slot = [&](size_t cur_idx) {
    // no prefilled pattern: use base_period as bound
    if (start_indices_prefilled_slots.size() == 0)
      return (int)base_period;

    // prefilled pattern
    if ((int) cur_idx < start_indices_prefilled_slots[cur_prefilled_slots_idx]) {
      // keep using the current index of the next occupied slot
      return start_indices_prefilled_slots[cur_prefilled_slots_idx];
    } else if ((size_t)cur_prefilled_slots_idx+1 < start_indices_prefilled_slots.size()) {
      // increment the index by one as we still didn't reach the end
      cur_prefilled_slots_idx++;
      return start_indices_prefilled_slots[cur_prefilled_slots_idx];
    } else {
      // we already reached the end, from now on only the base period is our bound
      return (int)base_period;
    }
  };

  // we call this method also for filling up a prefilled pattern (during analysis stage) that already contains some
  // aggressor accesses, in that case we should not clear the aggressors vector
  if (pattern.aggressors.size()==0) {
    pattern.aggressors = std::vector<Aggressor>(params.get_total_acts_pattern(), Aggressor());
  } else {
    // go through aggressors list and figure out prefilled slots but only keep the index of the start slot of a
    // prefilled contiguous area (e.g., "_ _ _ A1 A2 A3 _ _ A4 A5 _ _ _" would only record index of A1 and A4)
    bool in_prefilled_area = false;
    for (size_t i = 0; i < base_period; ++i) {
      if (pattern.aggressors[i].id!=ID_PLACEHOLDER_AGG) {
        if (!in_prefilled_area) {
          in_prefilled_area = true;
          start_indices_prefilled_slots.push_back((int) i);
        }
      } else {
        in_prefilled_area = false;
      }
    }
  }

  // the multiplicators are only dependent on the base period, i.e., we can precompute them once here
  std::vector<int> allowed_multiplicators = get_available_multiplicators(params);
  pattern.max_period = allowed_multiplicators.back()*base_period;

  int cur_amplitude = -1;
  int num_aggressors = -1;
  size_t cur_period = 0;

  // fill the "first" slot in the base period: this is the one that can have any possible frequency
  for (size_t k = 0; k < base_period; k += (num_aggressors*cur_amplitude)) {
    std::vector<Aggressor> aggressors;
    std::vector<int> cur_multiplicators(allowed_multiplicators.begin(), allowed_multiplicators.end());
    // if this slot is not filled yet -> we are generating a new pattern
    if (pattern.aggressors[k].id==ID_PLACEHOLDER_AGG) {
      auto cur_m = cur_multiplicators.at(get_random_gaussian(cur_multiplicators));
      remove_smaller_than(cur_multiplicators, cur_m);
      cur_period = base_period*cur_m;

      if (start_indices_prefilled_slots.size()==0) {
        // if there are no prefilled slots at any index: we are only limited by the base period
        num_aggressors = ((base_period - k)==1) ? 1 : params.get_random_N_sided(base_period - k);
        cur_amplitude = params.get_random_amplitude((int) (base_period - k)/num_aggressors);
      } else {
        // if there are prefilled slots we need to pay attention to not overwrite them either by choosing too many
        // aggressors or by choosing an amplitude that is too large
        auto next_prefilled_idx = get_next_prefilled_slot(k);
        num_aggressors = ((next_prefilled_idx - k)==1) ? 1 : params.get_random_N_sided(next_prefilled_idx - k);
        cur_amplitude = params.get_random_amplitude((int) std::floor((next_prefilled_idx - k)/num_aggressors));
      }
      get_n_aggressors(num_aggressors, aggressors, params.get_num_aggressors());

      pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, aggressors, k);
      fill_slots(k, cur_period, cur_amplitude, aggressors, pattern.aggressors, pattern_length);
    } else {  // this slot is already filled -> this is a prefilled pattern
      // determine the number of aggressors (num_aggressors) and the amplitude (cur_amplitude) based on the information
      // in the associated AggressorAccessPattern of this Aggressor
      auto agg_acc_patt = pattern.get_access_pattern_by_aggressor(pattern.aggressors[k]);
      remove_smaller_than(cur_multiplicators, agg_acc_patt.frequency/base_period);
      num_aggressors = agg_acc_patt.aggressors.size();
      cur_amplitude = agg_acc_patt.amplitude;
    }

    // fill all the remaining slots, i.e., slots at the same offset but in those base period that were not filled up
    // by the previously added aggressor pair. if frequency = base period, then there's nothing to do here as everything
    // is already filled up.
    // example where previously added aggressor pair (A1,A2) has frequency = base_period/2:
    // | A1 A2 _ _ _ _ | _ _ _ _ _ _ | A1 A2 _ _ _ _ | _ _ _ _ _ _ | A1 A2 _ _ _ _ |
    //                            ^ ^                           ^ ^
    // the slots marked by '^' are the ones that we are filling up in the following loop
    for (auto next_slot = all_slots_full(k, base_period, pattern_length, pattern.aggressors);
         next_slot!=-1;
         next_slot = all_slots_full(k, base_period, pattern_length, pattern.aggressors)) {
      auto cur_m2 = cur_multiplicators.at(get_random_gaussian(cur_multiplicators));
      remove_smaller_than(cur_multiplicators, cur_m2);
      cur_period = base_period*cur_m2;
      get_n_aggressors(num_aggressors, aggressors, params.get_num_aggressors());
      pattern.agg_access_patterns.emplace_back(cur_period, cur_amplitude, aggressors, next_slot);
      fill_slots(next_slot, cur_period, cur_amplitude, aggressors, pattern.aggressors, pattern_length);
    }
  }

  // update information in HammeringPattern s.t. it will be included into the JSON export
  pattern.total_activations = pattern.aggressors.size();
  pattern.num_refresh_intervals = params.get_num_refresh_intervals();
}

void PatternBuilder::generate_frequency_based_pattern(FuzzingParameterSet &params) {
  generate_frequency_based_pattern(params, params.get_total_acts_pattern(), (size_t) params.get_base_period());
}

void PatternBuilder::prefill_pattern(int pattern_total_acts,
                                     std::vector<AggressorAccessPattern> &fixed_aggs) {
  aggressor_id_counter = 1;
  pattern.aggressors = std::vector<Aggressor>(pattern_total_acts, Aggressor());
  for (auto &aap : fixed_aggs) {
    for (auto &agg : aap.aggressors) agg.id = aggressor_id_counter++;
    fill_slots(aap.start_offset, aap.frequency, aap.amplitude, aap.aggressors, pattern.aggressors, pattern_total_acts);
    pattern.agg_access_patterns.push_back(aap);
  }
}
