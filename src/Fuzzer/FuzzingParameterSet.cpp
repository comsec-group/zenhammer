#include "Fuzzer/FuzzingParameterSet.hpp"

#include <algorithm>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "GlobalDefines.hpp"
#include "Utilities/CustomRandom.hpp"
#include <iostream>

FuzzingParameterSet::FuzzingParameterSet() : /* NOLINT */
    flushing_strategy(FLUSHING_STRATEGY::EARLIEST_POSSIBLE),
    fencing_strategy(FENCING_STRATEGY::LATEST_POSSIBLE) {
      cr = CustomRandom();

      // call randomize_parameters once to initialize static values
      randomize_parameters(false);
}

void FuzzingParameterSet::print_static_parameters() const {
  Logger::log_info("Printing static hammering parameters:");
  Logger::log_data(format_string("agg_intra_distance: %d", agg_intra_distance));
  Logger::log_data(format_string("N_sided dist.: %s", get_dist_string().c_str()));
  Logger::log_data(format_string("hammering_total_num_activations: %d", hammering_total_num_activations));
  if (fixed_acts_per_trefi > 0) {
    Logger::log_data(format_string("acts_per_trefi: %d (fixed)", fixed_acts_per_trefi));
  } else {
    Logger::log_data("acts_per_trefi: (randomized for each pattern)");
  }
}

void FuzzingParameterSet::print_semi_dynamic_parameters() const {
  Logger::log_info("Printing pattern-specific fuzzing parameters:");
  Logger::log_data(format_string("acts_per_trefi: %d", num_activations_per_tREFI));
  Logger::log_data(format_string("num_aggressors: %d", num_aggressors));
  Logger::log_data(format_string("num_refresh_intervals: %d", num_refresh_intervals));
  Logger::log_data(format_string("total_acts_pattern: %zu", total_acts_pattern));
  Logger::log_data(format_string("base_period: %d", base_period));
  Logger::log_data(format_string("agg_inter_distance: %d", agg_inter_distance));
  Logger::log_data(format_string("flushing_strategy: %s", to_string(flushing_strategy).c_str()));
  Logger::log_data(format_string("fencing_strategy: %s", to_string(fencing_strategy).c_str()));
}

void FuzzingParameterSet::print_dynamic_parameters(const size_t bank, bool seq_addresses, int start_row) {
  Logger::log_info("Printing DRAM address-related fuzzing parameters:");
  Logger::log_data(format_string("bank_no: %d", bank));
  Logger::log_data(format_string("use_seq_addresses: %s", (seq_addresses ? "true" : "false")));
  Logger::log_data(format_string("start_row: %d", start_row));
}

void FuzzingParameterSet::print_dynamic_parameters2(int num_aggs_for_sync) {
  Logger::log_info("Printing code jitting-related fuzzing parameters:");
  Logger::log_data(format_string("num_aggressors_for_sync: %d", num_aggs_for_sync));
}

void FuzzingParameterSet::set_distribution(Range<int> range_N_sided, std::unordered_map<int, int> probabilities) {
  std::vector<int> dd;
  for (int i = 0; i <= range_N_sided.max; i += 1) {
    dd.push_back((probabilities.count(i) > 0) ? probabilities.at(i) : (int) 0);
  }
  N_sided_probabilities = std::discrete_distribution<int>(dd.begin(), dd.end());
}

int FuzzingParameterSet::get_random_even_divisior(int n, int min_value) {
  std::vector<int> divisors;
  for (auto i = 1; i <= sqrt(n); i++) {
    if (n%i==0) {
      if ((n/i)==1 && (i%2)==0) {
        divisors.push_back(i);
      } else {
        if (i%2==0) divisors.push_back(i);
        if ((n/i)%2==0) divisors.push_back(n/i);
      }
    }
  }

  std::shuffle(divisors.begin(), divisors.end(), cr.gen);
  for (const auto &e : divisors) {
    if (e >= min_value) return e;
  }

  Logger::log_error(format_string("Could not determine a random even divisor of n=%d. Using n.", n));
  return n;
}

void FuzzingParameterSet::set_acts_per_trefi(int acts_per_trefi) {
  this->num_activations_per_tREFI = acts_per_trefi;
  assert(this->num_activations_per_tREFI % 2 == 0);
}

void FuzzingParameterSet::set_fixed_acts_per_trefi(int fixed_acts_per_trefi) {
  this->fixed_acts_per_trefi = fixed_acts_per_trefi;
}

void FuzzingParameterSet::randomize_parameters(bool print) {
  // pick either the specified fixed ACTs/tREFI value, or randomly generate one.
  if (fixed_acts_per_trefi > 0) {
    num_activations_per_tREFI = fixed_acts_per_trefi;
  } else {
    num_activations_per_tREFI = Range<int>(20, 100).get_random_number(cr.gen);
  }
  // make sure that the number of activations per tREFI is even: this is required for proper pattern generation
  num_activations_per_tREFI -= (num_activations_per_tREFI % 2);

  if (print) Logger::log_info("Randomizing fuzzing parameters.");

  // █████████ DYNAMIC FUZZING PARAMETERS ████████████████████████████████████████████████████
  // are randomized for each added aggressor

  // [derivable from aggressors in AggressorAccessPattern]
  // note that in PatternBuilder::generate also uses 1-sided aggressors in case that the end of a base period needs to
  // be filled up
  N_sided = Range<int>(2, 12);
  // N_sided = Range<int>(1, 2);

  // [exported as part of AggressorAccessPattern]
  // choosing as max 'num_activations_per_tREFI/N_sided.min' allows hammering an agg pair for a whole REF interval;
  // we set the upper bound in dependent of N_sided.min but need to (manually) exclude 1 because an amplitude>1 does
  // not make sense for a single aggressor
  amplitude = Range<int>(1, num_activations_per_tREFI*4);

  // == are randomized for each different set of addresses a pattern is probed with ======

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  use_sequential_aggressors = Range<int>(0, 1);

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  start_row = Range<int>(0, 32);

  // █████████ STATIC FUZZING PARAMETERS ████████████████████████████████████████████████████
  // fix values/formulas that must be configured before running this program

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  agg_intra_distance = Range<int>(2, 2).get_random_number(cr.gen);

  // [CANNOT be derived from anywhere else - but does not fit anywhere: will print to stdout only, not include in json]
//  auto strategy = get_valid_strategy_pair();
//  flushing_strategy = strategy.first;
//  fencing_strategy = strategy.second;
  flushing_strategy = FLUSHING_STRATEGY::BATCHED;
  fencing_strategy = FENCING_STRATEGY::LATEST_POSSIBLE;

  // [CANNOT be derived from anywhere else - must explicitly be exported]
  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then this translates to:
  // pick a 1-sided pair with 20% probability and a 2-sided pair with 80% probability
  // Note if using N_sided = Range<int>(min, max, step), then the X values 
  // provided here as (X, Y) correspond to
  // the multiplier (e.g., multiplier's minimum is min/step and multiplier's 
  // maximum is max/step) 
  // set_distribution(N_sided, {{1, 10}, {2, 100}});
  std::unordered_map<int, int> probabilities;
  for (int k = N_sided.min; k < N_sided.max; ++k) {
    probabilities[k] = 100;
  }
  set_distribution(N_sided, probabilities);

  // [CANNOT be derived from anywhere else - must explicitly be exported]
  hammering_total_num_activations = 10'000'000;

  // █████████ SEMI-DYNAMIC FUZZING PARAMETERS ████████████████████████████████████████████████████
  // are only randomized once when calling this function

  // [derivable from aggressors in AggressorAccessPattern, also not very expressive because different agg IDs can be
  // mapped to the same DRAM address]
  num_aggressors = Range<int>(4,64).get_random_number(cr.gen);

  // [included in HammeringPattern]
  // it is important that this is a power of two, otherwise the aggressors in the pattern will not respect frequencies
  num_refresh_intervals = static_cast<int>(std::pow(2, Range<int>(2, 6).get_random_number(cr.gen)));

  // [included in HammeringPattern]
  total_acts_pattern = num_activations_per_tREFI*num_refresh_intervals;

  // [included in HammeringPattern]
  base_period = get_random_even_divisior(total_acts_pattern, 4);
//  base_period = num_activations_per_tREFI;

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  agg_inter_distance = Range<int>(2, 12).get_random_number(cr.gen);

  if (print)
    print_semi_dynamic_parameters();
}

std::string FuzzingParameterSet::get_dist_string() const {
  std::stringstream ss;
  double total = 0;
  std::vector<double> probs = N_sided_probabilities.probabilities();
  for (const auto &d : probs) total += d;
  for (size_t i = 0; i < probs.size(); ++i) {
    if (probs[i]==0) continue;
    ss << i << "-sided: " << probs[i] << "/" << total << ", ";
  }
  return ss.str();
}

int FuzzingParameterSet::get_hammering_total_num_activations() const {
  return hammering_total_num_activations;
}

int FuzzingParameterSet::get_num_aggressors() const {
  return num_aggressors;
}

int FuzzingParameterSet::get_random_N_sided() {
  return N_sided_probabilities(cr.gen);
}

int FuzzingParameterSet::get_random_N_sided(int upper_bound_max) {
  if (N_sided.max > upper_bound_max) {
    return Range<int>(N_sided.min, upper_bound_max).get_random_number(cr.gen);
  }
  return get_random_N_sided();
}

bool FuzzingParameterSet::get_random_use_seq_addresses() {
  return (bool) (use_sequential_aggressors.get_random_number(cr.gen));
}

int FuzzingParameterSet::get_total_acts_pattern() const {
  return total_acts_pattern;
}

int FuzzingParameterSet::get_base_period() const {
  return base_period;
}

int FuzzingParameterSet::get_num_base_periods() const {
  return (int)(get_total_acts_pattern()/(size_t)get_base_period());
}

int FuzzingParameterSet::get_agg_intra_distance() const {
  return agg_intra_distance;
}

int FuzzingParameterSet::get_agg_inter_distance() const {
  return agg_inter_distance;
}

int FuzzingParameterSet::get_random_amplitude(int max) {
  return Range<>(amplitude.min, std::min(amplitude.max, max)).get_random_number(cr.gen);
}

int FuzzingParameterSet::get_num_activations_per_t_refi() const {
  return num_activations_per_tREFI;
}

int FuzzingParameterSet::get_random_start_row() {
  return start_row.get_random_number(cr.gen);
}

int FuzzingParameterSet::get_num_refresh_intervals() const {
  return num_refresh_intervals;
}

void FuzzingParameterSet::set_total_acts_pattern(int pattern_total_acts) {
  FuzzingParameterSet::total_acts_pattern = pattern_total_acts;
}

void FuzzingParameterSet::set_hammering_total_num_activations(int hammering_total_acts) {
  FuzzingParameterSet::hammering_total_num_activations = hammering_total_acts;
}

void FuzzingParameterSet::set_agg_intra_distance(int agg_intra_dist) {
  FuzzingParameterSet::agg_intra_distance = agg_intra_dist;
}

void FuzzingParameterSet::set_agg_inter_distance(int agg_inter_dist) {
  FuzzingParameterSet::agg_inter_distance = agg_inter_dist;
}

void FuzzingParameterSet::set_use_sequential_aggressors(const Range<int> &use_seq_addresses) {
  FuzzingParameterSet::use_sequential_aggressors = use_seq_addresses;
}
