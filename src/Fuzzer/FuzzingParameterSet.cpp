#include <unordered_map>
#include <sstream>
#include <iostream>
#include <algorithm>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "GlobalDefines.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"

FuzzingParameterSet::FuzzingParameterSet(int measured_num_acts_per_ref) { /* NOLINT */
  std::random_device rd;
  gen = std::mt19937_64(rd());  // standard mersenne_twister_engine seeded with some random data

  // make sure that the number of activations per tREFI is even: this is required for proper pattern generation
  num_activations_per_tREFI = (measured_num_acts_per_ref/2)*2;

  // call randomize_parameters once to initialize static values
  randomize_parameters(false);
}

void FuzzingParameterSet::print_static_parameters() const {
  Logger::log_info("Printing static hammering parameters:");
  Logger::log_data(string_format("agg_intra_distance: %d", agg_intra_distance));
  Logger::log_data(string_format("flushing_strategy: %s", get_string(flushing_strategy).c_str()));
  Logger::log_data(string_format("fencing_strategy: %s", get_string(fencing_strategy).c_str()));
  Logger::log_data(string_format("N_sided dist.: %s", get_dist_string().c_str()));
  Logger::log_data(string_format("hammering_total_num_activations: %d", hammering_total_num_activations));
}

void FuzzingParameterSet::print_semi_dynamic_parameters() const {
  Logger::log_info("Printing pattern-specific fuzzing parameters:");
  Logger::log_data(string_format("num_aggressors: %d", num_aggressors));
  Logger::log_data(string_format("num_refresh_intervals: %d", num_refresh_intervals));
  Logger::log_data(string_format("total_acts_pattern: %zu", total_acts_pattern));
  Logger::log_data(string_format("base_period: %d", base_period));
  Logger::log_data(string_format("start_row: %d", start_row));
}

void FuzzingParameterSet::print_dynamic_parameters(const int bank, const int inter_dist, bool seq_addresses) {
  Logger::log_info("Printing DRAM address-related fuzzing parameters:");
  Logger::log_data(string_format("bank_no: %d", bank));
  Logger::log_data(string_format("agg_inter_distance: %d", inter_dist));
  Logger::log_data(string_format("use_seq_addresses: %s", (seq_addresses ? "true" : "false")));
}

void FuzzingParameterSet::set_distribution(Range<int> range_N_sided,
                                           std::unordered_map<int, int> probabilities) {
  std::vector<int> dd;
  size_t num_iterations = 0;
  for (int i = 0; i <= range_N_sided.max; num_iterations++, i += 1) {
    dd.push_back((probabilities.count(i) > 0) ? probabilities.at(i) : (int) 0);
  }

  N_sided_probabilities = std::discrete_distribution<int>(dd.begin(), dd.end());
}

int FuzzingParameterSet::get_random_even_divisior(int n, int min_value) {
  std::vector<int> divisors;
  for (size_t i = 1; i <= sqrt(n); i++) {
    if (n%i==0) {
      if ((n/i)==1 && (i%2)==0) {
        divisors.push_back(i);
      } else {
        if (i%2==0) divisors.push_back(i);
        if ((n/i)%2==0) divisors.push_back(n/i);
      }
    }
  }

  std::shuffle(divisors.begin(), divisors.end(), gen);
  for (const auto &e : divisors) {
    if (e >= min_value) return e;
  }
  return -1;
}

void FuzzingParameterSet::randomize_parameters(bool print) {
  Logger::log_info("Randomizing fuzzing parameters.");

  // █████████ SEMI-DYNAMIC FUZZING PARAMETERS ████████████████████████████████████████████████████

  // == are only randomized once when calling this function ======

  // [derivable from aggressors in AggressorAccessPattern, also not very expressful because different agg IDs can be
  // mapped to the same DRAM address]
  // TODO: In AddressCodeMapper ensure that each address is only taken once, otherwise we cannot ensure that
  //  num_aggressors holds (IDs could be mapped to the same address)
//  num_aggressors = Range<int>(4, 64).get_random_number(gen);
   num_aggressors = Range<int>(4, 64).get_random_number(gen);  // COMMENT: SAMSUNG parameters

  // [included in HammeringPattern]
  // it is important that this is a power of two, otherwise the aggressors in the pattern will not respect frequencies
//  num_refresh_intervals = std::pow(2, Range<int>(0, 5).get_random_number(gen));  // {2^0,..,2^k}
  num_refresh_intervals = std::pow(2, Range<int>(0, 4).get_random_number(gen));  // COMMENT: SAMSUNG parameters

  // [included in HammeringPattern]
  total_acts_pattern = num_activations_per_tREFI*num_refresh_intervals;

  // [included in HammeringPattern]
  //base_period = (num_activations_per_tREFI/4)*Range<int>(1, 1).get_random_number(gen);
  base_period = get_random_even_divisior(num_activations_per_tREFI, num_activations_per_tREFI/6);

  start_row = Range<int>(0, 8192).get_random_number(gen);

  // Remarks in brackets [ ] describe considerations on whether we need to include a parameter into the JSON export

  // █████████ DYNAMIC FUZZING PARAMETERS ████████████████████████████████████████████████████

  //  == are randomized for each added aggressor ======

  // [derivable from aggressors in AggressorAccessPattern]
  // note that in PatternBuilder::generate also uses 1-sided aggressors in case that the end of a base period needs to
  // be filled up
//  N_sided = Range<int>(2, 4, 2);
    N_sided = Range<int>(2, 2, 2);  // COMMENT: SAMSUNG parameters

  // [exported as part of AggressorAccessPattern]
  // choosing as max 'base_period/N_sided.min' allows hammering an aggressor for a whole base period
//  amplitude = Range<int>(1, base_period/N_sided.min);
  amplitude = Range<int>(1, 8);  // COMMENT: SAMSUNG parameters

  // == are randomized for each different set of addresses a pattern is probed with ======

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
//  agg_inter_distance = Range<int>(2, 64);
  agg_inter_distance = Range<int>(2, 16);   // COMMENT: SAMSUNG parameters

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  bank_no = Range<int>(0, NUM_BANKS - 1);

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  use_sequential_aggressors = Range<int>(0, 1);

  // sync_each_ref = 1 means that we sync after every refresh interval, otherwise we only sync after hammering
  // the whole pattern (which may consists of more than one REF interval)
//  sync_each_ref = Range<int>(0, 1);
  sync_each_ref = Range<int>(0, 0);   // COMMENT: SAMSUNG parameters

  // █████████ STATIC FUZZING PARAMETERS ████████████████████████████████████████████████████

  // == fix values/formulas that must be configured before running this program ======

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapper]
  agg_intra_distance = 2;

  // [CANNOT be derived from anywhere else - but does not fit anywhere: will print to stdout only, not include in json]
  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;

  // [CANNOT be derived from anywhere else - but does not fit anywhere: will print to stdout only, not include in json]
  fencing_strategy = FENCING_STRATEGY::LATEST_POSSIBLE;

  // [CANNOT be derived from anywhere else - must explicitly be exported]
  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then this translates to:
  // pick a 1-sided pair with 20% probability and a 2-sided pair with 80% probability
  set_distribution(N_sided, {{2, 100}});   // COMMENT: SAMSUNG parameters

  // [CANNOT be derived from anywhere else - must explicitly be exported]
  // hammering_total_num_activations is derived as follow:
  //    REF interval: 7.8 μs (tREFI), retention time: 64 ms   => 8,000 - 10,000 REFs per interval
  //    num_activations_per_tREFI: ≈100                       => 10,000 * 100 = 1M activations * 5 = 5M ACTs
  hammering_total_num_activations = 5000000;

  if (print) print_semi_dynamic_parameters();
}

int FuzzingParameterSet::get_start_row() const {
  return start_row;
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

int FuzzingParameterSet::get_random_bank_no() {
  return bank_no.get_random_number(gen);
}

int FuzzingParameterSet::get_hammering_total_num_activations() const {
  return hammering_total_num_activations;
}

int FuzzingParameterSet::get_num_aggressors() const {
  return num_aggressors;
}

int FuzzingParameterSet::get_random_N_sided() {
  return N_sided_probabilities(gen);
}

int FuzzingParameterSet::get_random_N_sided(size_t upper_bound_max) {
  if ((size_t) N_sided.max > upper_bound_max) {
    return Range<int>(N_sided.min, upper_bound_max).get_random_number(gen);
  }
  return get_random_N_sided();
}

bool FuzzingParameterSet::get_random_use_seq_addresses() {
  return (bool) (use_sequential_aggressors.get_random_number(gen));
}

size_t FuzzingParameterSet::get_total_acts_pattern() const {
  return total_acts_pattern;
}

int FuzzingParameterSet::get_base_period() const {
  return base_period;
}

int FuzzingParameterSet::get_agg_intra_distance() const {
  return agg_intra_distance;
}

int FuzzingParameterSet::get_random_inter_distance() {
  return agg_inter_distance.get_random_number(gen);
}

int FuzzingParameterSet::get_random_amplitude(int max) {
  return Range<>(amplitude.min, std::min(amplitude.max, max)).get_random_number(gen);
}

bool FuzzingParameterSet::get_sync_each_ref() {
  return (bool) (sync_each_ref.get_random_number(gen));
}

int FuzzingParameterSet::get_num_activations_per_t_refi() const {
  return num_activations_per_tREFI;
}


