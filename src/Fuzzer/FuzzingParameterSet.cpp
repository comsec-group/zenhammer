#include <GlobalDefines.hpp>
#include <unordered_map>
#include <sstream>
#include <nlohmann/json.hpp>
#include "Fuzzer/FuzzingParameterSet.hpp"

FuzzingParameterSet::FuzzingParameterSet(int measured_num_acts_per_ref) { /* NOLINT */
  std::random_device rd;
  gen = std::mt19937(rd());  // standard mersenne_twister_engine seeded with some random data

  // make sure that the number of activations per tREFI is even: this is required for proper pattern generation
  num_activations_per_tREFI = (measured_num_acts_per_ref/2)*2;

  // call randomize_parameters once to initialize static values
  randomize_parameters(false);
}

void FuzzingParameterSet::print_static_parameters() const {
  printf(FBLUE);
  printf("Benchmark run parameters:\n");
  printf("    agg_intra_distance: %d\n", agg_intra_distance);
  printf("    flushing_strategy: %s\n", get_string(flushing_strategy).c_str());
  printf("    fencing_strategy: %s\n", get_string(fencing_strategy).c_str());
  printf("    N_sided dist.: %s\n", get_dist_string().c_str());
  printf("    hammering_total_num_activations: %d\n", hammering_total_num_activations);
  printf(NONE);
}

void FuzzingParameterSet::print_semi_dynamic_parameters() const {
  printf(FBLUE);
  printf("Pattern-specific fuzzing parameters:\n");
  printf("    num_aggressors: %d\n", num_aggressors);
  printf("    num_refresh_intervals: %d\n", num_refresh_intervals);
  printf("    total_acts_pattern: %zu\n", total_acts_pattern);
  printf("    base_period: %d\n", base_period);
  printf(NONE);
}

std::discrete_distribution<int> FuzzingParameterSet::build_distribution(Range range_N_sided,
                                                                        std::unordered_map<int, int> probabilities) {
  std::vector<int> dd;
  for (int i = 0; i <= range_N_sided.max; i++) {
    dd.push_back((probabilities.count(i) > 0) ? probabilities.at(i) : 0);
  }
  return std::discrete_distribution<int>(dd.begin(), dd.end());
}

void FuzzingParameterSet::randomize_parameters(bool print) {
  printf("[+] Randomizing fuzzing parameters.\n");

  // Remarks in brackets [ ] describe considerations on whether we need to include a parameter into the JSON export

  // █████████ DYNAMIC FUZZING PARAMETERS ████████████████████████████████████████████████████

  //  == are randomized for each added aggressor ======

  // [exported as part of AggressorAccessPattern]
  amplitude = Range(1, 24);

  // [derivable from aggressors in AggressorAccessPattern]
  N_sided = Range(2, 2);

  // == are randomized for each different set of addresses a pattern is probed with ======

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapping]
  agg_inter_distance = Range(4, 6);

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapping]
  bank_no = Range(0, NUM_BANKS - 1);

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapping]
  use_sequential_aggressors = Range(0, 1);

  // █████████ SEMI-DYNAMIC FUZZING PARAMETERS ████████████████████████████████████████████████████

  // == are only randomized once when calling this function ======

  // [derivable from aggressors in AggressorAccessPattern, also not very expressful because different agg IDs can be
  // mapped to the same DRAM address]
  num_aggressors = Range(12, 56).get_random_number(gen);

  // [included in HammeringPattern]
  num_refresh_intervals = Range(1, 8).get_random_number(gen);

  // [included in HammeringPattern]
  total_acts_pattern = num_activations_per_tREFI*num_refresh_intervals;

  // [included in HammeringPattern]
  base_period = (num_activations_per_tREFI/4)*Range(1, num_refresh_intervals*4).get_random_number(gen);

  // TODO: add max period

  // █████████ STATIC FUZZING PARAMETERS ████████████████████████████████████████████████████
  // TODO: export (JSON) these only once per benchmark run

  // == fix values/formulas that must be configured before running this program ======

  // [derivable from aggressor_to_addr (DRAMAddr) in PatternAddressMapping]
  agg_intra_distance = 2;

  // [CANNOT be derived from anywhere else - but does not fit anywhere: will print to stdout only, not include in json]
  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;

  // [CANNOT be derived from anywhere else - but does not fit anywhere: will print to stdout only, not include in json]
  fencing_strategy = FENCING_STRATEGY::LATEST_POSSIBLE;

  // [CANNOT be derived from anywhere else - must explicitly be exported]
  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then this translates to:
  // pick a 1-sided pair with 20% probability and a 2-sided pair with 80% probability
  std::unordered_map<int, int> distribution = {{2, 1}};
  N_sided_probabilities = build_distribution(N_sided, distribution);

  // [CANNOT be derived from anywhere else - must explicitly be exported]
  // hammering_total_num_activations is derived as follow:
  //    REF interval: 7.8 μs (tREFI), retention time: 64 ms   => 8,000 - 10,000 REFs per interval
  //    num_activations_per_tREFI: ≈100                       => 10,000 * 100 = 1M activations * 5 = 5M ACTs
  hammering_total_num_activations = 5000000;

  if (print) print_semi_dynamic_parameters();
}

std::string FuzzingParameterSet::get_dist_string() const {
  std::stringstream ss;
  int total = 0;
  std::vector<double> probs = N_sided_probabilities.probabilities();
  for (const auto &d : probs) total += d;
  for (size_t i = N_sided.min; i < std::min(probs.size(), (size_t) N_sided.max); ++i) {
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

int FuzzingParameterSet::get_random_amplitude() {
  return amplitude.get_random_number(gen);
}

int FuzzingParameterSet::get_random_N_sided() {
  return N_sided_probabilities(gen);
}

const Range &FuzzingParameterSet::get_n_sided_range() const {
  return N_sided;
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

int FuzzingParameterSet::get_num_refresh_intervals() const {
  return num_refresh_intervals;
}
