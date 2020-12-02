#include <GlobalDefines.hpp>
#include <unordered_map>
#include <sstream>
#include "Fuzzer/FuzzingParameterSet.hpp"

FuzzingParameterSet::FuzzingParameterSet(int measured_num_acts_per_ref) {
  std::random_device rd;
  gen = std::mt19937(rd());  // standard mersenne_twister_engine seeded with some random data

  // make sure that the number of activations per tREFI is even: this is required for proper pattern generation
  num_activations_per_tREFI = (measured_num_acts_per_ref/2)*2;
}

void FuzzingParameterSet::print_parameters() const {
  printf("    agg_inter_distance: (%d,%d)\n", agg_inter_distance.min, agg_inter_distance.max);
  printf("    agg_intra_distance: %d\n", agg_intra_distance);
  printf("    amplitude: (%d,%d)\n", amplitude.min, amplitude.max);
  printf("    fencing_strategy: %s\n", get_string(fencing_strategy).c_str());
  printf("    flushing_strategy: %s\n", get_string(flushing_strategy).c_str());
  printf("    N_sided dist.: %s\n", get_dist_string().c_str());
  printf("    N_sided: (%d,%d)\n", N_sided.min, N_sided.max);
  printf("    num_activations_per_tREFI: %d\n", num_activations_per_tREFI);
  printf("    num_aggressors: %d\n", num_aggressors);
  printf("    num_refresh_intervals: %d\n", num_refresh_intervals);
  printf("    hammering_total_num_activations: %d\n", hammering_total_num_activations);
  printf("    total_acts_pattern: %zu\n", total_acts_pattern);
  printf("    use_sequential_aggressors: %s\n", (use_sequential_aggressors ? "true" : "false"));
  printf(NONE);  // revert back color
}

std::discrete_distribution<int> FuzzingParameterSet::build_distribution(Range range_N_sided,
                                                                        std::unordered_map<int, int> probabilities) {
  std::vector<int> dd;
  for (int i = 0; i <= range_N_sided.max; i++) {
    dd.push_back((probabilities.count(i) > 0) ? probabilities.at(i) : 0);
  }
  return std::discrete_distribution<int>(dd.begin(), dd.end());
}

void FuzzingParameterSet::randomize_parameters() {
  printf(FCYAN "[+] Randomizing fuzzing parameters:\n");

  // === DYNAMIC FUZZING PARAMETERS ====================================================
  // specify ranges of valid values that are used to randomize during pattern generation or fuzzing

  // following values are randomized for each added aggressor
  amplitude = Range(1, 24);

  N_sided = Range(2, 2);

  agg_inter_distance = Range(2, 16);

  // is randomized for each different set of addresses a pattern is probed with
  bank_no = Range(0, NUM_BANKS - 1);

  // === SEMI-DYNAMIC FUZZING PARAMETERS ====================================================
  // are only randomized once when calling this function
  num_aggressors = Range(12, 56).get_random_number(gen);

  use_sequential_aggressors = (bool) (Range(0, 1).get_random_number(gen));

  num_refresh_intervals = Range(1, 8).get_random_number(gen);

  total_acts_pattern = num_activations_per_tREFI*num_refresh_intervals;

  base_period = num_activations_per_tREFI/4*Range(1, num_refresh_intervals*16).get_random_number(gen);

  // === STATIC FUZZING PARAMETERS ====================================================
  // fix values/formulas that must be configured before running this program

  agg_intra_distance = 2;

  flushing_strategy = FLUSHING_STRATEGY::EARLIEST_POSSIBLE;

  fencing_strategy = FENCING_STRATEGY::LATEST_POSSIBLE;

  // if N_sided = (1,2) and this is {{1,2},{2,8}}, then this translates to:
  // pick a 1-sided pair with 20% probability and a 2-sided pair with 80% probability
  std::unordered_map<int, int> distribution = {{2, 1}};
  N_sided_probabilities = build_distribution(N_sided, distribution);

  // hammering_total_num_activations is derived as follow:
  //    REF interval: 7.8 μs (tREFI), retention time: 64 ms   => 8,000 - 10,000 REFs per interval
  //    num_activations_per_tREFI: ≈100                       => 10,000 * 100 = 1M activations * 5 = 5M ACTs
  hammering_total_num_activations = 5000000;
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

int FuzzingParameterSet::get_bank_no() {
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

bool FuzzingParameterSet::use_sequential_aggressor_addresses() const {
  return use_sequential_aggressors;
}

size_t FuzzingParameterSet::get_total_acts_pattern() const {
  return total_acts_pattern;
}

int FuzzingParameterSet::get_base_period() const {
  return base_period;
}
