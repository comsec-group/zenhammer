#ifndef BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_H_
#define BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_H_

#include <random>
#include "Utilities/Range.hpp"
#include "CodeJitter.hpp"

class FuzzingParameterSet {
 private:
  std::mt19937 gen;

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval.
  int num_refresh_intervals{};

  /// The numbers of aggressors to be picked from during random pattern generation.
  int num_aggressors{};

  int agg_intra_distance{};

  int num_activations_per_tREFI{};

  int hammering_total_num_activations{};

  int base_period{};

  Range bank_no{};

  size_t total_acts_pattern{};

  bool use_sequential_aggressors{};

  Range agg_inter_distance;

  Range amplitude;

  Range N_sided;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  std::discrete_distribution<int> N_sided_probabilities;

  std::string get_dist_string() const;

 public:
  explicit FuzzingParameterSet(int measured_num_acts_per_ref);

  void randomize_parameters();

  static std::discrete_distribution<int> build_distribution(Range range_N_sided,
                                                            std::unordered_map<int, int> probabilities);

  void print_parameters() const;

  int get_bank_no();

  int get_hammering_total_num_activations() const;

  int get_num_aggressors() const;

  int get_random_amplitude();

  int get_random_N_sided();

  const Range &get_n_sided_range() const;

  bool use_sequential_aggressor_addresses() const;

  size_t get_total_acts_pattern() const;

  int get_base_period() const;
};

#endif //BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_H_
