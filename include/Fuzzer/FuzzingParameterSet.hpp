#ifndef BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_HPP_
#define BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_HPP_

#include <random>
#include <unordered_map>

#include "Utilities/Range.hpp"
#include "Utilities/Enums.hpp"

class FuzzingParameterSet {
 private:
  std::mt19937 gen;

  /// MC issues a REFRESH every 7.8us to ensure that all cells are refreshed within a 64ms interval.
  int num_refresh_intervals;

  /// The numbers of aggressors to be picked from during random pattern generation.
  int num_aggressors;

  int agg_intra_distance;

  int num_activations_per_tREFI;

  int hammering_total_num_activations;

  int base_period;

  int start_row;

  int max_row_no;

  size_t total_acts_pattern;

  Range<int> bank_no;

  Range<int> use_sequential_aggressors;

  Range<int> agg_inter_distance;

  Range<int> amplitude;

  Range<int> N_sided;

  Range<int> sync_each_ref;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  std::discrete_distribution<int> N_sided_probabilities;

  std::string get_dist_string() const;

 public:
  explicit FuzzingParameterSet(int measured_num_acts_per_ref);

  int get_random_bank_no();

  int get_hammering_total_num_activations() const;

  int get_num_aggressors() const;

  int get_random_amplitude(int max);

  int get_random_N_sided();

  int get_base_period() const;

  int get_agg_intra_distance() const;

  int get_random_inter_distance();

  int get_random_even_divisior(int n, int min_value);

  int get_random_N_sided(size_t upper_bound_max);

  int get_num_activations_per_t_refi() const;

  int get_start_row() const;

  size_t get_total_acts_pattern() const;

  bool get_random_use_seq_addresses();

  bool get_random_sync_each_ref();

  void print_static_parameters() const;

  void print_semi_dynamic_parameters() const;

  void randomize_parameters(bool print = true);

  void set_distribution(Range<int> range_N_sided, std::unordered_map<int, int> probabilities);

  static void print_dynamic_parameters(int bank, int inter_dist, bool seq_addresses);

  int get_max_row_no() const;
};

#endif //BLACKSMITH_INCLUDE_FUZZER_FUZZINGPARAMETERSET_HPP_
