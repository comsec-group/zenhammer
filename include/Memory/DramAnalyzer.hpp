#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <vector>
#include <random>

#include "Utilities/AsmPrimitives.hpp"
#include "ConflictCluster.hpp"
#include "Utilities/CustomRandom.hpp"
#include "Utilities/ExperimentConfig.hpp"

class DramAnalyzer {
 private:
  std::vector<std::vector<volatile char *>> banks;

  volatile char *start_address;

  ConflictCluster &cc;

  void find_targets(std::vector<volatile char *> &target_bank);

  std::uniform_int_distribution<int> dist;

  CustomRandom cr;

  uint64_t ref_threshold_low;

 public:
  explicit  DramAnalyzer(volatile char *target, ConflictCluster &cc);

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts();

  /// Measures the time between accessing two addresses.
  static int inline measure_time(volatile char *a1, volatile char *a2);

  /// Determine the number of possible activations within a refresh interval.
  size_t count_acts_per_ref(ExperimentConfig &exp_cfg);

  size_t count_acts_per_ref();

  [[nodiscard]] unsigned long get_ref_threshold() const;
};

#endif /* DRAMANALYZER */
