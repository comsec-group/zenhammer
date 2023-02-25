#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <vector>
#include <random>

#include "Utilities/AsmPrimitives.hpp"
#include "ConflictCluster.hpp"
#include "Utilities/CustomRandom.hpp"

class DramAnalyzer {
 private:
  std::vector<std::vector<volatile char *>> banks;

//  std::vector<uint64_t> bank_rank_functions;

//  uint64_t row_function;

  volatile char *start_address;

  ConflictCluster &cc;

  void find_targets(std::vector<volatile char *> &target_bank);

  std::uniform_int_distribution<int> dist;

  CustomRandom cr;

  uint64_t th_low;

 public:
  explicit  DramAnalyzer(volatile char *target, ConflictCluster &cc);

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts();

  /// Measures the time between accessing two addresses.
  static int inline measure_time(volatile char *a1, volatile char *a2) {
    uint64_t before, after;
    before = rdtscp();
    lfence();
    for (size_t i = 0; i < DRAMA_RNDS; i++) {
      (void)*a1;
      (void)*a2;
      clflushopt(a1);
      clflushopt(a2);
      mfence();
    }
    after = rdtscp();
    return (int) ((after - before)/DRAMA_RNDS);
  }

  /// Determine the number of possible activations within a refresh interval.
  size_t count_acts_per_ref();

  unsigned long get_ref_threshold();
};

#endif /* DRAMANALYZER */
