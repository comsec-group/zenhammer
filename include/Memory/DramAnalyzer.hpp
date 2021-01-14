#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <vector>

#include "Utilities/AsmPrimitives.hpp"

class DramAnalyzer {
 private:
  std::vector<std::vector<volatile char *>> banks;

  std::vector<std::vector<uint64_t>> bank_rank_masks;

  std::vector<uint64_t> bank_rank_functions;

  uint64_t row_function;

  volatile char *start_address;

  static uint64_t test_addr_against_bank(volatile char *addr, std::vector<volatile char *> &bank);

  std::vector<uint64_t> get_bank_rank(std::vector<volatile char *> &target_bank);

  void find_targets(std::vector<volatile char *> &target_bank, size_t size);

 public:
  explicit DramAnalyzer(volatile char *target);

  uint64_t get_row_increment() const;

  void find_functions(bool superpage_on);

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts();

  /// Measures the time between accessing two addresses.
  static int inline measure_time(volatile char *a1, volatile char *a2) {
    uint64_t before, after;
    before = rdtscp();
    lfence();
    for (size_t i = 0; i < DRAMA_ROUNDS; i++) {
      *a1;
      *a2;
      clflushopt(a1);
      clflushopt(a2);
      mfence();
    }
    after = rdtscp();
    return (int) ((after - before)/DRAMA_ROUNDS);
  }

  void find_bank_rank_masks();

  std::vector<uint64_t> get_bank_rank_functions();

  void load_known_functions(int num_ranks);

  /// Determine the number of possible activations within a refresh interval.
  size_t count_acts_per_ref();
};

#endif /* DRAMANALYZER */
