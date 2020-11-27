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

  uint64_t row_function{};

 public:
  DramAnalyzer();

  volatile char *normalize_addr_to_bank(volatile char *cur_addr, size_t bank_no);

  uint64_t get_row_increment() const;

  std::vector<uint64_t> get_bank_rank(std::vector<volatile char *> &target_bank);

  uint64_t get_row_index(const volatile char *addr);

  void find_functions(bool superpage_on);

  static uint64_t test_addr_against_bank(volatile char *addr, std::vector<volatile char *> &bank);

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts(volatile char *target);

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

  void find_targets(volatile char *target, std::vector<volatile char *> &target_bank, size_t size);

  const std::vector<std::vector<volatile char *>> &get_banks() const;

  void find_bank_rank_masks();

  std::vector<uint64_t> get_bank_rank_functions();

  uint64_t get_row_function() const;

  const std::vector<std::vector<uint64_t>> &get_bank_rank_masks() const;

  const std::vector<std::vector<uint64_t>> &get_bank_rank_masks();
};

#endif /* DRAMANALYZER */
