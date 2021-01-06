#ifndef DRAMANALYZER
#define DRAMANALYZER

#include <cinttypes>
#include <vector>

class DramAnalyzer {
 private:
  std::vector<std::vector<volatile char *>> banks;

  std::vector<std::vector<uint64_t>> bank_rank_masks;

  std::vector<uint64_t> bank_rank_functions;

  uint64_t row_function{};

  volatile char *start_address;

  static uint64_t test_addr_against_bank(volatile char *addr, std::vector<volatile char *> &bank);

  std::vector<uint64_t> get_bank_rank(std::vector<volatile char *> &target_bank);

  void find_targets(std::vector<volatile char *> &target_bank, size_t size);

 public:
  explicit DramAnalyzer(volatile char *target);

  volatile char *normalize_addr_to_bank(volatile char *cur_addr, size_t bank_no);

  uint64_t get_row_increment() const;

  uint64_t get_row_index(const volatile char *addr) const;

  void find_functions(bool superpage_on);

  /// Finds addresses of the same bank causing bank conflicts when accessed sequentially
  void find_bank_conflicts();

  const std::vector<std::vector<volatile char *>> &get_banks() const;

  void find_bank_rank_masks();

  std::vector<uint64_t> get_bank_rank_functions();
};

#endif /* DRAMANALYZER */