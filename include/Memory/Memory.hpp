#ifndef ZENHAMMER_SRC_MEMORY_H_
#define ZENHAMMER_SRC_MEMORY_H_

#include <cstdint>
#include <cstdlib>
#include <string>

#include "Memory/DramAnalyzer.hpp"
#include "Fuzzer/PatternAddressMapper.hpp"

enum class DATA_PATTERN : char {
  ZEROES, ONES, RANDOM
};

class Memory {
 private:
  /// the starting address of the allocated memory area
  /// this is a fixed value as the assumption is that all memory cells are equally vulnerable
  volatile char *start_address = (volatile char *) 0x2000000000;

  // the mount point of the huge pages filesystem
  const std::string hugetlbfs_mountpoint = "/mnt/huge/buff";

  // the size of the allocated memory area in bytes
  uint64_t size;

  // whether this memory allocation is backed up by a superage
  const bool superpage;

  size_t check_memory_internal(PatternAddressMapper &mapping, const volatile char *start,
                               const volatile char *end, bool reproducibility_mode, bool verbose);

  DATA_PATTERN data_pattern;

  uint32_t get_fill_value() const;

  static void reseed_srand(uint64_t cur_page);

  void initialize(DATA_PATTERN patt);

  void* shadow_page;

 public:
  // the flipped bits detected during the last call to check_memory
  std::vector<BitFlip> flipped_bits;

  explicit Memory(bool use_superpage);

  ~Memory();

  void allocate_memory(size_t mem_size);

  size_t check_memory(PatternAddressMapper &mapping, bool reproducibility_mode, bool verbose);

  [[nodiscard]] volatile char *get_starting_address() const;

  std::string get_flipped_rows_text_repr();

  void check_memory_full();

  uint64_t round_down_to_next_page_boundary(uint64_t address);

  static size_t get_max_superpages();
};

#endif //ZENHAMMER_SRC_MEMORY_H_
