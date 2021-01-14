#ifndef BLACKSMITH_SRC_MEMORY_H_
#define BLACKSMITH_SRC_MEMORY_H_

#include <cstdint>
#include <cstdlib>
#include <string>

#include "Memory/DramAnalyzer.hpp"
#include "Fuzzer/PatternAddressMapper.hpp"

class Memory {
 private:
  /// the starting address of the allocated memory area
  /// this is a fixed value as the assumption is that all memory cells are equally vulnerable
  volatile char *start_address = (volatile char *) 0x2000000000;

  const std::string hugetlbfs_mountpoint = "/mnt/huge/buff";

  uint64_t size;

  bool superpage;

 public:

  explicit Memory(bool use_superpage);

  ~Memory();

  void allocate_memory(size_t mem_size);

  void check_memory(const volatile char *start, const volatile char *end, size_t check_offset);

  void initialize();

  volatile char *get_starting_address() const;

  size_t check_memory(PatternAddressMapper &mapping,
                      const volatile char *start,
                      const volatile char *end,
                      size_t check_margin_rows,
                      bool reproducibility_mode);

  size_t check_memory(DramAnalyzer &dram_analyzer, PatternAddressMapper &mapping, bool reproducibility_mode);
};

#endif //BLACKSMITH_SRC_MEMORY_H_
