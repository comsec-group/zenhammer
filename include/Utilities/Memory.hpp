#ifndef BLACKSMITH_SRC_MEMORY_H_
#define BLACKSMITH_SRC_MEMORY_H_

#include <cstdint>
#include <cstdlib>
#include <string>

class Memory {
 private:
  /// the starting address of the allocated memory area
  /// this is a fixed value as the assumption is that all memory cells are equally vulnerable
  volatile char *starting_address = (volatile char *) 0x2000000000;

  const std::string hugetlbfs_mountpoint = "/mnt/huge/buff";

  uint64_t size;

  bool superpage;

 public:

  explicit Memory(bool use_superpage);

  ~Memory();

  volatile char *allocate_memory(uint64_t mem_size);

  void check_memory(const volatile char *start, const volatile char *end, uint64_t row_function);

  void initialize();
};

#endif //BLACKSMITH_SRC_MEMORY_H_
