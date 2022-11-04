#ifndef ROWHAMMER_REF_IMPL_SRC_PAGEMAP_HPP_
#define ROWHAMMER_REF_IMPL_SRC_PAGEMAP_HPP_

#include <cstdint>

class pagemap {
 public:
  static uint64_t vaddr2paddr(uint64_t vaddr);
};

#endif //ROWHAMMER_REF_IMPL_SRC_PAGEMAP_HPP_
