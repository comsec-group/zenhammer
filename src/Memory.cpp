#include "Memory.hpp"

#include <sys/mman.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "DramAnalyzer.hpp"
#include "Fuzzer/BitFlip.hpp"
#include "GlobalDefines.hpp"
#include "Utilities/AsmPrimitives.hpp"

/// Allocates a MEM_SIZE bytes of memory by using super or huge pages.
void Memory::allocate_memory(size_t mem_size) {
  this->size = mem_size;
  volatile char *target;
  int ret;
  FILE *fp;

  if (superpage) {
    // allocate memory using super pages
    fp = fopen(hugetlbfs_mountpoint.c_str(), "w+");
    if (fp==nullptr) {
      Logger::log_info(string_format("Could not mount superpage from %s. Error:", hugetlbfs_mountpoint.c_str()));
      Logger::log_data(std::strerror(errno));
      exit(-1);
    }
    target = (volatile char *) mmap((void *) start_address, MEM_SIZE, PROT_READ | PROT_WRITE,
                                    MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | (30UL << MAP_HUGE_SHIFT), fileno(fp), 0);
    if (target==MAP_FAILED) {
      perror("mmap");
      exit(-1);
    }
  } else {
    // allocate memory using huge pages
    ret = posix_memalign((void **) &target, MEM_SIZE, MEM_SIZE);
    assert(ret==0);
    ret = madvise((void *) target, MEM_SIZE, MADV_HUGEPAGE);
    assert(ret==0);
    memset((char *) target, 'A', MEM_SIZE);
    // for khugepaged
    Logger::log_info("Waiting for khugepaged.");
    sleep(10);
  }

  if (target!=start_address) {
    Logger::log_error(string_format("Could not create mmap area at address %p, instead using %p.",
                                    start_address,
                                    target));
    start_address = target;
  }

  // initialize memory with random but reproducible sequence of numbers
  initialize();
}

void Memory::initialize() {
  Logger::log_info("Initializing memory with pseudorandom sequence.");
  // for each page in the address space [start, end]
  for (uint64_t i = 0; i < size; i += getpagesize()) {
    // reseed rand to have a sequence of reproducible numbers, using this we can compare the initialized values with
    // those after hammering to see whether bit flips occurred
    srand(i*getpagesize());
    for (uint64_t j = 0; j < (uint64_t) getpagesize(); j += sizeof(int)) {
      uint64_t offset = i + j;
      // write (pseudo)random 4 bytes to target[offset] = target[i+j]
      *((int *) (start_address + offset)) = rand();
    }
  }
}

void Memory::check_memory(DramAnalyzer &dram_analyzer, PatternAddressMapper &mapping) {
  Logger::log_info("Checking if any bit flips occurred.");
  for (const auto &victim_row : mapping.get_victim_rows()) {
    check_memory(dram_analyzer, victim_row.first, victim_row.second, 0, mapping);
  }
}

void Memory::check_memory(DramAnalyzer &dram_analyzer,
                          const volatile char *start,
                          const volatile char *end,
                          size_t check_offset,
                          PatternAddressMapper &mapping) {

  if ((start==nullptr || end==nullptr) || ((uint64_t) start >= (uint64_t) end)) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(string_format("Start addr: 0x%lx %s",
                                   (uint64_t) start,
                                   DRAMAddr((void *) start).to_string().c_str()));
    Logger::log_data(string_format("End addr: 0x%lx %s", (uint64_t) end, DRAMAddr((void *) end).to_string().c_str()));
    exit(1);
  }

  auto row_increment = dram_analyzer.get_row_increment();
  start -= row_increment*check_offset;
  end += row_increment*check_offset;

  auto start_offset = (uint64_t) (start - start_address);
  start_offset = (start_offset/getpagesize())*getpagesize();

  auto end_offset = start_offset + (uint64_t) (end - start);
  end_offset = (end_offset/getpagesize())*getpagesize();

  // for each page (4K) in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += getpagesize()) {

    // reseed rand to have a sequence of reproducible numbers, using this we can
    // compare the initialized values with those after hammering to see whether
    // bit flips occurred
    srand(i*getpagesize());

    // iterate over blocks of 4 bytes (=sizeof(int))
    for (uint64_t j = 0; j < (uint64_t) getpagesize(); j += sizeof(int)) {
      uint64_t offset = i + j;
      volatile char *cur_addr = start_address + offset;
      int expected_rand_value = rand();

      // make sure that we do not access an address out of the allocated memory area
      if ((cur_addr + sizeof(int) - 1) > (start_address + size)) {
        return;
      }

      // clear the cache to make sure we do not access a cached value
      clflushopt(cur_addr);
      mfence();

      // if the bit did not flip -> continue checking next row
      if (*((int *) cur_addr)==expected_rand_value) {
        continue;
      }

      // if the bit flipped -> compare byte per byte
      for (unsigned long c = 0; c < sizeof(int); c++) {
        volatile char *flipped_address = cur_addr + c;

        if (*((char *) flipped_address)!=((char *) &expected_rand_value)[c]) {
          Logger::log_bitflip(flipped_address, dram_analyzer.get_row_index(flipped_address),
                              offset%getpagesize(),
                              ((unsigned char *) &expected_rand_value)[c],
                              *(unsigned char *) flipped_address,
                              (unsigned long) time(nullptr));
          uint8_t bitmask = ((unsigned char *) &expected_rand_value)[c] ^(*(unsigned char *) flipped_address);
          mapping.bit_flips.emplace_back(DRAMAddr((void *) flipped_address), bitmask, *(unsigned char *) flipped_address);
//          Logger::log_data(string_format("Flip at %s", DRAMAddr((void *) flipped_address).to_string_compact().c_str()));
        }
      }

      // restore original (unflipped) value
      *((int *) cur_addr) = expected_rand_value;

      // flush this address os that future accesses see the new value
      clflushopt(cur_addr);
      mfence();
    }
  }
}

void Memory::check_memory(DramAnalyzer &dram_analyzer,
                          const volatile char *start,
                          const volatile char *end,
                          size_t check_offset) {
  // create a "fake" pattern mapping to keep this method for backward compatibility
  PatternAddressMapper pattern_mapping;
  check_memory(dram_analyzer, start, end, check_offset, pattern_mapping);
}

Memory::Memory(bool use_superpage) : size(0), superpage(use_superpage) {
}

Memory::~Memory() {
  if (munmap((void *) start_address, size)==-1) {
    Logger::log_error(string_format("munmap failed with error:"));
    Logger::log_data(std::strerror(errno));
  }
}

volatile char *Memory::get_starting_address() const {
  return start_address;
}
