#include "Memory/Memory.hpp"

#include <sys/mman.h>
#include <unistd.h>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

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
      Logger::log_info(format_string("Could not mount superpage from %s. Error:", hugetlbfs_mountpoint.c_str()));
      Logger::log_data(std::strerror(errno));
      exit(EXIT_FAILURE);
    }
    auto mapped_target = mmap((void *) start_address, MEM_SIZE, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB | (30UL << MAP_HUGE_SHIFT), fileno(fp), 0);
    if (mapped_target==MAP_FAILED) {
      perror("mmap");
      exit(EXIT_FAILURE);
    }
    target = (volatile char*) mapped_target;
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
    Logger::log_error(format_string("Could not create mmap area at address %p, instead using %p.",
        start_address, target));
    start_address = target;
  }

  // initialize memory with random but reproducible sequence of numbers
  initialize(DATA_PATTERN::RANDOM);
}

void Memory::initialize(DATA_PATTERN data_pattern) {
  Logger::log_info("Initializing memory with pseudorandom sequence.");

  // for each page in the address space [start, end]
  for (uint64_t cur_page = 0; cur_page < size; cur_page += getpagesize()) {
    // reseed rand to have a sequence of reproducible numbers, using this we can compare the initialized values with
    // those after hammering to see whether bit flips occurred
    srand(cur_page*getpagesize());
    for (uint64_t cur_pageoffset = 0; cur_pageoffset < (uint64_t) getpagesize(); cur_pageoffset += sizeof(int)) {

      int fill_value = 0;
      if (data_pattern == DATA_PATTERN::RANDOM) {
        fill_value = rand();
      } else if (data_pattern == DATA_PATTERN::ZEROES) {
        fill_value = 0;
      } else if (data_pattern == DATA_PATTERN::ONES) {
        fill_value = 1;
      } else {
        Logger::log_error("Could not initialize memory with given (unknown) DATA_PATTERN.");
      }
        
      // write (pseudo)random 4 bytes
      uint64_t offset = cur_page + cur_pageoffset;
      *((int *) (start_address + offset)) = fill_value;
    }
  }
}

size_t Memory::check_memory(PatternAddressMapper &mapping, bool reproducibility_mode, bool verbose) {
  flipped_bits.clear();
  auto victim_rows = mapping.get_victim_rows();
  if (verbose) Logger::log_info(format_string("Checking %zu victims for bit flips.", victim_rows.size()));
  size_t sum_found_bitflips = 0;
  for (const auto &victim_row : victim_rows) {
    auto end = (uint64_t) victim_row.second;
    if ((uint64_t) victim_row.first > end) {
      end = (uint64_t) get_starting_address() + size;
    }
    sum_found_bitflips += check_memory_internal(mapping, victim_row.first, (volatile char *) end, 0,
        reproducibility_mode, verbose);
  }
  return sum_found_bitflips;
}

size_t Memory::check_memory(const volatile char *start, const volatile char *end, size_t check_offset) {
  flipped_bits.clear();
  // create a "fake" pattern mapping to keep this method for backward compatibility
  PatternAddressMapper pattern_mapping;
  return check_memory_internal(pattern_mapping, start, end, check_offset, false, true);
}

size_t Memory::check_memory_internal(PatternAddressMapper &mapping,
                                     const volatile char *start,
                                     const volatile char *end,
                                     size_t check_margin_rows,
                                     bool reproducibility_mode,
                                     bool verbose) {
  size_t found_bitflips = 0;

  if (start==nullptr || end==nullptr || ((uint64_t) start >= (uint64_t) end)) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(format_string("Start addr.: %s", DRAMAddr((void *) start).to_string().c_str()));
    Logger::log_data(format_string("End addr.: %s", DRAMAddr((void *) end).to_string().c_str()));
    return found_bitflips;
  }

  DRAMAddr start_addr((void *) start);
  start_addr.row = (check_margin_rows > start_addr.row) ? 0UL : (start_addr.row - check_margin_rows);
  start = (volatile char *) start_addr.to_virt();

  DRAMAddr end_addr((void *) end);
  end_addr.row = (check_margin_rows > end_addr.row) ? 0UL : (end_addr.row + check_margin_rows);
  end = (volatile char *) end_addr.to_virt();

  auto start_offset = (uint64_t) (start - start_address);
  start_offset = (start_offset/getpagesize())*getpagesize();

  auto end_offset = start_offset + (uint64_t) (end - start);
  end_offset = (end_offset/getpagesize())*getpagesize();

  void *page_ptr = malloc(getpagesize());
  int *page = (int*)page_ptr;
  if (page_ptr != NULL) {
    memset((void*)page, 0x0, getpagesize());
  } else {
    Logger::log_debug("malloc in Memory::check_memory_internal failed!");
    exit(EXIT_FAILURE);
  }

  // for each page (4K) in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += getpagesize()) {
    // reseed rand to have a sequence of reproducible numbers, using this we can
    // compare the initialized values with those after hammering to see whether
    // bit flips occurred
    srand(i*getpagesize());

    if (page_ptr != NULL) {
      // fill page with expected values generated by rand()
      for (size_t j = 0; j < (unsigned long)getpagesize()/sizeof(int); ++j) {
        page[j] = rand();
      }
      // check if any bit flipped in the page using the fast memcmp function, if flips ocurred we need to iterate over
      // each byte one-by-one (much slower), otherwise we just continue with the next page
      uint64_t addr = ((uint64_t)start_address+i);
      if ((addr+getpagesize()) < ((uint64_t)start_address+size) && memcmp((void*)addr, (void*)page, getpagesize()) == 0) 
        continue;
    }

    // iterate over blocks of 4 bytes (=sizeof(int))
    for (uint64_t j = 0; j < (uint64_t) getpagesize(); j += sizeof(int)) {
      uint64_t offset = i + j;
      volatile char *cur_addr = start_address + offset;
      // int expected_rand_value = rand();
      int expected_rand_value = page[j/sizeof(int)];

      // make sure that we do not access an address out of the allocated memory area
      if ((cur_addr + sizeof(int) - 1) > (start_address + size)) {
        free(page);
        return found_bitflips;
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
          auto flipped_addr_dram = DRAMAddr((void *) flipped_address);
          auto flipped_addr_value = *(unsigned char *) flipped_address;
          const auto expected_value = ((unsigned char *) &expected_rand_value)[c];
          if (verbose) {
            Logger::log_bitflip(flipped_address, flipped_addr_dram.row, (uint64_t)flipped_address%getpagesize(), 
              expected_value, flipped_addr_value, (size_t) time(nullptr));
          }
          // store detailed information about the bit flip
          BitFlip bitflip(flipped_addr_dram, (expected_value ^ flipped_addr_value), flipped_addr_value);
          // ..in the mapping that triggered this bit flip
          if (!reproducibility_mode) mapping.bit_flips.push_back(bitflip);
          // ..in an attribute of this class so that it can be retrived by the caller
          flipped_bits.push_back(bitflip);
          found_bitflips += bitflip.count_bit_corruptions();
        }
      }

      // restore original (unflipped) value
      *((int *) cur_addr) = expected_rand_value;

      // flushes this address so that future aggressors see the new value
      clflushopt(cur_addr);
      mfence();
    }
  }
  
  free(page);
  return found_bitflips;
}

Memory::Memory(bool use_superpage) : size(0), superpage(use_superpage) {
}

Memory::~Memory() {
  if (munmap((void *) start_address, size)==-1) {
    Logger::log_error(format_string("munmap failed with error:"));
    Logger::log_data(std::strerror(errno));
  }
}

volatile char *Memory::get_starting_address() const {
  return start_address;
}

bool Memory::is_superpage() const {
  return superpage;
}

std::string Memory::get_flipped_rows_text_repr() {
  // first extract all rows, otherwise it will not be possible to know in advance whether we we still
  // need to add a separator (comma) to the string as upcoming DRAMAddr instances might refer to the same row
  std::set<size_t> flipped_rows;
  for (const auto &da : flipped_bits) {
    flipped_rows.insert(da.address.row);
  }

  std::stringstream ss;
  for (const auto &row : flipped_rows) {
    ss << row;
    if (row!=*flipped_rows.rbegin()) ss << ",";
  }
  return ss.str();
}


