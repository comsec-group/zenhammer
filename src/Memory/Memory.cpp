#include "Memory/Memory.hpp"

#include <sys/mman.h>
#include <iostream>

/// Allocates a MEM_SIZE bytes of memory by using super or huge pages.
void Memory::allocate_memory(size_t mem_size) {
  this->size = mem_size;
  volatile char *target = nullptr;
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
    assert(posix_memalign((void **) &target, MEM_SIZE, MEM_SIZE)==0);
    assert(madvise((void *) target, MEM_SIZE, MADV_HUGEPAGE)==0);
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
    srand(static_cast<unsigned int>(cur_page*getpagesize()));
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
  if (verbose)
    Logger::log_info(format_string("Checking %zu victims for bit flips.", victim_rows.size()));

  size_t sum_found_bitflips = 0;
  for (const auto &vr : victim_rows) {
    auto next_victim_row = conflict_cluster.get_next_row(vr);
    sum_found_bitflips += check_memory_internal(mapping, vr.vaddr, next_victim_row.vaddr, reproducibility_mode, verbose);
  }
  return sum_found_bitflips;
}

size_t Memory::check_memory_internal(PatternAddressMapper &mapping,
                                     const volatile char *start,
                                     const volatile char *end,
                                     bool reproducibility_mode,
                                     bool verbose) {
  // if end < start, then we flipped around the row list because we reached its end
  // in this case we use the typical row offset to 'guess' the next row
  if ((uint64_t)start >= (uint64_t)end) {
    end = (volatile char*)std::min((uint64_t)start+conflict_cluster.get_typical_row_offset(),
                                   (uint64_t)get_starting_address()+size);
  }

  // counter for the number of found bit flips in the memory region [start, end]
  size_t found_bitflips = 0;

  if (start==nullptr || end==nullptr || ((uint64_t) start >= (uint64_t) end)) {
    Logger::log_error("Function check_memory called with invalid arguments.");
    Logger::log_data(format_string("Start addr.: 0x%lx", (uint64_t)start));
    Logger::log_data(format_string("End addr.: 0x%lx", (uint64_t)end));
    return found_bitflips;
  }

  auto start_offset = (uint64_t) (start - start_address);

  const auto pagesize = static_cast<size_t>(getpagesize());
  start_offset = (start_offset/pagesize)*pagesize;

  auto end_offset = start_offset + (uint64_t) (end - start);
  end_offset = (end_offset/pagesize)*pagesize;

  void *page_raw = malloc(pagesize);
  if (page_raw == nullptr) {
    Logger::log_error("Could not create temporary page for memory comparison.");
    exit(EXIT_FAILURE);
  }
  memset(page_raw, 0, pagesize);
  int *page = (int*)page_raw;

  // for each page (4K) in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += pagesize) {
    // reseed rand to have the desired sequence of reproducible numbers
    srand(static_cast<unsigned int>(i*pagesize));

    // fill comparison page with expected values generated by rand()
    for (size_t j = 0; j < (unsigned long) pagesize / sizeof(int); ++j) {
      page[j] = rand(); // NOLINT(cert-msc50-cpp)
    }

    uint64_t addr = ((uint64_t)start_address+i);

    // check if any bit flipped in the page using the fast memcmp function, if any flip occurred we need to iterate over
    // each byte one-by-one (much slower), otherwise we just continue with the next page
    if ((addr+ pagesize) < ((uint64_t)start_address+size) && memcmp((void*)addr, (void*)page, pagesize) == 0)
      continue;

    // iterate over blocks of 4 bytes (=sizeof(int))
    for (uint64_t j = 0; j < (uint64_t) pagesize; j += sizeof(int)) {
      uint64_t offset = i + j;
      volatile char *cur_addr = start_address + offset;

      // if this address is outside the superpage we must not proceed to avoid segfault
      if ((uint64_t)cur_addr >= ((uint64_t)start_address+size))
        continue;

      // clear the cache to make sure we do not access a cached value
      clflushopt(cur_addr);
      mfence();

      // if the bit did not flip -> continue checking next block
      int expected_rand_value = page[j/sizeof(int)];
      if (*((int *) cur_addr)==expected_rand_value)
        continue;

      // if the bit flipped -> compare byte per byte
      for (unsigned long c = 0; c < sizeof(int); c++) {
        volatile char *flipped_address = cur_addr + c;
        if (*flipped_address != ((char *) &expected_rand_value)[c]) {
          auto simple_addr_flipped = conflict_cluster.get_simple_dram_address(flipped_address);

//          assert(flipped_address == (volatile char*)flipped_addr_dram.to_virt());
          const auto flipped_addr_value = *(unsigned char *) flipped_address;
          const auto expected_value = ((unsigned char *) &expected_rand_value)[c];
          if (verbose) {
            Logger::log_bitflip(flipped_address,
                                simple_addr_flipped.row_id,
                                expected_value,
                                flipped_addr_value,
                                (size_t) time(nullptr),
                                true);
          }
          // store detailed information about the bit flip
          BitFlip bitflip(simple_addr_flipped, (expected_value ^ flipped_addr_value), flipped_addr_value);
          // ..in the mapping that triggered this bit flip
          if (!reproducibility_mode) {
            if (mapping.bit_flips.empty()) {
              Logger::log_error("Cannot store bit flips found in given address mapping.\n"
                                "You need to create an empty vector in PatternAddressMapper::bit_flips before calling "
                                "check_memory.");
            }
            mapping.bit_flips.back().push_back(bitflip);
          }
          // ..in an attribute of this class so that it can be retrived by the caller
          flipped_bits.push_back(bitflip);
          found_bitflips += bitflip.count_bit_corruptions();
        }
      }

      // restore original (unflipped) value
      *((int *) cur_addr) = expected_rand_value;

      // flush this address so that value is committed before hammering again there
      clflushopt(cur_addr);
      mfence();
    }
  }
  
  free(page);
  return found_bitflips;
}

Memory::Memory(bool use_superpage, std::string &rowlist_filepath, std::string &rowlist_filepath_bgbk)
    : size(0), superpage(use_superpage), conflict_cluster(rowlist_filepath, rowlist_filepath_bgbk) {
}

Memory::~Memory() {
  if (munmap((void *) start_address, size)==-1) {
    Logger::log_error("munmap failed with error:");
    Logger::log_data(std::strerror(errno));
  }
}

volatile char *Memory::get_starting_address() const {
  return start_address;
}

std::string Memory::get_flipped_rows_text_repr() {
  std::stringstream ss;
  size_t cnt = 0;
  for (const auto &row : flipped_bits) {
    if (cnt > 0) {
      ss << ", ";
    }
    ss << row.address.row_id;
    cnt++;
  }
  return ss.str();
}