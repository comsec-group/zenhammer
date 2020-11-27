#include <cstdio>
#include <cassert>
#include <cstdlib>
#include <sys/mman.h>
#include <cstring>
#include <unistd.h>

#include "GlobalDefines.hpp"
#include "Utilities/AsmPrimitives.hpp"
#include "DramAnalyzer.hpp"

#include "Utilities/Memory.hpp"

/// Allocates a MEM_SIZE bytes of memory by using super or huge pages.
volatile char *Memory::allocate_memory(size_t mem_size) {
  this->size = mem_size;
  volatile char *target;
  int ret;
  FILE *fp;

  if (superpage) {
    // allocate memory using super pages
    fp = fopen(hugetlbfs_mountpoint.c_str(), "w+");
    if (fp==nullptr) {
      perror("fopen");
      exit(-1);
    }
    target = (volatile char *) mmap((void *) starting_address, MEM_SIZE, PROT_READ | PROT_WRITE,
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
    printf("[+] Waiting for khugepaged.\n");
    sleep(10);
  }

  if (target!=starting_address) {
    printf("[-] Could not create mmap area at address %p, instead using %p.\n",
           starting_address, target);
    starting_address = target;
  }

  // initialize memory with random but reproducible sequence of numbers
  initialize();

  return target;
}

void Memory::initialize() {
  printf("[+] Initializing memory with pseudorandom sequence.\n");
  // for each page in the address space [start, end]
  for (uint64_t i = 0; i < size; i += PAGE_SIZE) {
    // reseed rand to have a sequence of reproducible numbers, using this we can compare the initialized values with
    // those after hammering to see whether bit flips occurred
    srand(i*PAGE_SIZE);
    for (uint64_t j = 0; j < PAGE_SIZE; j += sizeof(int)) {
      uint64_t offset = i + j;
      // write (pseudo)random 4 bytes to target[offset] = target[i+j]
      *((int *) (starting_address + offset)) = rand();
    }
  }
}

/// Serves two purposes, if init=true then it initializes the memory with a pseudorandom (i.e., reproducible) sequence
/// of numbers; if init=false then it checks whether any of the previously written values changed (i.e., bits flipped).
void Memory::check_memory(const volatile char *start, const volatile char *end, uint64_t row_function) {

  if (start==nullptr || end==nullptr) {
    printf("[-] Function mem_values called with invalid arguments\n");
    exit(1);
  }

  // use std::max here to make sure that we do not pass (under) the allocated memory area
  auto start_offset = (uint64_t) std::max(0L, (start - starting_address));
  start_offset = (start_offset/PAGE_SIZE)*PAGE_SIZE;

  // use std::min here to make sure that we do not pass (over) the allocated memory area
  auto end_offset = start_offset + std::min(size, ((uint64_t) (end - start)));
  end_offset = (end_offset/PAGE_SIZE)*PAGE_SIZE;

  printf("[+] Checking if any bit flips occurred.\n");

  // for each page in the address space [start, end]
  for (uint64_t i = start_offset; i < end_offset; i += PAGE_SIZE) {
    // reseed rand to have a sequence of reproducible numbers, using this we can
    // compare the initialized values with those after hammering to see whether
    // bit flips occurred
    srand(i*PAGE_SIZE);
    for (uint64_t j = 0; j < PAGE_SIZE; j += sizeof(int)) {
      uint64_t offset = i + j;
      int rand_val = rand();

      clflushopt(starting_address + offset);
      mfence();

      // the bit did not flip
      if (*((int *) (starting_address + offset))==rand_val) {
        continue;
      }

      // the bit flipped, now compare byte per byte
      for (unsigned long c = 0; c < sizeof(int); c++) {
        if (*((char *) (starting_address + offset + c))!=((char *) &rand_val)[c]) {
          printf(FRED "[!] Flip %p, row %lu, page offset: %lu, from %x to %x detected at t=%lu" NONE "\n",
                 starting_address + offset + c,
                 get_row_index(starting_address + offset + c, row_function),
                 offset%PAGE_SIZE,
                 ((unsigned char *) &rand_val)[c],
                 *(unsigned char *) (starting_address + offset + c),
                 (unsigned long) time(nullptr));
        }
      }

      // restore original (unflipped) value
      *((int *) (starting_address + offset)) = rand_val;

      clflushopt(starting_address + offset);
      mfence();
    }
  }
}

Memory::Memory(bool use_superpage) : size(0), superpage(use_superpage) {

}

Memory::~Memory() {
  if (munmap((void *) starting_address, size)==-1) {
    fprintf(stderr, "munmap failed with error:");
    perror("mmap");
  }
}
