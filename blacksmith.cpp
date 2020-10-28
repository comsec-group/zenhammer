#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <vector>
#include <inttypes.h>

#include "utils.h"
#include "PatternBuilder.h"

/// the starting address of the allocated memory area
#define ADDR 0x2000000000
/// the number of rounds to be used to measure cache hit/miss latency
#define DRAMA_ROUNDS 1000
/// size in bytes of a cacheline
#define CACHELINE_SIZE 64
/// threshold to distinguish between cache miss (t > THRESH) 
/// and cache hit (t < THRESH)
#define THRESH 430
#define NUM_TARGETS 10
/// the maximum number of aggressor rows
#define MAX_ROWS 30
/// the number of banks in the system
#define NUM_BANKS 16
/// the number of bytes to be allocated
#define MEM_SIZE (GB(1))
/// allocate a super page
#define SUPERPAGE 1
/// do synchronized hammering
#define NOSYNC 0

/// the number of rounds to hammer
/// this is controllable via the first (unnamed) program parameter
static int HAMMER_ROUNDS = 1000000;

/// Measures the time between accessing two addresses.
int measure_time(volatile char *a1, volatile char *a2) {
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
  return (int)((after - before) / DRAMA_ROUNDS);
}

/// Performs hammering on given aggressor rows for HAMMER_ROUNDS times.
void hammer(std::vector<volatile char *> &aggressors) {
#if 0
    for(size_t i = 0; i < aggressors.size() -1; i++)
        printf("measure_time %d\n", measure_time(aggressors[i], aggressors[i+1]));
#endif
  for (size_t i = 0; i < HAMMER_ROUNDS; i++) {
    for (auto &a : aggressors) {
      *a;
    }
    for (auto &a : aggressors) {
      clflushopt(a);
    }
    mfence();
  }
}

/// Performs synchronized hammering on the given aggressor rows.
void hammer_sync(std::vector<volatile char*>& aggressors, int acts,
                 volatile char* d1, volatile char* d2) {
                
  int ref_rounds = acts / aggressors.size();
  int agg_rounds = ref_rounds;
  uint64_t before = 0;
  uint64_t after = 0;

  *d1;
  *d2;

  // synchronize with the beginning of an interval
  while (true) {
    clflushopt(d1);
    clflushopt(d2);
    mfence();
    before = rdtscp();
    lfence();
    *d1;
    *d2;
    after = rdtscp();
    // check if an ACTIVATE was issued
    if ((after - before) > 1000) {
      break;
    }
  } 
  
  // perform hammering for HAMMER_ROUNDS/ref_rounds times
  for (int i = 0; i < HAMMER_ROUNDS / ref_rounds; i++) {
    for (int j = 0; j < agg_rounds; j++) {
      for (auto& a : aggressors) {
        *a;
      }
      for (auto& a : aggressors) {
        clflushopt(a);
      }
      mfence();
    }

    // after HAMMER_ROUNDS/ref_rounds times hammering, check for next ACTIVATE
    while (true) {
      clflushopt(d1);
      clflushopt(d2);
      mfence();
      lfence();
      before = rdtscp();
      lfence();
      *d1;
      *d2;
      after = rdtscp();
      lfence();
      // stop if an ACTIVATE was issued
      if ((after - before) > 1000) break;
    }
  }
}

// Gets the row index for a given address by considering the given row function.
uint64_t get_row_index(volatile char* addr, uint64_t row_function) {
  uint64_t cur_row = (uint64_t)addr & row_function;
  for (size_t i = 0; i < 64; i++) {
    if (row_function & (1 << i)) {
      return (cur_row >> i);
    }
  }
  return cur_row;
}

/// Writes a random value to 
void mem_values(volatile char* target, bool init, volatile char* start,
                volatile char* end, uint64_t row_function) {
  uint64_t start_o = 0;
  uint64_t end_o = MEM_SIZE;

  if (start != NULL) {
    start_o = (uint64_t)(start - target);
    start_o = (start_o / PAGE_SIZE) * PAGE_SIZE;
  }

  if (end != NULL) {
    end_o = start_o + ((uint64_t)(end - start));
    end_o = (end_o / PAGE_SIZE) * PAGE_SIZE;
  }

  // for each page in the address space [start, end]
  for (uint64_t i = start_o; i < end_o; i += PAGE_SIZE) {
    // reseed rand to have a sequence of reproducible numbers, using this we can
    // compare the initialized values with those after hammering to see whether
    // bit flips occurred
    srand(i * PAGE_SIZE);
    for (uint64_t j = 0; j < PAGE_SIZE; j += sizeof(int)) {
      uint64_t offset = i + j;
      int rand_val = rand();
      if (init) {
        // write random 4 bytes to target[offset] = target[i+j]
        *((int*)(target + offset)) = rand_val;
      } else {
        // check if any of the values written before (when 'init' was passed),
        // changed its value
        clflushopt(target + offset);
        mfence();
        if (*((int*)(target + offset)) != rand_val) {
          for (unsigned long c = 0; c < sizeof(int); c++) {
            if (*((char*)(target + offset + c)) != ((char*)&rand_val)[c]) {
              printf("\033[0;31m[*] Flip %p, row %lu, from %x to %x\033[0m\n",
                     target + offset + c,
                     get_row_index(target + offset + c, row_function),
                     ((unsigned char*)&rand_val)[c],
                     *(unsigned char*)(target + offset + c));
            }
          }
          *((int*)(target + offset)) = rand_val;
          clflushopt(target + offset);
          mfence();
        }
      }
    }
  }
}

/// Allocates a MEM_SIZE bytes of memory by using super or huge pages.
volatile char* allocate_memory() {
  volatile char* target;
  int ret;
  FILE* fp;

  if (SUPERPAGE) {
    // allocate memory using super pages
    fp = fopen("/mnt/huge/buff", "w+");
    if (fp == NULL) {
      perror("fopen");
      exit(-1);
    }
    target = (volatile char*)mmap((void*)ADDR, MEM_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB,
                                  fileno(fp), 0);
    if (target == MAP_FAILED) {
      perror("mmap");
      exit(-1);
    }
  } else {
    // allocate memory using huge pages
    ret = posix_memalign((void**)&target, MEM_SIZE, MEM_SIZE);
    assert(ret == 0);
    ret = madvise((void*)target, MEM_SIZE, MADV_HUGEPAGE);
    assert(ret == 0);
    memset((char*)target, 'A', MEM_SIZE);
    // for khugepaged
    printf("[+] Waiting for khugepaged\n");
    sleep(10);
  }
  // initialize memory with random but reproducible sequence of numbers
  mem_values(target, true, NULL, NULL, 0);
  return target;
}

/// Determine exactly 'size' target addresses in given bank.
void find_targets(volatile char* target,
                   std::vector<volatile char*>& target_bank, 
                   size_t size) {
  srand(time(0));
  while (target_bank.size() < size) {
    auto a1 = target + (rand() % (MEM_SIZE / 64)) * 64;
    auto look = std::find(target_bank.begin(), target_bank.end(), a1);
    if (look != target_bank.end()) continue;
    uint64_t cumulative_times = 0;
    for (const auto& addr : target_bank) {
      cumulative_times += measure_time(a1, addr);
    }
    if ((cumulative_times / (target_bank.size())) > THRESH) {
      target_bank.push_back(a1);
    }
  }
}

void find_bank_conflicts(volatile char* target,
                         std::vector<volatile char*>* banks) {
  srand(time(0));
  int nr_banks_cur = 0;
  while (nr_banks_cur < NUM_BANKS) {
  reset:
    auto a1 = target + (rand() % (MEM_SIZE / 64)) * 64;
    auto a2 = target + (rand() % (MEM_SIZE / 64)) * 64;
    auto ret1 = measure_time(a1, a2);
    auto ret2 = measure_time(a1, a2);

    if ((ret1 > THRESH) && (ret2 > THRESH)) {
      bool all_banks_set = true;
      for (size_t i = 0; i < NUM_BANKS; i++) {
        if (banks[i].empty()) {
          all_banks_set = false;
        } else {
          auto bank = banks[i];
          ret1 = measure_time(a1, bank[0]);
          ret2 = measure_time(a2, bank[0]);
          if ((ret1 > THRESH) || (ret2 > THRESH)) {
            // possibly noise if only exactly one is true,
            // i.e., (ret1 > THRESH) or (ret2 > THRESH)
            goto reset;
          }
        }
      }

      // stop if we already determined all bank functions
      if (all_banks_set) return;
      
      // store bank functions
      for (size_t i = 0; i < NUM_BANKS; i++) {
        auto bank = &banks[i];
        if (bank->empty()) {
          bank->push_back(a1);
          bank->push_back(a2);
          nr_banks_cur++;
          break;
        }
      }
    }
  }
}

uint64_t test_addr_against_bank(volatile char* addr,
                                std::vector<volatile char*>& bank) {
  uint64_t cumulative_times = 0;
  int times = 0;
  for (auto const& other_addr : bank) {
    if (addr != other_addr) {
      times++;
      auto ret = measure_time(addr, other_addr);
      cumulative_times += ret;
    }
  }
  return (times == 0) ? 0 : cumulative_times / times;
}

/*
 * Assumptions:
 *  1) row selection starts from higher bits than 13 (8K DRAM pages)
 *  2) single DIMM system (only bank/rank bits)
 *  3) Bank/Rank functions use at most 2 bits
 */
void find_functions(volatile char* target, std::vector<volatile char*>* banks,
                    uint64_t& row_function,
                    std::vector<uint64_t>& bank_rank_functions) {
  int max_bits;
  row_function = 0;
  max_bits = (SUPERPAGE) ? 30 : 21;

  for (int ba = 6; ba < NUM_BANKS; ba++) {
    auto addr = banks[ba].at(0);

    for (int b = 6; b < max_bits; b++) {
      // flip the bit at position b in the given address
      auto test_addr = (volatile char*)((uint64_t)addr ^ BIT_SET(b));
      auto time = test_addr_against_bank(test_addr, banks[ba]);

      if (time > THRESH) {
        if (b > 13) {
          row_function = row_function | BIT_SET(b);
        }
      } else {
        // it is possible that flipping this bit changes the function
        for (int tb = 6; tb < b; tb++) {
          auto test_addr2 = (volatile char*)((uint64_t)test_addr ^ BIT_SET(tb));
          time = test_addr_against_bank(test_addr2, banks[ba]);
          if (time > THRESH) {
            if (b > 13) {
              row_function = row_function | BIT_SET(b);
            }
            uint64_t new_function = 0;
            new_function = BIT_SET(b) | BIT_SET(tb);
            auto iter = std::find(bank_rank_functions.begin(),
                                  bank_rank_functions.end(), 
                                  new_function);
            if (iter == bank_rank_functions.end()) {
              bank_rank_functions.push_back(new_function);
            }
          }
        }
      }
    }
  }
}

uint64_t get_row_increment(uint64_t row_function) {
  for (size_t i = 0; i < 64; i++) {
    if (row_function & BIT_SET(i)) {
      return BIT_SET(i);
    }
  }
  printf("[-] no bit set for row function\n");
  return 0;
}

std::vector<uint64_t> get_bank_rank(
    std::vector<volatile char*>& target_bank,
    std::vector<uint64_t>& bank_rank_functions) {
  std::vector<uint64_t> bank_rank;
  auto addr = target_bank.at(0);
  for (size_t i = 0; i < bank_rank_functions.size(); i++) {
    uint64_t mask = ((uint64_t)addr) & bank_rank_functions[i];
    if ((mask == bank_rank_functions[i]) || (mask == 0)) {
      bank_rank.push_back(0);
    } else {
      bank_rank.push_back(1);
    }
  }
  return bank_rank;
}

volatile char* normalize_addr_to_bank(
    volatile char* cur_addr, std::vector<uint64_t>& cur_bank_rank,
    std::vector<uint64_t>& bank_rank_functions) {
  volatile char* normalized_addr = cur_addr;
  for (size_t i = 0; i < cur_bank_rank.size(); i++) {
    // apply the bank/rank function on the given address
    uint64_t mask = ((uint64_t)normalized_addr) & bank_rank_functions[i];
    
    // check whether we need to normalize the address
    bool normalize = 
      (cur_bank_rank[i] == ((mask == 0) || (mask == bank_rank_functions[i])));

    // continue with next iteration if no normalization is required
    if (!normalize) continue;

    // normalize address
    for (int b = 0; b < 64; b++) {
      if (bank_rank_functions[i] & BIT_SET(b)) {
        normalized_addr =
            (volatile char*)(((uint64_t)normalized_addr) ^ BIT_SET(b));
        break;
      }
    }
  }

  return normalized_addr;
}

volatile char* remap_row(volatile char* addr, uint64_t row_function) {
  uint64_t cur_row = (uint64_t)addr & row_function;
  for (size_t i = 0; i < 64; i++) {
    if (row_function & (1 << i)) {
      cur_row >>= i;
      uint64_t a3 = cur_row & 0x8ULL;
      cur_row = cur_row ^ ((a3 >> 1) | (a3 >> 2));
      cur_row <<= i;
      volatile char* old_addr = addr;
      addr = (volatile char*)
        (((uint64_t)addr ^ ((uint64_t)addr & row_function)) | cur_row);
      if (addr != old_addr) {
        printf("[+] switched addr\n");
      }
      break;
    }
  }
  return addr;
}

// Performs n-sided hammering.
void n_sided_hammer(volatile char* target, std::vector<volatile char*>* banks,
                    uint64_t row_function,
                    std::vector<uint64_t>& bank_rank_functions, int acts) {
  auto row_increment = get_row_increment(row_function);

  std::vector<uint64_t> bank_rank_masks[NUM_BANKS];
  for (size_t i = 0; i < NUM_BANKS; i++) {
    bank_rank_masks[i] = get_bank_rank(banks[i], bank_rank_functions);
  }

  while (true) {
    srand(time(NULL));

    // skip the first and last 100MB (just for convenience to avoid hammering 
    // on non-existing/illegal locations)
    auto cur_start_addr =
        target + MB(100) +
        (((rand() % (MEM_SIZE - MB(200)))) / PAGE_SIZE) * PAGE_SIZE;
    int aggressor_rows_size = (rand() % (MAX_ROWS - 3)) + 3;

    int v = (rand() % 3) + 1;
    int d = (rand() % 16);

    // This config generates flips on the golden module
    // cur_start_addr = (volatile char*)0x201b85c040;

    // cur_start_addr = (volatile char*)(((uint64_t)cur_start_addr &
    // 0xffffffffff000000LL) | 0x85c040); aggressor_rows_size = 16;
    v = 2;
    // d = 10;

    // hammering first four banks
    for (int ba = 0; ba < 4; ba++) {
      cur_start_addr = normalize_addr_to_bank(
          cur_start_addr, bank_rank_masks[ba], bank_rank_functions);

      std::vector<volatile char*> aggressors;

      volatile char* cur_next_addr = cur_start_addr;

      printf("[+] agg row ");
      for (int i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr =
            normalize_addr_to_bank(cur_next_addr + (d * row_increment),
                                   bank_rank_masks[ba], bank_rank_functions);
        // if(i == 1) printf("first %llx\n", cur_next_addr);
        printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);

        cur_next_addr =
            normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                   bank_rank_masks[ba], bank_rank_functions);
        printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);
      }
      if ((aggressor_rows_size % 2)) {
        normalize_addr_to_bank(cur_next_addr + (d * row_increment),
                               bank_rank_masks[ba], bank_rank_functions);
        printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);
      }
      printf("\n");

      if (NOSYNC) {
        printf("[+] Hammering %d aggressors with v %d d %d on bank %d\n",
               aggressor_rows_size, v, d, ba);
        hammer(aggressors);
      } else {
        cur_next_addr =
            normalize_addr_to_bank(cur_next_addr + (100 * row_increment),
                                   bank_rank_masks[ba], bank_rank_functions);
        auto d1 = cur_next_addr;
        cur_next_addr =
            normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                   bank_rank_masks[ba], bank_rank_functions);
        auto d2 = cur_next_addr;
        printf("[+] d1 row %" PRIu64 " d2 row %" PRIu64 "\n", get_row_index(d1, row_function),
               get_row_index(d2, row_function));
        if (ba == 0) {
          printf("[+] sync: ref_rounds %lu remainder %lu\n",
                 acts / aggressors.size(),
                 acts - ((acts / aggressors.size()) * aggressors.size()));
        }

        printf("[+] Hammering sync %d aggressors from addr %p on bank %d\n",
               aggressor_rows_size, cur_start_addr, ba);
        hammer_sync(aggressors, acts, d1, d2);
      }

      // check 100 rows before and after
      mem_values(target, false, aggressors[0] - (row_increment * 100),
                 aggressors[aggressors.size() - 1] + (row_increment * 120),
                 row_function);
    }
  }
}

/// Determine the number of activations per refresh interval.
int count_acts_per_ref(std::vector<volatile char*>* banks) {
  volatile char* a;
  volatile char* b;
  std::vector<uint64_t> acts;
  uint64_t before, after, count = 0, count_old = 0;
  a = (banks[0]).at(0);
  b = (banks[0]).at(1);

  *a;
  *b;

  while (true) {
    clflushopt(a);
    clflushopt(b);
    mfence();
    before = rdtscp();
    lfence();
    *a;
    *b;
    after = rdtscp();
    count++;
    if ((after - before) > 1000) {
      if (count_old != 0) {
        acts.push_back((count - count_old) * 2);
        // stop if we collected 50 data points
        if (acts.size() > 50) break;
      }
      count_old = count;
    }
  }

  count = 0;
  for (size_t i = 10; i < acts.size(); i++) {
    count += acts[i];
  }
  return (count / (acts.size() - 10));
}

int main(int argc, char** argv) {
  PatternBuilder pb;
  pb.print_patterns(100, 12);

  // paramter 1 is the number of hammer rounds
  if (argc == 2) {
    HAMMER_ROUNDS=(*argv[1] - '0');
  }


  // TODO: Makefile target to run evaluation, print on screen and write into file

  // TODO: Add metadata file with git commit, current DIMM etc.

  // TODO: Add help info



  volatile char* target;
  // create an array of size NUM_BANKS in which each element is a 
  // vector<volatile char*>
  std::vector<volatile char*> banks[NUM_BANKS];
  std::vector<uint64_t> bank_rank_functions;
  uint64_t row_function;
  int act;
  int ret;

  // give this process the highest CPU priority
  ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret != 0) printf("[-] setpriority failed\n");
  
  // allocate a bulk of memory
  target = allocate_memory();

  // generate address sets that map to the same bank
  find_bank_conflicts(target, banks);
  printf("[+] found bank conflicts\n");

  //
  for (size_t i = 0; i < NUM_BANKS; i++) {
    find_targets(target, banks[i], NUM_TARGETS);
  }
  printf("[+] populated addresses from different banks\n");

  // determine the row and bank/rank functions
  find_functions(target, banks, row_function, bank_rank_functions);

  // print functions
  printf(
      "[+] row function %" PRIu64 ", row increment %" PRIu64 ", and %lu bank/rank functions: ",
      row_function, get_row_increment(row_function),
      bank_rank_functions.size());
  for (size_t i = 0; i < bank_rank_functions.size(); i++) {
    printf("%" PRIu64 " ", bank_rank_functions[i]);
    if (i == (bank_rank_functions.size() - 1)) printf("\n");
  }

  // count the number of activations per refresh interval
  act = count_acts_per_ref(banks);
  printf("[+] %d activations for each refresh interval\n", act);

  // perform the hammering and check the flipped bits after each round
  n_sided_hammer(target, banks, row_function, bank_rank_functions, act);
}
