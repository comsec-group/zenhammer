#include <assert.h>
#include <inttypes.h>
#include <limits.h>
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
#include <numeric>
#include <vector>

#include "DramAnalyzer.h"
#include "GlobalDefines.h"
#include "PatternBuilder.h"
#include "utils.h"

/// the number of rounds to hammer
/// this is controllable via the first (unnamed) program parameter
static unsigned long long EXECUTION_ROUNDS = 0;
static bool EXECUTION_ROUNDS_INFINITE = true;

/// Performs hammering on given aggressor rows for HAMMER_ROUNDS times.
void hammer(std::vector<volatile char*>& aggressors) {
#if 0
    for(size_t i = 0; i < aggressors.size() -1; i++)
        printf("measure_time %d\n", measure_time(aggressors[i], aggressors[i+1]));
#endif
  for (size_t i = 0; i < HAMMER_ROUNDS; i++) {
    for (auto& a : aggressors) {
      *a;
    }
    for (auto& a : aggressors) {
      clflushopt(a);
    }
    mfence();
  }
}

/// Performs synchronized hammering on the given aggressor rows.
void hammer_sync(std::vector<volatile char*>& aggressors, int acts, volatile char* d1, volatile char* d2) {
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
    // stop if an ACTIVATE was issued
    if ((after - before) > 1000) break;
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

/// Serves two purposes, if init=true then it initializes the memory with a pseudorandom (i.e., reproducible) sequence
/// of numbers; if init=false then it checks whether any of the previously written values changed (i.e., bits flipped).
void mem_values(volatile char* target, bool init, volatile char* start, volatile char* end, uint64_t row_function) {
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

  if (init)
    printf("[+] Initializing memory with pseudorandom sequence.\n");
  else
    printf("[+] Checking if any bit flips occurred.\n");

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
              printf(FRED "[!] Flip %p, row %lu, from %x to %x" NONE "\n", target + offset + c,
                     get_row_index(target + offset + c, row_function), ((unsigned char*)&rand_val)[c],
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

  if (USE_SUPERPAGE) {
    // allocate memory using super pages
    fp = fopen("/mnt/huge/buff", "w+");
    if (fp == NULL) {
      perror("fopen");
      exit(-1);
    }
    target = (volatile char*)mmap((void*)ADDR, MEM_SIZE, PROT_READ | PROT_WRITE,
                                  MAP_SHARED | MAP_ANONYMOUS | MAP_HUGETLB, fileno(fp), 0);
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
void find_targets(volatile char* target, std::vector<volatile char*>& target_bank, size_t size) {
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

volatile char* remap_row(volatile char* addr, uint64_t row_function) {
  uint64_t cur_row = (uint64_t)addr & row_function;
  for (size_t i = 0; i < 64; i++) {
    if (row_function & (1 << i)) {
      cur_row >>= i;
      uint64_t a3 = cur_row & 0x8ULL;
      cur_row = cur_row ^ ((a3 >> 1) | (a3 >> 2));
      cur_row <<= i;
      volatile char* old_addr = addr;
      addr = (volatile char*)(((uint64_t)addr ^ ((uint64_t)addr & row_function)) | cur_row);
      if (addr != old_addr) {
        printf("[+] Switched addr\n");
      }
      break;
    }
  }
  return addr;
}

void n_sided_fuzzy_hammering(volatile char* target, uint64_t row_function,
                             std::vector<uint64_t>& bank_rank_functions, std::vector<uint64_t>* bank_rank_masks, int acts) {
  auto row_increment = get_row_increment(row_function);

  if (!USE_SYNC) {
    fprintf(stderr, "Fuzzing only supported with synchronized hammering. Aborting.");
    exit(0);
  }

  PatternBuilder pb;
  int cur_round = 0;
  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    cur_round++;
    // TODO: Move this bank no. (ba) parameter into the PatternBuilder
    // hammer the first four banks
    for (int ba = 0; ba < 4; ba++) {
      // generate a random pattern using fuzzing
      printf(FGREEN "[+] Running round %d on bank %d" NONE "\n", cur_round, ba);
      auto agg_addresses = pb.generate_random_pattern(target, bank_rank_masks, bank_rank_functions, row_function, row_increment, acts, ba);
      // access this pattern synchroniously with the REFRESH command
      pb.access_pattern(acts);
      // check if pattern caused any bit flips
      mem_values(target, false, agg_addresses.first - (row_increment * 100),
                 agg_addresses.second + (row_increment * 120), row_function);
      // clean up the code jitting runtime for reuse with the next pattern
      pb.cleanup_pattern();
    }
  }
}

// Performs n-sided hammering.
void n_sided_hammer(volatile char* target, uint64_t row_function,
                    std::vector<uint64_t>& bank_rank_functions, std::vector<uint64_t>* bank_rank_masks, int acts) {
  auto row_increment = get_row_increment(row_function);

  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    srand(time(NULL));

    // skip the first and last 100MB (just for convenience to avoid hammering on non-existing/illegal locations)
    auto cur_start_addr = target + MB(100) + (((rand() % (MEM_SIZE - MB(200)))) / PAGE_SIZE) * PAGE_SIZE;
    int aggressor_rows_size = (rand() % (MAX_ROWS - 3)) + 3;

    // distance between aggressors (within a pair)
    int v = (rand() % 3) + 1;
    v = 2;

    // distance of each double-sided aggressor pair
    int d = (rand() % 16);

    // hammering first four banks
    for (int ba = 0; ba < 4; ba++) {
      cur_start_addr = normalize_addr_to_bank(cur_start_addr, bank_rank_masks[ba], bank_rank_functions);
      std::vector<volatile char*> aggressors;
      volatile char* cur_next_addr = cur_start_addr;
      printf("[+] agg row ");
      for (int i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (d * row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);

        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);
      }

      if ((aggressor_rows_size % 2) != 0) {
        normalize_addr_to_bank(cur_next_addr + (d * row_increment), bank_rank_masks[ba], bank_rank_functions);
        printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);
      }
      printf("\n");

      if (!USE_SYNC) {
        printf("[+] Hammering %d aggressors with v %d d %d on bank %d\n", aggressor_rows_size, v, d, ba);
        hammer(aggressors);
      } else {
        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (100 * row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        auto d1 = cur_next_addr;
        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        auto d2 = cur_next_addr;
        printf("[+] d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)\n",
               get_row_index(d1, row_function),
               d1,
               get_row_index(d2, row_function),
               d2);
        if (ba == 0) {
          printf("[+] sync: ref_rounds %lu, remainder %lu\n",
                 acts / aggressors.size(),
                 acts - ((acts / aggressors.size()) * aggressors.size()));
        }

        printf("[+] Hammering sync %d aggressors from addr %p on bank %d\n", aggressor_rows_size, cur_start_addr, ba);
        hammer_sync(aggressors, acts, d1, d2);
      }

      // check 100 rows before and 120 rows after if any bits flipped
      mem_values(target, false, aggressors[0] - (row_increment * 100),
                 aggressors[aggressors.size() - 1] + (row_increment * 120), row_function);
    }
  }
}

/// Determine the number of activations per refresh interval.
int count_acts_per_ref(std::vector<volatile char*>* banks) {
  volatile char* a = banks[0].at(0);
  volatile char* b = banks[0].at(1);
  std::vector<uint64_t> acts;
  uint64_t before, after, count = 0, count_old = 0;
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

/// Prints metadata about this evaluation run.
void print_metadata() {
  printf("=== Evaluation Run Metadata ==========\n");
  // TODO: Include our internal DRAM ID (not sure yet where to encode it; environment variable, dialog, parameter?)
  printf("Internal_DIMM_ID: %d\n", -1);
  system("echo \"Git_SHA: `git rev-parse --short HEAD`\"\n");
  fflush(stdout);
  system("echo Git_Status: `if [ \"$(git diff --stat)\" != \"\" ]; then echo dirty; else echo clean; fi`");
  fflush(stdout);
  printf("------ Program Arguments ------\n");
  printf("ADDR: 0x%lx\n", ADDR);
  printf("CACHELINE_SIZE: %d\n", CACHELINE_SIZE);
  printf("DRAMA_ROUNDS: %d\n", DRAMA_ROUNDS);
  printf("HAMMER_ROUNDS: %d\n", HAMMER_ROUNDS);
  printf("EXECUTION_ROUNDS: %s\n", (EXECUTION_ROUNDS_INFINITE ? std::string("INFINITE") : std::to_string(EXECUTION_ROUNDS)).c_str());
  printf("MAX_ROWS: %d\n", MAX_ROWS);
  printf("MEM_SIZE: %d\n", MEM_SIZE);
  printf("NUM_BANKS: %d\n", NUM_BANKS);
  printf("NUM_TARGETS: %d\n", NUM_TARGETS);
  printf("USE_FUZZING: %s\n", USE_FUZZING ? "true" : "false");
  printf("USE_SUPERPAGE: %s\n", USE_SUPERPAGE ? "true" : "false");
  printf("USE_SYNC: %s\n", USE_SYNC ? "true" : "false");
  printf("======================================\n");
  fflush(stdout);
}

int main(int argc, char** argv) {
  // prints the current git commit and the metadata
  print_metadata();

  // paramter 1 is the number of execution rounds: this is important as we need a fair comparison
  if (argc == 2) {
    char* p;
    errno = 0;
    unsigned long long conv = strtoull(argv[1], &p, 10);
    // check for errors
    if (errno != 0 || *p != '\0' || conv > ULONG_LONG_MAX) {
      printf("[-] Given program parameter (EXECUTION_ROUNDS) is invalid! Aborting.\n");
      return -1;
    }
    EXECUTION_ROUNDS = conv;
    EXECUTION_ROUNDS_INFINITE = false;
  }

  // TODO: Add help info on how to run this tool (sudo) and supported args

  volatile char* target;
  // create an array of size NUM_BANKS in which each element is a
  // vector<volatile char*>
  std::vector<volatile char*> banks[NUM_BANKS];
  std::vector<uint64_t> bank_rank_functions;
  uint64_t row_function;
  int act, ret;

  // give this process the highest CPU priority
  ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret != 0) printf("[-] Instruction setpriority failed\n");

  // allocate a bulk of memory
  target = allocate_memory();

  // find addresses of the same bank causing bank conflicts when accessed sequentially
  find_bank_conflicts(target, banks);
  printf("[+] Found bank conflicts\n");

  //
  for (size_t i = 0; i < NUM_BANKS; i++) {
    find_targets(target, banks[i], NUM_TARGETS);
  }
  printf("[+] Populated addresses from different banks\n");

  // determine the row and bank/rank functions
  find_functions(target, banks, row_function, bank_rank_functions);

  // print row and bank/rank functions
  printf("[+] Row function 0x%" PRIx64 ", row increment 0x%" PRIx64 ", and %lu bank/rank functions: ",
         row_function,
         get_row_increment(row_function),
         bank_rank_functions.size());
  for (size_t i = 0; i < bank_rank_functions.size(); i++) {
    printf("0x%" PRIx64 " ", bank_rank_functions[i]);
    if (i == (bank_rank_functions.size() - 1)) printf("\n");
  }

  // count the number of possible activations per refresh interval
  act = count_acts_per_ref(banks);
  printf("[+] %d activations for each refresh interval\n", act);

  // determine bank/rank masks
  std::vector<uint64_t> bank_rank_masks[NUM_BANKS];
  for (size_t i = 0; i < NUM_BANKS; i++) {
    bank_rank_masks[i] = get_bank_rank(banks[i], bank_rank_functions);
  }

  // perform the hammering and check the flipped bits after each round
  if (USE_FUZZING) {
    n_sided_fuzzy_hammering(target, row_function, bank_rank_functions, bank_rank_masks, act);
  } else {
    n_sided_hammer(target, row_function, bank_rank_functions, bank_rank_masks, act);
  }

  return 0;
}
