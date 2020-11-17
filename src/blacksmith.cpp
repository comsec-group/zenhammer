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
#include <unordered_set>
#include <vector>

#include "../include/DramAnalyzer.hpp"
#include "../include/GlobalDefines.hpp"
#include "../include/PatternBuilder.hpp"
#include "../include/utils.hpp"

/// the number of rounds to hammer
/// this is controllable via the first (unnamed) program parameter
static unsigned long long EXECUTION_ROUNDS = 0;
static bool EXECUTION_ROUNDS_INFINITE = true;

size_t count_activations_per_refresh_interval(unsigned char** patt, size_t num_accesses, size_t rounds) {
  auto median = [](size_t* vals, size_t size) -> uint64_t {
    auto gt = [](const void* a, const void* b) -> int {
      return (*(int*)a - *(int*)b);
    };
    qsort(vals, size, sizeof(uint64_t), gt);
    return ((size % 2) == 0) ? vals[size / 2] : (vals[(size_t)size / 2] + vals[((size_t)size / 2 + 1)]) / 2;
  };
  size_t* times = (size_t*)malloc(sizeof(size_t) * rounds);
  for (size_t k = 0; k < 15; k++) {
    sfence();
    for (size_t l = 0; l < num_accesses; l++) {
      *(volatile char*)patt[l];
    }
    for (size_t l = 0; l < num_accesses; l++) {
      clflush(patt[l]);
    }
  }
  for (size_t k = 0; k < rounds; k++) {
    sfence();
    size_t t0 = rdtscp();
    for (size_t l = 0; l < num_accesses; l++) {
      *(volatile char*)patt[l];
    }
    times[k] = rdtscp() - t0;
    for (size_t l = 0; l < num_accesses; l++) {
      clflush(patt[l]);
    }
  }
  size_t median_sum_access_time = median(times, rounds);
  // printf("Avg. cycles per access: %lu\n", median_sum_access_time / num_accesses);
  free(times);
  return median_sum_access_time / num_accesses;
}

void run_experiment(volatile char* start_address, int acts, std::vector<uint64_t>& cur_bank_rank_masks,
                    std::vector<uint64_t>& bank_rank_fns, uint64_t row_function) {
  const int NUM_INTERVALS = 500;
  std::vector<int> NOPS = {0, 1, 2, 5, 10, 15, 20, 25, 50, 75, 100, 250, 500, 700, 1000};
  for (const auto& NUM_NOPS : NOPS) {
    printf("###### NUM_NOPS: %d ######\n", NUM_NOPS);
    volatile char* address = start_address;
    const int NUM_ADDRESSES = 200;
    uint64_t before = 0;
    uint64_t after = 0;
    auto row_increment = get_row_increment(row_function);

    // generate addresses to the same bank but different rows
    // printf("rows in list_of_same_bank_addresses: ");
    unsigned char* same_bank_addrs[NUM_ADDRESSES];
    std::vector<volatile char*> conflict_address_set;
    for (size_t i = 0; i < NUM_ADDRESSES; i++) {
      address = normalize_addr_to_bank(address + row_increment, cur_bank_rank_masks, bank_rank_fns);
      // printf("   (r %" PRIu64 ", addr %p)\n", get_row_index(address, row_function), address);
      same_bank_addrs[i] = (unsigned char*)address;
      conflict_address_set.push_back(address);
    }
    // printf("\n");
    if ((long)address > (ADDR + (GB(1)))) {
      fprintf(stderr, "[-] Crossed boundary of 1 GB superpage. Exiting!");
      exit(1);
    }

    volatile char* last_addr = normalize_addr_to_bank(address + (rand() % 42) * row_increment, cur_bank_rank_masks, bank_rank_fns);

    const int NUM_ACCESSES_PER_REFRESH_INTERVAL = count_activations_per_refresh_interval(same_bank_addrs, NUM_ADDRESSES, 25);
    printf("NUM_ACCESSES_PER_REFRESH_INTERVAL: %d\n", NUM_ACCESSES_PER_REFRESH_INTERVAL);
    // shrink set of addresses in conflict_address_set to 98%
    while (conflict_address_set.size() > 0.95 * NUM_ACCESSES_PER_REFRESH_INTERVAL) conflict_address_set.pop_back();
    printf("accessing %zu addresses\n", conflict_address_set.size());

    // do some warmup..
    for (size_t k = 0; k < 15; k++) {
      sfence();
      for (size_t l = 0; l < conflict_address_set.size(); l++) {
        *conflict_address_set.at(l);
      }
      for (size_t l = 0; l < conflict_address_set.size(); l++) {
        clflushopt(conflict_address_set.at(l));
      }
    }
    clflushopt(last_addr);

    int cnt = 0;
    for (size_t i = 0; i < NUM_INTERVALS; i++) {
      // now access all addresses, then a NUM_NOPS nops, and then time the access to an arbitrary address
      int t = 0;
      sfence();
      // access all addresses sequentially
      for (volatile char* addr : conflict_address_set) {
        *addr;
        clflushopt(addr);
      }
      for (int j = 0; j < NUM_NOPS / 2; ++j) {
        asm("nop");
      }
      before = rdtscp();
      *last_addr;
      after = rdtscp();
      for (int j = (NUM_NOPS / 2) + 1; j < NUM_NOPS; ++j) {
        asm("nop");
      }
      t += (after - before);
      // printf("#cycles per access: %d\n", (after - before) / (int)conflict_address_set.size());
      // printf("#cycles for last access: %" PRIu64 "\n", (after - before));
      if ((after - before) > 1000) cnt++;
      clflushopt(last_addr);
    }
    printf("#intervals with #cycles > 1000: %d of %d\n", cnt, NUM_INTERVALS);
    printf("\n");
  }

  // Findings of experiments conducted in run_experiment in this and previous commits:
  // - using tREFI/tRC = 7800/46.750 ≈ 167 we can find out how many activates are theoretically possible within a
  //   REFRESH interval
  // - the theoretic value can be approximated by synchronizing with the start of the REFRESH interval and then
  //   accessing N same-bank addresses (see method count_activations_per_refresh_interval)
  // - if we choose 95% of the determined possible accesses as length for the hammering pattern, followed by M NOPs, we
  //   can see that the REFRESH happens most of the time (approx. 95%) within the NOPs, this effectively allows us to
  //   avoid using expensive fences and do a kind of soft-synchronization –- see the code in run_experiment
}

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
      for (size_t k = 0; k < aggressors.size() - 2; k++) {
        *aggressors[k];
        clflushopt(aggressors[k]);
      }
      mfence();
    }

    // after HAMMER_ROUNDS/ref_rounds times hammering, check for next ACTIVATE
    while (true) {
      mfence();
      lfence();
      before = rdtscp();
      lfence();
      clflushopt(d1);
      *d1;
      clflushopt(d2);
      *d2;
      after = rdtscp();
      lfence();
      // stop if an ACTIVATE was issued
      if ((after - before) > 1000) break;
    }
  }
}

// /// Performs synchronized hammering on the given aggressor rows.
// void hammer_sync(std::vector<volatile char*>& aggressors, int acts, volatile char* d1, volatile char* d2) {
//   char d1_value = *d1;
//   char d2_value = *d2;

//   int ref_rounds = acts / aggressors.size();
//   printf("acts: %d, aggressors.size(): %zu, HAMMER_ROUNDS/ref_rounds: %d\n",
//          acts, aggressors.size(), HAMMER_ROUNDS / ref_rounds);
//   int agg_rounds = ref_rounds;
//   uint64_t before = 0;
//   uint64_t after = 0;

//   *d1;
//   *d2;

//   // synchronize with the beginning of an interval
//   while (true) {
//     clflushopt(d1);
//     clflushopt(d2);
//     mfence();
//     before = rdtscp();
//     lfence();
//     *d1;
//     *d2;
//     after = rdtscp();
//     // stop if an REFRESH was issued
//     if ((after - before) > 1000) break;
//   }

//   // int cnt_d = 0;
//   // int cnt_f = 0;

//   // perform hammering for HAMMER_ROUNDS/ref_rounds intervals
//   for (int i = 0; i < HAMMER_ROUNDS / ref_rounds; i++) {
//     for (int j = 0; j < agg_rounds; j++) {
//       for (auto& a : aggressors) {
//         *a;
//       }
//       for (auto& a : aggressors) {
//         clflushopt(a);
//       }
//       mfence();
//     }

//     // after HAMMER_ROUNDS/ref_rounds times hammering, check for next REFRESH
//     while (true) {
//       // two activations: flush from cache which triggers a write-back to the DRAM as cache line is dirty after write
//       before = rdtscp();
//       lfence();
//       clflush(d1);
//       clflush(d2);
//       sfence();
//       after = rdtscp();
//       lfence();
//       if ((after - before) > 1000) {
//         // cnt_f++;
//         break;
//       }

//       // two activations: read and write the value to the cache
//       before = rdtscp();
//       lfence();
//       *d1 = *d1;
//       *d2 = *d2;
//       mfence();
//       after = rdtscp();
//       lfence();
//       if ((after - before) > 1000) {
//         // cnt_d++;
//         break;
//       }
//     }
//   }
//   // printf("[DEBUG] cnt_f: %d\n", cnt_f);
//   // printf("[DEBUG] cnt_d: %d\n", cnt_d);
// }

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
              printf(FRED "[!] Flip %p, row %lu, page offset: %lu, from %x to %x detected at t=%lu" NONE "\n",
                     target + offset + c,
                     get_row_index(target + offset + c, row_function), offset % PAGE_SIZE, ((unsigned char*)&rand_val)[c],
                     *(unsigned char*)(target + offset + c), (unsigned long)time(NULL));
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
  // create an unordered set of the addresses in the target bank for a quick lookup
  std::unordered_set<volatile char*> tmp(target_bank.begin(), target_bank.end());
  target_bank.clear();
  size_t num_repetitions = 5;
  srand(time(0));
  while (tmp.size() < size) {
    auto a1 = target + (rand() % (MEM_SIZE / 64)) * 64;
    if (tmp.count(a1) > 0) continue;
    uint64_t cumulative_times = 0;
    for (size_t i = 0; i < num_repetitions; i++) {
      for (const auto& addr : tmp) {
        cumulative_times += measure_time(a1, addr);
      }
    }
    cumulative_times /= num_repetitions;
    if ((cumulative_times / tmp.size()) > THRESH) {
      tmp.insert(a1);
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
                             std::vector<uint64_t>& bank_rank_functions,
                             std::vector<uint64_t>* bank_rank_masks,
                             int acts) {
  if (!USE_SYNC) {
    fprintf(stderr, "Fuzzing only supported with synchronized hammering. Aborting.");
    exit(0);
  }

  PatternBuilder pb(acts, target);

  int exec_round = 0;
  int num_optimization_rounds = 0;
  const int limit_optimization_rounds = 5;
  auto row_increment = get_row_increment(row_function);
  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    // hammer the first four banks
    for (int bank_no = 0; bank_no < 4; bank_no++) {
      // bool parameter_optimal = false;
      // generate a random pattern using fuzzing
      printf(FGREEN "[+] Running round %d on bank %d" NONE "\n", ++exec_round, bank_no);
      volatile char* first_address;
      volatile char* last_address;
      pb.randomize_parameters();

      pb.generate_random_pattern(bank_rank_masks, bank_rank_functions, row_function, row_increment,
                                 bank_no, &first_address, &last_address);

      // this loop optimizes the number of aggressors by looking at the number of activations that happen in the
      // synchronization at each REFRESH
      // do {
      // access this pattern synchronously with the REFRESH command
      auto trailing_acts = pb.hammer_pattern();
      auto overflow_acts = acts - trailing_acts;

      // check if any bit flips occurred while hammering
      mem_values(target, false,
                 first_address - (row_increment * 100),
                 last_address + (row_increment * 120),
                 row_function);

      // printf("trailing acts: %d\n", trailing_acts);
      // printf("overflow acts: %d\n", overflow_acts);

      // only optimize the pattern (remove aggressors) if the number of trailing activations is larger than 40
      // (we tested, 20-40 looks like to work) and is not larger than the activations in a REFRESH interval; also
      // check that we did not pass the optimization rounds limit yet
      //   if (trailing_acts % acts > 10 && num_optimization_rounds < limit_optimization_rounds) {
      //     int aggs_to_be_removed = overflow_acts / 2;
      //     if ((size_t)aggs_to_be_removed >= pb.count_aggs() || aggs_to_be_removed == 0) break;
      //     printf("[+] Optimizing pattern's length by removing %d aggs.\n", aggs_to_be_removed);
      //     int num_aggs_now = pb.remove_aggs(aggs_to_be_removed);
      //     if (num_aggs_now == 0) break;
      //     num_optimization_rounds++;
      //     // do again the code jitting
      //     pb.cleanup();
      //     pb.jit_code();
      //   } else {
      //     break;
      //   }
      // } while (true);

      // clean up the code jitting runtime for reuse with the next pattern
      pb.cleanup();

      printf("\n");
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

      if (RUN_EXPERIMENT) {
        printf("█████████████████████  RUNNING EXPERIMENT MODE  ████████████████████\n");
        run_experiment(cur_next_addr, acts, bank_rank_masks[ba], bank_rank_functions, row_function);
        printf("█████████████████████  TERMINATING EXPERIMENT  ████████████████████\n");
        exit(0);
      }

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
  size_t skip_first_N = 50;
  volatile char* a = banks[0].at(0);
  volatile char* b = banks[0].at(1);
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before, after, count = 0, count_old = 0;
  *a;
  *b;

  auto compute_std = [](std::vector<uint64_t>& values, uint64_t running_sum, int num_numbers) {
    int mean = running_sum / num_numbers;
    uint64_t var = 0;
    for (const auto& num : values) {
      var += std::pow(num - mean, 2);
    }
    return std::sqrt(var / num_numbers);
  };

  for (size_t i = 0;; i++) {
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
      if (i > skip_first_N && count_old != 0) {
        uint64_t value = (count - count_old) * 2;
        acts.push_back(value);
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 0 -> then stop collecting measurements
        if ((acts.size() % 200) == 0 && compute_std(acts, running_sum, acts.size()) == 0) break;
      }
      count_old = count;
    }
  }

  return (running_sum / acts.size());
}

/// Prints metadata about this evaluation run.
void print_metadata() {
  printf("=== Evaluation Run Metadata ==========\n");
  // TODO: Include our internal DRAM ID (not sure yet where to encode it; environment variable, dialog, parameter?)
  printf("Start_ts: %lu\n", (unsigned long)time(NULL));
  char name [1024] = "";
  gethostname( name, sizeof name );
  printf("Hostname: %s\n", name);
  printf("Internal_DIMM_ID: %d\n", -1);
  system("echo \"Git_SHA: `git rev-parse --short HEAD`\"\n");
  fflush(stdout);
  system("echo Git_Status: `if [ \"$(git diff --stat)\" != \"\" ]; then echo dirty; else echo clean; fi`");
  fflush(stdout);
  printf("------ Run Configuration ------\n");
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
  // seed srand with the current time
  srand(time(NULL));

  // prints the current git commit and some metadata
  print_metadata();

  // paramter 1 is the number of execution rounds: this is important as we need a fair comparison (same run time for
  // each DIMM to find patterns and for hammering)
  if (argc == 2) {
    char* p;
    errno = 0;
    unsigned long long conv = strtoull(argv[1], &p, 10);
    // check for errors
    if (errno != 0 || *p != '\0' || conv > ULONG_LONG_MAX) {
      printf(FRED "[-] Given program parameter (EXECUTION_ROUNDS) is invalid! Aborting." NONE "\n");
      return -1;
    }
    EXECUTION_ROUNDS = conv;
    EXECUTION_ROUNDS_INFINITE = false;
  }

  volatile char* target;
  // create an array of size NUM_BANKS in which each element is a
  // vector<volatile char*>
  std::vector<volatile char*> banks[NUM_BANKS];
  std::vector<uint64_t> bank_rank_functions;
  uint64_t row_function;
  int act, ret;

  // give this process the highest CPU priority
  ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret != 0) printf(FRED "[-] Instruction setpriority failed." NONE "\n");

  // allocate a large bulk of contigous memory
  target = allocate_memory();

  // find addresses of the same bank causing bank conflicts when accessed sequentially
  find_bank_conflicts(target, banks);
  printf("[+] Found bank conflicts.\n");
  for (size_t i = 0; i < NUM_BANKS; i++) {
    find_targets(target, banks[i], NUM_TARGETS);
    printf("[+] Populated addresses from different banks.\n");

    // determine the row and bank/rank functions
    find_functions(target, banks, row_function, bank_rank_functions);
    printf("[+] Row function 0x%" PRIx64 ", row increment 0x%" PRIx64 ", and %lu bank/rank functions: ",
           row_function, get_row_increment(row_function), bank_rank_functions.size());
    for (size_t i = 0; i < bank_rank_functions.size(); i++) {
      printf("0x%" PRIx64 " ", bank_rank_functions[i]);
      if (i == (bank_rank_functions.size() - 1)) printf("\n");
    }

    // count the number of possible activations per refresh interval
    act = count_acts_per_ref(banks);
    printf("[+] %d activations per refresh interval\n", act);

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
}
