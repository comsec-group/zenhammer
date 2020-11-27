#include <cinttypes>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <sys/mman.h>
#include <sys/resource.h>
#include <ctime>
#include <unistd.h>
#include <cstdint>
#include <unordered_set>
#include <vector>
#include <Utilities/Memory.hpp>

#include "Blacksmith.hpp"
#include "DRAMAddr.hpp"
#include "DramAnalyzer.hpp"
#include "Fuzzer/CodeJitter.hpp"
#include "Fuzzer/HammeringPattern.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/PatternAddressMapper.h"

/// the number of rounds to hammer
/// this is controllable via the first (unnamed) program parameter
static unsigned long long EXECUTION_ROUNDS{0};
static bool EXECUTION_ROUNDS_INFINITE{true};

/// Performs hammering on given aggressor rows for HAMMER_ROUNDS times.
void hammer(std::vector<volatile char *> &aggressors) {
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
void hammer_sync(std::vector<volatile char *> &aggressors, int acts,
                 volatile char *d1, volatile char *d2) {
  int ref_rounds = acts/aggressors.size();
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
  for (int i = 0; i < HAMMER_ROUNDS/ref_rounds; i++) {
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

/// Determine exactly 'size' target addresses in given bank.
void find_targets(volatile char *target, std::vector<volatile char *> &target_bank, size_t size) {
  // create an unordered set of the addresses in the target bank for a quick lookup
  // std::unordered_set<volatile char*> tmp; tmp.insert(target_bank.begin(), target_bank.end());
  std::unordered_set<volatile char *> tmp(target_bank.begin(), target_bank.end());
  target_bank.clear();
  size_t num_repetitions = 5;
  srand(time(nullptr));
  while (tmp.size() < size) {
    auto a1 = target + (rand()%(MEM_SIZE/64))*64;
    if (tmp.count(a1) > 0) continue;
    uint64_t cumulative_times = 0;
    for (size_t i = 0; i < num_repetitions; i++) {
      for (const auto &addr : tmp) {
        cumulative_times += measure_time(a1, addr);
      }
    }
    cumulative_times /= num_repetitions;
    if ((cumulative_times/tmp.size()) > THRESH) {
      tmp.insert(a1);
      target_bank.push_back(a1);
    }
  }
}

void n_sided_frequency_based_hammering(Memory &memory, uint64_t row_function, int acts) {
  PatternBuilder pattern_builder(acts, memory.get_starting_address());
  CodeJitter code_jitter;
  const uint64_t row_increment = get_row_increment(row_function);
  std::random_device rd;
  std::mt19937 gen = std::mt19937(rd());

  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    printf("EXECUTION_ROUNDS: %llu\n", EXECUTION_ROUNDS);
    printf("EXECUTION_ROUNDS_INFINITE: %d\n", (int) EXECUTION_ROUNDS_INFINITE);
    // generate a hammering pattern: this is like a general access pattern template without concrete addresses
    pattern_builder.randomize_parameters();
    HammeringPattern hammering_pattern;
    pattern_builder.generate_frequency_based_pattern(hammering_pattern);
    printf("Pattern length: %zu\n", hammering_pattern.accesses.size());

    // then test this pattern with 5 different address sets
    int trials_per_pattern = 5;
    while (trials_per_pattern--) {
      // choose random addresses for pattern
      PatternAddressMapper address_mapper(hammering_pattern);
      address_mapper.randomize_addresses(Range(0, 16).get_random_number(gen));

      // generate jitted hammering function
      // TODO future work: do jitting for each pattern once only and pass vector of addresses as array
      code_jitter.jit_strict(pattern_builder.hammering_total_num_activations,
                             pattern_builder.hammer_sync_reps,
                             FLUSHING_STRATEGY::EARLIEST_POSSIBLE,
                             FENCING_STRATEGY::LATEST_POSSIBLE,
                             address_mapper.export_pattern_for_jitting());

      // do hammering
      code_jitter.hammer_pattern();

      // check whether any bit flips occurred
      memory.check_memory(address_mapper.get_lowest_address() - (row_increment*25),
                          address_mapper.get_highest_address() + (row_increment*25), row_function);

      // cleanup the jitter for its next use
      code_jitter.cleanup();
    }
  }
}

// Performs n-sided hammering.
void n_sided_hammer(Memory &memory,
                    uint64_t row_function,
                    std::vector<uint64_t> &bank_rank_functions,
                    std::vector<uint64_t> *bank_rank_masks,
                    int acts) {
  auto row_increment = get_row_increment(row_function);

  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    srand(time(nullptr));

    // skip the first and last 100MB (just for convenience to avoid hammering on non-existing/illegal locations)
    auto cur_start_addr =
        memory.get_starting_address() + MB(100) + (((rand()%(MEM_SIZE - MB(200))))/PAGE_SIZE)*PAGE_SIZE;
    int aggressor_rows_size = (rand()%(MAX_ROWS - 3)) + 3;

    // distance between aggressors (within a pair)
    int v = 2;

    // distance of each double-sided aggressor pair
    int d = (rand()%16);

    // hammering first four banks
    for (int ba = 0; ba < 4; ba++) {
      cur_start_addr = normalize_addr_to_bank(cur_start_addr, bank_rank_masks[ba], bank_rank_functions);
      std::vector<volatile char *> aggressors;
      volatile char *cur_next_addr = cur_start_addr;
      printf("[+] agg row ");
      for (int i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (d*row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        printf("%lu ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);

        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v*row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        printf("%lu ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);
      }

      if ((aggressor_rows_size%2)!=0) {
        normalize_addr_to_bank(cur_next_addr + (d*row_increment), bank_rank_masks[ba], bank_rank_functions);
        printf("%lu ", get_row_index(cur_next_addr, row_function));
        aggressors.push_back(cur_next_addr);
      }
      printf("\n");

      if (!USE_SYNC) {
        printf("[+] Hammering %d aggressors with v %d d %d on bank %d\n", aggressor_rows_size, v, d, ba);
        hammer(aggressors);
      } else {
        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (100*row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        auto d1 = cur_next_addr;
        cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v*row_increment),
                                               bank_rank_masks[ba],
                                               bank_rank_functions);
        auto d2 = cur_next_addr;
        printf("[+] d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)\n",
               get_row_index(d1, row_function),
               d1,
               get_row_index(d2, row_function),
               d2);
        if (ba==0) {
          printf("[+] sync: ref_rounds %lu, remainder %lu\n",
                 acts/aggressors.size(),
                 acts - ((acts/aggressors.size())*aggressors.size()));
        }
        printf("[+] Hammering sync %d aggressors from addr %p on bank %d\n", aggressor_rows_size, cur_start_addr, ba);
        hammer_sync(aggressors, acts, d1, d2);
      }

      // check 100 rows before and 120 rows after if any bits flipped
      memory.check_memory(aggressors[0] - (row_increment*100),
                          aggressors[aggressors.size() - 1] + (row_increment*120), row_function);
    }
  }
}

/// Determine the number of activations per refresh interval.
size_t count_acts_per_ref(std::vector<volatile char *> *banks) {
  size_t skip_first_N = 50;
  volatile char *a = banks[0].at(0);
  volatile char *b = banks[0].at(1);
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before, after, count = 0, count_old = 0;
  *a;
  *b;

  auto compute_std = [](std::vector<uint64_t> &values, uint64_t running_sum, size_t num_numbers) {
    size_t mean = running_sum/num_numbers;
    uint64_t var = 0;
    for (const auto &num : values) {
      var += std::pow(num - mean, 2);
    }
    return std::sqrt(var/num_numbers);
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
      if (i > skip_first_N && count_old!=0) {
        uint64_t value = (count - count_old)*2;
        acts.push_back(value);
        running_sum += value;
        // check after each 200 data points if our standard deviation reached 0 -> then stop collecting measurements
        if ((acts.size()%200)==0 && compute_std(acts, running_sum, acts.size())==0) break;
      }
      count_old = count;
    }
  }

  return (running_sum/acts.size());
}

/// Prints metadata about this evaluation run.
void print_metadata() {
  printf("=== Evaluation Run Metadata ==========\n");
  // TODO: Include our internal DRAM ID (not sure yet where to encode it; environment variable, dialog, parameter?)
  printf("Start_ts: %lu\n", (unsigned long) time(nullptr));
  char name[1024] = "";
  gethostname(name, sizeof name);
  printf("Hostname: %s\n", name);
  printf("Internal_DIMM_ID: %d\n", -1);
  system("echo \"Git_SHA: `git rev-parse --short HEAD`\"\n");
  fflush(stdout);
  system("echo Git_Status: `if [ \"$(git diff --stat)\" != \"\" ]; then echo dirty; else echo clean; fi`");
  fflush(stdout);
  printf("------ Run Configuration ------\n");
  printf("CACHELINE_SIZE: %d\n", CACHELINE_SIZE);
  printf("DRAMA_ROUNDS: %d\n", DRAMA_ROUNDS);
  printf("HAMMER_ROUNDS: %d\n", HAMMER_ROUNDS);
  printf("EXECUTION_ROUNDS: %s\n",
         (EXECUTION_ROUNDS_INFINITE ? std::string("INFINITE") : std::to_string(EXECUTION_ROUNDS)).c_str());
  printf("MAX_ROWS: %d\n", MAX_ROWS);
  printf("MEM_SIZE: %lu\n", MEM_SIZE);
  printf("NUM_BANKS: %d\n", NUM_BANKS);
  printf("NUM_TARGETS: %d\n", NUM_TARGETS);
  printf("USE_SYNC: %s\n", USE_SYNC ? "true" : "false");
  printf("======================================\n");
  fflush(stdout);
}

void parse_arguments(int argc, char **argv) {
  // optional parameter 1: number of execution rounds
  if (argc==2) {
    char *p;
    errno = 0;
    unsigned long long conv = strtoull(argv[1], &p, 10);
    if (errno!=0 || *p!='\0' || conv > ULLONG_MAX) {
      printf(FRED "[-] Given program parameter (EXECUTION_ROUNDS) is invalid! Aborting." NONE "\n");
      exit(1);
    }
    EXECUTION_ROUNDS = conv;
    EXECUTION_ROUNDS_INFINITE = false;
  }
}

int main(int argc, char **argv) {
  // prints the current git commit and some metadata
  print_metadata();

  // parse the program arguments
  parse_arguments(argc, argv);

  // create an array of size NUM_BANKS in which each element is a vector<volatile char*>
  std::vector<volatile char *> banks[NUM_BANKS];
  std::vector<uint64_t> bank_rank_functions;
  uint64_t row_function = 0;
  int act = 0;
  int ret = 0;

  // give this process the highest CPU priority
  ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) printf(FRED "[-] Instruction setpriority failed." NONE "\n");

  // allocate a large bulk of contigous memory
  bool use_superpage = true;
  Memory memory(use_superpage);
  memory.allocate_memory(MEM_SIZE);

  // find addresses of the same bank causing bank conflicts when accessed sequentially
  find_bank_conflicts(memory.get_starting_address(), banks);
  printf("[+] Found bank conflicts.\n");
  for (auto &bank : banks) {
    find_targets(memory.get_starting_address(), bank, NUM_TARGETS);
  }
  printf("[+] Populated addresses from different banks.\n");

  // determine the row and bank/rank functions
  find_functions(banks, row_function, bank_rank_functions, use_superpage);
  printf("[+] Row function 0x%" PRIx64 ", row increment 0x%" PRIx64 ", and %lu bank/rank functions: ",
         row_function, get_row_increment(row_function), bank_rank_functions.size());
  for (size_t j = 0; j < bank_rank_functions.size(); j++) {
    printf("0x%" PRIx64 " ", bank_rank_functions[j]);
    if (j==(bank_rank_functions.size() - 1)) printf("\n");
  }

  // TODO: This is a shortcut to check if it's a single rank dimm or dual rank in order to load the right memory
  //  configuration. We should get these infos from dmidecode to do it properly, but for now this is easier.
  size_t num_ranks;
  if (bank_rank_functions.size()==5) {
    num_ranks = RANKS(2);
  } else if (bank_rank_functions.size()==4) {
    num_ranks = RANKS(1);
  } else {
    fprintf(stderr, FRED "[-] Could not initialize DRAMAddr as #ranks seems not to be 1 or 2." NONE "\n");
    exit(0);
  }
  DRAMAddr::load_mem_config((CHANS(CHANNEL) | DIMMS(DIMM) | num_ranks | BANKS(NUM_BANKS)));
  DRAMAddr::set_base((void *) memory.get_starting_address());

  // count the number of possible activations per refresh interval
  act = count_acts_per_ref(banks);
  printf("[+] %d activations per refresh interval.\n", act);

  // determine bank/rank masks
  std::vector<uint64_t> bank_rank_masks[NUM_BANKS];
  for (size_t j = 0; j < NUM_BANKS; j++) {
    bank_rank_masks[j] = get_bank_rank(banks[j], bank_rank_functions);
  }

  // perform the hammering and check the flipped bits after each round
  if (USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    n_sided_frequency_based_hammering(memory, row_function, act);
  } else if (!USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    n_sided_hammer(memory, row_function, bank_rank_functions, bank_rank_masks, act);
  } else {
    fprintf(stderr,
            "Invalid combination of program control-flow arguments given. "
            "Note that fuzzing is only supported with synchronized hammering.");
    exit(1);
  }

  return 0;
}
