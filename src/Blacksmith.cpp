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

#include "Blacksmith.hpp"
#include "DRAMAddr.hpp"
#include "DramAnalyzer.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/CodeJitter.hpp"
#include "Fuzzer/HammeringPattern.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/PatternAddressMapping.hpp"
#include "Memory.hpp"

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
  size_t ref_rounds = acts/aggressors.size();
  size_t agg_rounds = ref_rounds;
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
  for (size_t i = 0; i < HAMMER_ROUNDS/ref_rounds; i++) {
    for (size_t j = 0; j < agg_rounds; j++) {
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

void n_sided_frequency_based_hammering(Memory &memory, DramAnalyzer &dram_analyzer, int acts) {
  printf("Starting frequency-based hammering.\n");
  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();
  CodeJitter code_jitter;

  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    fuzzing_params.randomize_parameters(true);

    // generate a hammering pattern: this is like a general access pattern template without concrete addresses
    HammeringPattern hammering_pattern;
    PatternBuilder pattern_builder(hammering_pattern);
    pattern_builder.generate_frequency_based_pattern(fuzzing_params);
    printf("[+] Pattern length: %zu\n", hammering_pattern.accesses.size());

    // then test this pattern with 5 different address sets
    int trials_per_pattern = 5;
    while (trials_per_pattern--) {
      // choose random addresses for pattern
      PatternAddressMapping mapping = hammering_pattern.generate_random_addr_mapping(fuzzing_params);

      // generate jitted hammering function
      // TODO future work: do jitting for each pattern once only and pass vector of addresses as array
      code_jitter.jit_strict(fuzzing_params.get_hammering_total_num_activations(),
                             FLUSHING_STRATEGY::EARLIEST_POSSIBLE,
                             FENCING_STRATEGY::LATEST_POSSIBLE,
                             hammering_pattern.get_jittable_accesses_vector(mapping));

      // do hammering
      code_jitter.hammer_pattern();
      // check whether any bit flips occurred
      memory.check_memory(dram_analyzer, mapping.get_lowest_address(), mapping.get_highest_address(), 25);

      // cleanup the jitter for its next use
      code_jitter.cleanup();
    }

//    std::cout << "++++++++++++ DEBUGGING MODE ++++++++++++++++++++++++++++++++++++" << std::endl;
//    nlohmann::json j = hammering_pattern;
//    std::cout << j << std::endl;
//    std::cout << "++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++" << std::endl;
//    exit(0);
  }
}

// Performs n-sided hammering.
void n_sided_hammer(Memory &memory, DramAnalyzer &dram_analyzer, int acts) {
  // TODO: Remove the usage of rand here and use C++ functions instead
  auto row_increment = dram_analyzer.get_row_increment();

  while (EXECUTION_ROUNDS_INFINITE || EXECUTION_ROUNDS--) {
    srand(time(nullptr));

    // skip the first and last 100MB (just for convenience to avoid hammering on non-existing/illegal locations)
    auto cur_start_addr =
        memory.get_starting_address() + MB(100) + (((rand()%(MEM_SIZE - MB(200))))/getpagesize())*getpagesize();
    int aggressor_rows_size = (rand()%(MAX_ROWS - 3)) + 3;

    // distance between aggressors (within a pair)
    int v = 2;

    // distance of each double-sided aggressor pair
    int d = (rand()%16);

    // hammering first four banks
    for (int ba = 0; ba < 4; ba++) {
      cur_start_addr =
          dram_analyzer.normalize_addr_to_bank(cur_start_addr, ba);
      std::vector<volatile char *> aggressors;
      volatile char *cur_next_addr = cur_start_addr;
      printf("[+] agg row ");
      for (int i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (d*row_increment), ba);
        printf("%lu ", dram_analyzer.get_row_index(cur_next_addr));
        aggressors.push_back(cur_next_addr);

        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (v*row_increment), ba);
        printf("%lu ", dram_analyzer.get_row_index(cur_next_addr));
        aggressors.push_back(cur_next_addr);
      }

      if ((aggressor_rows_size%2)!=0) {
        dram_analyzer.normalize_addr_to_bank(cur_next_addr + (d*row_increment), ba);
        printf("%lu ", dram_analyzer.get_row_index(cur_next_addr));
        aggressors.push_back(cur_next_addr);
      }
      printf("\n");

      // TODO: make USE_SYNC a program parameter (not a define)
      if (!USE_SYNC) {
        printf("[+] Hammering %d aggressors with v %d d %d on bank %d\n", aggressor_rows_size, v, d, ba);
        hammer(aggressors);
      } else {
        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (100*row_increment), ba);
        auto d1 = cur_next_addr;
        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (v*row_increment), ba);
        auto d2 = cur_next_addr;
        printf("[+] d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)\n",
               dram_analyzer.get_row_index(d1), d1, dram_analyzer.get_row_index(d2), d2);
        if (ba==0) {
          printf("[+] sync: ref_rounds %lu, remainder %lu\n",
                 acts/aggressors.size(),
                 acts - ((acts/aggressors.size())*aggressors.size()));
        }
        printf("[+] Hammering sync %d aggressors from addr %p on bank %d\n", aggressor_rows_size, cur_start_addr, ba);
        hammer_sync(aggressors, acts, d1, d2);
      }

      // check 100 rows before and after for flipped bits
      memory.check_memory(dram_analyzer, aggressors[0], aggressors[aggressors.size() - 1], 100);
    }
  }
}

/// Determine the number of activations per refresh interval.
size_t count_acts_per_ref(const std::vector<std::vector<volatile char *>> &banks) {
  size_t skip_first_N = 50;
  volatile char *a = banks.at(0).at(0);
  volatile char *b = banks.at(0).at(1);
  std::vector<uint64_t> acts;
  uint64_t running_sum = 0;
  uint64_t before = 0, after = 0, count = 0, count_old = 0;
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

  auto activations = (running_sum/acts.size());
  printf("[+] Counted %lu activations per refresh interval.\n", activations);

  return activations;
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
  system("echo \"Git_SHA: `git rev-parse --short HEAD 2>/dev/null || echo 'not a repository'`\"\n");
  fflush(stdout);
  system("echo Git_Status: `if [ \"$(git diff --stat 2>/dev/null)\" != \"\" ]; then echo dirty; else echo clean; fi`");
  fflush(stdout);
  printf("EXECUTION_ROUNDS: %s\n",
         (EXECUTION_ROUNDS_INFINITE ? std::string("INFINITE") : std::to_string(EXECUTION_ROUNDS)).c_str());
  print_global_defines();
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

  // give this process the highest CPU priority
  int ret = 0;
  ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) printf(FRED "[-] Instruction setpriority failed." NONE "\n");

  // allocate a large bulk of contiguous memory
  bool use_superpage = true;
  Memory memory(use_superpage);
  memory.allocate_memory(MEM_SIZE);

  DramAnalyzer dram_analyzer(memory.get_starting_address());
  // find address sets that create bank conflicts
  dram_analyzer.find_bank_conflicts();
  // determine the row and bank/rank functions
  dram_analyzer.find_functions(use_superpage);
  // determine the bank/rank masks
  dram_analyzer.find_bank_rank_masks();

  // initialize the DRAMAddr class
  DRAMAddr::initialize(dram_analyzer.get_bank_rank_functions().size(), memory.get_starting_address());

  // count the number of possible activations per refresh interval
  int act = 0;
  act = count_acts_per_ref(dram_analyzer.get_banks());

  // perform the hammering and check the flipped bits after each round
  if (USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    n_sided_frequency_based_hammering(memory, dram_analyzer, act);
  } else if (!USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    n_sided_hammer(memory, dram_analyzer, act);
  } else {
    fprintf(stderr,
            "Invalid combination of program control-flow arguments given. "
            "Note that fuzzing is only supported with synchronized hammering.");
    exit(1);
  }

  return 0;
}
