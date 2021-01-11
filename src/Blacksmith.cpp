#include <cinttypes>
#include <cstdlib>
#include <ctime>
#include <cstdint>
#include <unordered_set>
#include <vector>
#include <fstream>
#include <chrono>
#include <thread>

#include <sys/mman.h>
#include <sys/resource.h>
#include <unistd.h>

#include "Blacksmith.hpp"
#include "DRAMAddr.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/CodeJitter.hpp"
#include "Fuzzer/HammeringPattern.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/PatternAddressMapper.hpp"
#include "Utilities/Logger.hpp"

/// the number of rounds to hammer
static long RUN_TIME_LIMIT{0};

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

void generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses) {
  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

  fuzzing_params.randomize_parameters(true);

  if (trials_per_pattern > 1 && trials_per_pattern < PROBES_PER_PATTERN) {
    trials_per_pattern++;
    hammering_pattern.aggressors.clear();
  } else {
    trials_per_pattern = 0;
    hammering_pattern.aggressors.clear();
    hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
  }

  PatternBuilder pattern_builder(hammering_pattern);
  pattern_builder.generate_frequency_based_pattern(fuzzing_params);

  // choose random addresses for pattern
  PatternAddressMapper mapping;
  mapping.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns);
  mapping.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, rows_to_access, max_accesses);
}

long get_timestamp_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
};

unsigned long long get_timestamp_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch())
      .count();
};

void do_random_accesses(const std::vector<volatile char *> random_rows, unsigned long long duration_us) {
  auto random_access_limit = get_timestamp_us() + duration_us;
  while (get_timestamp_us() < random_access_limit) {
    for (volatile char *e : random_rows) {
      *e; // this should be fine as random_rows as volatile
    }
  }
}

void n_sided_frequency_based_hammering(Memory &memory, DramAnalyzer &dram_analyzer, int acts) {
  Logger::log_info("Starting frequency-based hammering.");

  // the number of successful hammering probes (note: if a pattern works on different locations, we increase this
  // counter once for each successful location)
  size_t NUM_SUCCESSFULL_PROBES = 0;

  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

  CodeJitter code_jitter;

#ifdef ENABLE_JSON
  nlohmann::json arr = nlohmann::json::array();
#endif

  long execution_time_limit = get_timestamp_sec() + RUN_TIME_LIMIT;

  int cur_round = 0;
  while (get_timestamp_sec() < execution_time_limit) {
    cur_round++;

    Logger::log_highlight(string_format("Generating hammering pattern #%d.", cur_round));
    fuzzing_params.randomize_parameters(true);

    // generate a hammering pattern: this is like a general access pattern template without concrete addresses
    hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
    PatternBuilder pattern_builder(hammering_pattern);
    pattern_builder.generate_frequency_based_pattern(fuzzing_params);

    // randomize the order of AggressorAccessPatterns to avoid biasing the PatternAddressMapper as it always assigns
    // rows in order of the AggressorAccessPatterns map
    // (e.g., the first element in AggressorAccessPatterns is assigned to the lowest DRAM row).
    std::random_device rd;
    std::shuffle(hammering_pattern.agg_access_patterns.begin(),
                 hammering_pattern.agg_access_patterns.end(),
                 std::default_random_engine(rd()));


    // then test this pattern with N different address sets
    while (trials_per_pattern++ < PROBES_PER_PATTERN) {
      // choose random addresses for pattern
      PatternAddressMapper mapper;

      Logger::log_info(string_format("Running pattern #%d (%s) for address set %d (%s).",
                                     cur_round,
                                     hammering_pattern.instance_id.c_str(),
                                     trials_per_pattern,
                                     mapper.get_instance_id().c_str()));

      // randomize the aggressor ID -> DRAM row mapping
      mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns);

      // now fill the pattern with these random addresses
      std::vector<volatile char *> hammering_accesses_vec;
      mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, hammering_accesses_vec);

      // now create instructions that follow this pattern (i.e., do jitting of code)
      bool sync_at_each_ref = fuzzing_params.get_random_sync_each_ref();
      int num_aggs_for_sync = fuzzing_params.get_random_num_aggressors_for_sync();
      code_jitter.jit_strict(fuzzing_params,
                             FLUSHING_STRATEGY::EARLIEST_POSSIBLE,
                             FENCING_STRATEGY::LATEST_POSSIBLE,
                             hammering_accesses_vec,
                             sync_at_each_ref,
                             num_aggs_for_sync);

      // wait for a random time before starting to hammer, while waiting access random rows that are not part of the
      // currently hammering pattern; this wait interval serves for two purposes: to reset the sampler and start from a
      // clean state before hammering, and also to fuzz a possible dependence at which REF we start hammering
      auto wait_until_hammering_us = fuzzing_params.get_random_wait_until_start_hammering_microseconds();
      FuzzingParameterSet::print_dynamic_parameters2(sync_at_each_ref, wait_until_hammering_us, num_aggs_for_sync);
      std::vector<volatile char *> random_rows;
      if (wait_until_hammering_us > 0) {
        random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
        do_random_accesses(random_rows, wait_until_hammering_us);
      }

#ifdef DEBUG_SAMSUNG
      const int reproducibility_rounds = 20;
#else
      const int reproducibility_rounds = 100;
#endif
      int cur_reproducibility_round = 1;
      int reproducibility_rounds_with_bitflips = 0;
      bool reproducibility_mode = false;
      std::stringstream ss;
      do {
        // do hammering
        code_jitter.hammer_pattern(fuzzing_params, !reproducibility_mode);

        // check if any bit flips happened
        auto flipped_bits = memory.check_memory(dram_analyzer, mapper, reproducibility_mode);
        if (flipped_bits > 0) reproducibility_rounds_with_bitflips++;

        // this if/else block is only executed in the very first round: it decides whether to start the reproducibility
        // check (if any bit flips were found) or not
        if (!reproducibility_mode && flipped_bits==0) {
          // don't do reproducibility check if this pattern does not seem to be working
          break;
        } else if (!reproducibility_mode && flipped_bits > 0) {
          // mark this probe as successful (but only once, not each reproducibility round!)
          NUM_SUCCESSFULL_PROBES++;
        }

        // start/continue reproducibility check
        ss << flipped_bits;
        if (cur_reproducibility_round < reproducibility_rounds) ss << " ";
        if (!reproducibility_mode) {
          reproducibility_mode = true;
          Logger::log_info("Testing bit flip's reproducibility.");
        }

        // last round: finish reproducibility check by printing pattern's reproducibility coefficient
        if (cur_reproducibility_round==reproducibility_rounds) {
          Logger::log_info(string_format("Bit flip's reproducibility score: %d/%d (#flips: %s)",
                                         reproducibility_rounds_with_bitflips,
                                         reproducibility_rounds,
                                         ss.str().c_str()));

          // derive number of reps we need to do to trigger a bit flip based on the current reproducibility coefficient
          reproducibility_score = reproducibility_rounds_with_bitflips/reproducibility_rounds;
          auto old_reps_per_pattern = REPS_PER_PATTERN;
          // it's important to use max here, otherwise REPS_PER_PATTERN can become 0 (i.e., stop hammering)
          REPS_PER_PATTERN =
              std::max(1UL,
                       REPS_PER_PATTERN + (1/NUM_SUCCESSFULL_PROBES)*(reproducibility_score - REPS_PER_PATTERN));
          Logger::log_info(string_format("Updated REPS_PER_PATTERN: %d → %d", old_reps_per_pattern, REPS_PER_PATTERN));
        }

        // wait a bit and do some random accesses before checking reproducibility of the pattern
        if (random_rows.empty()) {
          random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
        }
        do_random_accesses(random_rows, 64000); // 64000us (retention time)

        cur_reproducibility_round++;
      } while (cur_reproducibility_round <= reproducibility_rounds);

      // assign the computed reproducibility score to this pattern s.t. it is included in the JSON export
      mapper.reproducibility_score = reproducibility_score;

      // it is important that we store this mapper after we did memory.check_memory to include the found BitFlip
      hammering_pattern.address_mappings.push_back(mapper);

#ifdef ENABLE_JSON
      arr.push_back(hammering_pattern);
#endif

      // cleanup the jitter for its next use
      code_jitter.cleanup();
    }
    trials_per_pattern = 0;
  }

#ifdef ENABLE_JSON
  // export everything to JSON, this includes the HammeringPattern, AggressorAccessPattern, and BitFlips
  std::ofstream json_export;
  json_export.open("raw_data.json");
  json_export << arr;
  json_export.close();
#endif
}

// Performs n-sided hammering.
void n_sided_hammer(Memory &memory, DramAnalyzer &dram_analyzer, int acts) {
  // TODO: Remove the usage of rand here and use C++ functions instead
  auto row_increment = dram_analyzer.get_row_increment();

  auto ts_start = std::chrono::high_resolution_clock::now();
  ts_start.time_since_epoch().count();
  auto limit = get_timestamp_sec() + RUN_TIME_LIMIT;

  while (get_timestamp_sec() < limit) {
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
      std::stringstream ss;
      ss << "agg row: ";
      for (int i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (d*row_increment), ba);
        ss << dram_analyzer.get_row_index(cur_next_addr) << " ";
        aggressors.push_back(cur_next_addr);

        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (v*row_increment), ba);
        ss << dram_analyzer.get_row_index(cur_next_addr) << " ";
        aggressors.push_back(cur_next_addr);
      }

      if ((aggressor_rows_size%2)!=0) {
        dram_analyzer.normalize_addr_to_bank(cur_next_addr + (d*row_increment), ba);
        ss << dram_analyzer.get_row_index(cur_next_addr) << " ";
        aggressors.push_back(cur_next_addr);
      }
      Logger::log_data(ss.str());

      if (!USE_SYNC) {
        Logger::log_info(string_format("Hammering %d aggressors with v=%d d=%d on bank %d",
                                       aggressor_rows_size,
                                       v,
                                       d,
                                       ba));
        hammer(aggressors);
      } else {
        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (100*row_increment), ba);
        auto d1 = cur_next_addr;
        cur_next_addr = dram_analyzer.normalize_addr_to_bank(cur_next_addr + (v*row_increment), ba);
        auto d2 = cur_next_addr;
        Logger::log_info(string_format("d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)",
                                       dram_analyzer.get_row_index(d1),
                                       d1,
                                       dram_analyzer.get_row_index(d2),
                                       d2));
        if (ba==0) {
          Logger::log_info(string_format("sync: ref_rounds %lu, remainder %lu.", acts/aggressors.size(),
                                         acts - ((acts/aggressors.size())*aggressors.size())));
        }
        Logger::log_info(string_format("Hammering sync %d aggressors from addr %p on bank %d",
                                       aggressor_rows_size,
                                       cur_start_addr,
                                       ba));
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
  Logger::log_info("Determined the number of possible ACTs per refresh interval.");
  Logger::log_data(string_format("num_acts_per_tREFI: %lu", activations));

  return activations;
}

/// Prints metadata about this evaluation run.
void print_metadata() {
  Logger::log_info("General information about this fuzzing run:");

  char name[1024] = "";
  gethostname(name, sizeof name);

  std::stringstream ss;
  ss << "Start_ts: " << (unsigned long) time(nullptr) << std::endl
     << "Hostname: " << name << std::endl
     << "Git SHA: " << GIT_COMMIT_HASH << std::endl
     << "RUN_TIME_LIMIT: " << RUN_TIME_LIMIT;

  Logger::log_data(ss.str());

  print_global_defines();
}

char *getCmdOption(char **begin, char **end, const std::string &option) {
  char **itr = std::find(begin, end, option);
  if (itr!=end && ++itr!=end) {
    return *itr;
  }
  return nullptr;
}

bool cmdOptionExists(char **begin, char **end, const std::string &option) {
  return std::find(begin, end, option)!=end;
}

int main(int argc, char **argv) {
  Logger::initialize();

#ifdef DEBUG_SAMSUNG
  Logger::log_debug(
      "\n"
      "=================================================================================================\n"
      "==== ATTENTION // Debugging enabled: DEBUG_SAMSUNG=1 ===========================================\n"
      "=================================================================================================");
#endif

  // process parameter '-generate_patterns'
  const std::string ARG_GENERATE_PATTERN = "-generate_patterns";
  if (cmdOptionExists(argv, argv + argc, ARG_GENERATE_PATTERN)) {
    size_t acts = strtoul(getCmdOption(argv, argv + argc, ARG_GENERATE_PATTERN), nullptr, 10);
    const size_t MAX_NUM_REFRESH_INTERVALS = 32; // this parameter is defined in FuzzingParameterSet
    const size_t MAX_ACCESSES = acts*MAX_NUM_REFRESH_INTERVALS;
    void *rows_to_access = calloc(MAX_ACCESSES, sizeof(int));
    if (rows_to_access==nullptr) {
      Logger::log_error("Allocation of rows_to_access failed!");
      exit(1);
    }
    generate_pattern_for_ARM(acts, static_cast<int *>(rows_to_access), MAX_ACCESSES);
    return 0;
  }

  // process parameter '-runtime_limit'
  const std::string ARG_RUNTIME_LIMIT = "-runtime_limit";
  if (cmdOptionExists(argv, argv + argc, ARG_RUNTIME_LIMIT)) {
    // parse the program arguments
    RUN_TIME_LIMIT = strtol(getCmdOption(argv, argv + argc, ARG_RUNTIME_LIMIT), nullptr, 10);
  } else {
    RUN_TIME_LIMIT = 120; // 2 minutes
  }

  // process parameter '-num_ranks'
  const std::string ARG_NUM_RANKS = "-num_ranks";
  bool param_num_ranks_given = false;
  int num_ranks;
  if (cmdOptionExists(argv, argv + argc, ARG_NUM_RANKS)) {
    // parse the program arguments
    num_ranks = (int) strtol(getCmdOption(argv, argv + argc, ARG_NUM_RANKS), nullptr, 10);
    param_num_ranks_given = true;
  }

  // prints the current git commit and some metadata
  print_metadata();

  // give this process the highest CPU priority
  int ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) {
    Logger::log_error("Instruction setpriority failed.");
  }
  // allocate a large bulk of contiguous memory
  bool use_superpage = true;
  Memory memory(use_superpage);
  memory.allocate_memory(MEM_SIZE);

  DramAnalyzer dram_analyzer(memory.get_starting_address());
  // find address sets that create bank conflicts
  dram_analyzer.find_bank_conflicts();

  if (param_num_ranks_given) {
    dram_analyzer.load_known_functions(num_ranks);
  } else {
    // determine the row and bank/rank functions
    dram_analyzer.find_functions(use_superpage);
  }
  // determine the bank/rank masks
  dram_analyzer.find_bank_rank_masks();

  // process parameter '-acts_per_ref'
  int act;
  const std::string ARG_ACTS_PER_REF = "-acts_per_ref";
  if (cmdOptionExists(argv, argv + argc, ARG_ACTS_PER_REF)) {
    // parse the program arguments
    size_t tmp = strtol(getCmdOption(argv, argv + argc, ARG_ACTS_PER_REF), nullptr, 10);
    if (tmp > ((size_t) INT16_MAX)) {
      Logger::log_error(string_format("Given parameter value %lu for %s is invalid!", tmp, ARG_ACTS_PER_REF.c_str()));
      exit(1);
    }
    act = (int) tmp;
  } else {
    // count the number of possible activations per refresh interval
    act = count_acts_per_ref(dram_analyzer.get_banks());
  }

  // initialize the DRAMAddr class
  DRAMAddr::initialize(dram_analyzer.get_bank_rank_functions().size(), memory.get_starting_address());

  // perform the hammering and check the flipped bits after each round
  if (USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    n_sided_frequency_based_hammering(memory, dram_analyzer, act);
  } else if (!USE_FREQUENCY_BASED_FUZZING) {
    n_sided_hammer(memory, dram_analyzer, act);
  } else {
    Logger::log_error("Invalid combination of program control-flow arguments given. "
                      "Note that fuzzing is only supported with synchronized hammering.");
    return 1;
  }

  Logger::close();

  return 0;
}
