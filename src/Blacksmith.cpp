#include "Blacksmith.hpp"

#include <cstdlib>
#include <sys/mman.h>
#include <sys/resource.h>

#include "Forges/TraditionalHammerer.hpp"
#include "Forges/FuzzyHammerer.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Utilities/Logger.hpp"

int main(int argc, char **argv) {
  // CONFIGURATION
  // total number of (different) locations (i.e., Aggressor ID -> DRAM rows mapping) where we try a pattern
  const size_t PROBES_PER_PATTERN = NUM_BANKS/4;

  Logger::initialize();

#ifdef DEBUG_SAMSUNG
  Logger::log_debug(
      "\n"
      "=================================================================================================\n"
      "==== ATTENTION // Debugging enabled: DEBUG_SAMSUNG=1 ===========================================\n"
      "=================================================================================================");
#endif

  // process parameter '-generate_patterns' (for ARM)
  const std::string ARG_GENERATE_PATTERN = "-generate_patterns";
  if (cmd_parameter_exists(argv, argv + argc, ARG_GENERATE_PATTERN)) {
    size_t acts = strtoul(get_cmd_parameter(argv, argv + argc, ARG_GENERATE_PATTERN), nullptr, 10);
    const size_t MAX_NUM_REFRESH_INTERVALS = 32; // this parameter is defined in FuzzingParameterSet
    const size_t MAX_ACCESSES = acts*MAX_NUM_REFRESH_INTERVALS;
    void *rows_to_access = calloc(MAX_ACCESSES, sizeof(int));
    if (rows_to_access==nullptr) {
      Logger::log_error("Allocation of rows_to_access failed!");
      return EXIT_FAILURE;
    }
    FuzzyHammerer::generate_pattern_for_ARM(acts, static_cast<int *>(rows_to_access), MAX_ACCESSES, PROBES_PER_PATTERN);
    return EXIT_SUCCESS;
  }

  // process parameter '-runtime_limit'
  const std::string ARG_RUNTIME_LIMIT = "-runtime_limit";
  long run_time_limit = 120; // = 2 minutes (default value)
  if (cmd_parameter_exists(argv, argv + argc, ARG_RUNTIME_LIMIT)) {
    // parse the program arguments
    run_time_limit = strtol(get_cmd_parameter(argv, argv + argc, ARG_RUNTIME_LIMIT), nullptr, 10);
  }

  // prints the current git commit and some metadata
  Logger::log_metadata(GIT_COMMIT_HASH, run_time_limit);

  // give this process the highest CPU priority
  int ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) Logger::log_error("Instruction setpriority failed.");

  // allocate a large bulk of contiguous memory
  Memory memory(true);
  memory.allocate_memory(MEM_SIZE);

  // find address sets that create bank conflicts
  DramAnalyzer dram_analyzer(memory.get_starting_address());
  dram_analyzer.find_bank_conflicts();

  // process parameter '-num_ranks'
  const std::string ARG_NUM_RANKS = "-num_ranks";
  int num_ranks;
  if (cmd_parameter_exists(argv, argv + argc, ARG_NUM_RANKS)) {
    // parse the program arguments
    num_ranks = (int) strtol(get_cmd_parameter(argv, argv + argc, ARG_NUM_RANKS), nullptr, 10);
    dram_analyzer.load_known_functions(num_ranks);
  } else {
    // determine the row and bank/rank functions
    dram_analyzer.find_functions(memory.is_superpage());
  }
  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::initialize(dram_analyzer.get_bank_rank_functions().size(), memory.get_starting_address());
  // determine the bank/rank masks
  dram_analyzer.find_bank_rank_masks();

  // process parameter '-acts_per_ref'
  int act;
  const std::string ARG_ACTS_PER_REF = "-acts_per_ref";
  if (cmd_parameter_exists(argv, argv + argc, ARG_ACTS_PER_REF)) {
    // parse the program arguments
    size_t tmp = strtol(get_cmd_parameter(argv, argv + argc, ARG_ACTS_PER_REF), nullptr, 10);
    if (tmp > ((size_t) std::numeric_limits<int>::max())) {
      Logger::log_error(format_string("Given parameter value %lu for %s is invalid!", tmp, ARG_ACTS_PER_REF.c_str()));
      exit(1);
    }
    act = (int) tmp;
  } else {
    // count the number of possible activations per refresh interval
    act = dram_analyzer.count_acts_per_ref();
  }

  // process parameters '-load_json' and '-replay_patterns'
  const std::string ARG_LOAD_PATTERN = "-load_json";
  if (cmd_parameter_exists(argv, argv + argc, ARG_LOAD_PATTERN)) {
    const std::string ARG_PATTERN_IDs = "-replay_patterns";
    if (!cmd_parameter_exists(argv, argv + argc, ARG_PATTERN_IDs)) {
      Logger::log_error(format_string("Parameter %s expects parameter %s.\n"
                                      "Ex.: blacksmith [-load_json filename] [-replay_patterns PatternUUID ...]",
          ARG_LOAD_PATTERN.c_str(),
          ARG_PATTERN_IDs.c_str()));
      Logger::close();
      return EXIT_FAILURE;
    }
    char *filename = get_cmd_parameter(argv, argv + argc, ARG_LOAD_PATTERN);
    char *pattern_ids = get_cmd_parameter(argv, argv + argc, ARG_PATTERN_IDs);
    FuzzyHammerer::replay_patterns(memory, filename, pattern_ids, act);
  } else if (USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    FuzzyHammerer::n_sided_frequency_based_hammering(memory, act, run_time_limit, PROBES_PER_PATTERN);
  } else if (!USE_FREQUENCY_BASED_FUZZING) {
    TraditionalHammerer::n_sided_hammer(memory, act, run_time_limit);
  } else {
    Logger::log_error("Invalid combination of program control-flow arguments given. "
                      "Note that fuzzing is only supported with synchronized hammering.");
  }

  Logger::close();
  return EXIT_SUCCESS;
}

char *get_cmd_parameter(char **begin, char **end, const std::string &parameter_name) {
  char **itr = std::find(begin, end, parameter_name);
  return (itr!=end && ++itr!=end) ? *itr : nullptr;
}

bool cmd_parameter_exists(char **begin, char **end, const std::string &parameter_name) {
  return std::find(begin, end, parameter_name)!=end;
}

