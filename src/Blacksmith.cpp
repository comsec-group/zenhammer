#include "Blacksmith.hpp"

#include <cstdlib>
#include <sys/mman.h>
#include <sys/resource.h>

#include <unordered_set>

#include "Forges/TraditionalHammerer.hpp"
#include "Forges/FuzzyHammerer.hpp"
#include "Forges/ReplayingHammerer.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Utilities/Logger.hpp"

int main(int argc, char **argv) {
  Logger::initialize();

#ifdef DEBUG_SAMSUNG
  Logger::log_debug(
      "\n"
      "=================================================================================================\n"
      "==== ATTENTION // Debugging enabled: DEBUG_SAMSUNG=1 ===========================================\n"
      "=================================================================================================");
#endif

  ProgramArguments args;
  handle_args(args, argc, argv);

  // prints the current git commit and some program metadata
  Logger::log_metadata(GIT_COMMIT_HASH, args.runtime_limit);

  // give this process the highest CPU priority
  int ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) Logger::log_error("Instruction setpriority failed.");

  // allocate a large bulk of contiguous memory
  Memory memory(true);
  memory.allocate_memory(MEM_SIZE);

  // find address sets that create bank conflicts
  DramAnalyzer dram_analyzer(memory.get_starting_address());
  dram_analyzer.find_bank_conflicts();
  if (args.num_ranks!=0) {
    dram_analyzer.load_known_functions(args.num_ranks);
  } else {
    // determine the row and bank/rank functions
    dram_analyzer.find_functions(memory.is_superpage());
  }
  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::initialize(dram_analyzer.get_bank_rank_functions().size(), memory.get_starting_address());
  // determine the bank/rank masks
  dram_analyzer.find_bank_rank_masks();

  // count the number of possible activations per refresh interval, if not given as program argument
  if (args.acts_per_ref==0) args.acts_per_ref = dram_analyzer.count_acts_per_ref();

  if (args.load_json_filename!=nullptr) {
    ReplayingHammerer replayer(memory);
    replayer.replay_patterns(args.load_json_filename, args.pattern_ids);
  } else if (USE_FREQUENCY_BASED_FUZZING && USE_SYNC) {
    FuzzyHammerer::n_sided_frequency_based_hammering(memory, args.acts_per_ref, args.runtime_limit,
        args.probes_per_pattern, args.sweeping);
  } else if (!USE_FREQUENCY_BASED_FUZZING) {
    TraditionalHammerer::n_sided_hammer(memory, args.acts_per_ref, args.runtime_limit);
  } else {
    Logger::log_error("Invalid combination of program control-flow arguments given. "
                      "Note: Fuzzing is only supported with synchronized hammering.");
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

void handle_arg_generate_patterns(char *value, const size_t probes_per_pattern) {
  size_t acts = strtoul(value, nullptr, 10);
  const size_t MAX_NUM_REFRESH_INTERVALS = 32; // this parameter is defined in FuzzingParameterSet
  const size_t MAX_ACCESSES = acts*MAX_NUM_REFRESH_INTERVALS;
  void *rows_to_access = calloc(MAX_ACCESSES, sizeof(int));
  if (rows_to_access==nullptr) {
    Logger::log_error("Allocation of rows_to_access failed!");
    exit(EXIT_FAILURE);
  }
  FuzzyHammerer::generate_pattern_for_ARM(acts, static_cast<int *>(rows_to_access), MAX_ACCESSES, probes_per_pattern);
  exit(EXIT_SUCCESS);
}

void handle_arg_replay_patterns(char *pattern_ids, const char *json_filename, std::unordered_set<std::string> &ids) {
  if (json_filename==nullptr) {
    Logger::log_error("Argument -replay_patterns requires loading a JSON file using -load_json <filename>.");
    exit(EXIT_FAILURE);
  }

  // extract all HammeringPattern IDs from the given comma-separated json_filename
  std::stringstream ids_str(pattern_ids);
  while (ids_str.good()) {
    std::string substr;
    getline(ids_str, substr, ',');
    ids.insert(substr);
  }
}

void handle_args(ProgramArguments &args, int argc, char **argv) {
  const std::string ARG_GENERATE_PATTERN = "-generate_patterns";
  if (cmd_parameter_exists(argv, argv + argc, ARG_GENERATE_PATTERN)) {
    handle_arg_generate_patterns(get_cmd_parameter(argv, argv + argc, ARG_GENERATE_PATTERN), args.probes_per_pattern);
  }

  const std::string ARG_RUNTIME_LIMIT = "-runtime_limit";
  if (cmd_parameter_exists(argv, argv + argc, ARG_RUNTIME_LIMIT)) {
    args.runtime_limit = strtol(get_cmd_parameter(argv, argv + argc, ARG_RUNTIME_LIMIT), nullptr, 10);
  }

  const std::string ARG_NUM_RANKS = "-num_ranks";
  if (cmd_parameter_exists(argv, argv + argc, ARG_NUM_RANKS)) {
    args.num_ranks = (int) strtol(get_cmd_parameter(argv, argv + argc, ARG_NUM_RANKS), nullptr, 10);
  }

  const std::string ARG_ACTS_PER_REF = "-acts_per_ref";
  if (cmd_parameter_exists(argv, argv + argc, ARG_ACTS_PER_REF)) {
    // parse the program arguments
    args.acts_per_ref = (int) strtol(get_cmd_parameter(argv, argv + argc, ARG_ACTS_PER_REF), nullptr, 10);
  }

  const std::string ARG_LOAD_PATTERN = "-load_json";
  if (cmd_parameter_exists(argv, argv + argc, ARG_LOAD_PATTERN)) {
    args.load_json_filename = get_cmd_parameter(argv, argv + argc, ARG_LOAD_PATTERN);
  }

  const std::string ARG_PATTERN_IDs = "-replay_patterns";
  if (cmd_parameter_exists(argv, argv + argc, ARG_PATTERN_IDs)) {
    handle_arg_replay_patterns(get_cmd_parameter(argv, argv + argc, ARG_PATTERN_IDs),
        args.load_json_filename,
        args.pattern_ids);
  }

  const std::string ARG_NUM_PROBES = "-probes";
  if (cmd_parameter_exists(argv, argv + argc, ARG_NUM_PROBES)) {
    args.probes_per_pattern = (int) strtol(get_cmd_parameter(argv, argv + argc, ARG_NUM_PROBES), nullptr, 10);
  }

  const std::string ARG_SWEEPING = "-sweeping";
  if (cmd_parameter_exists(argv, argv + argc, ARG_SWEEPING)) {
    args.sweeping = true;
  }
}


