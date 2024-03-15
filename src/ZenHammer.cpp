#include "ZenHammer.hpp"

#include <sys/resource.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>

#include "Forges/FuzzyHammerer.hpp"
#include "Memory/DRAMConfig.hpp"

#include <argagg/argagg.hpp>
#include <argagg/convert/csv.hpp>

ProgramArguments program_args;

int main(int argc, char **argv) {
  Logger::initialize();

  handle_args(argc, argv);

  // prints the current git commit and some program metadata
  Logger::log_metadata(GIT_COMMIT_HASH, program_args.runtime_limit);

  // give this process the highest CPU priority so it can hammer with less interruptions
  int ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret!=0) Logger::log_error("Instruction setpriority failed.");

  DRAMConfig::select_config(
    program_args.uarch_str,
    program_args.num_ranks,
    program_args.num_bank_groups,
    program_args.num_banks,
    program_args.samsung_row_mapping);

  // Allocate two blocks of memory:
  // One for hammering, and one for refresh synchronization.
  auto allocation_size = DRAMConfig::get().memory_size();
  Logger::log_info(format_string("Allocating 2x%zu MB of memory...", allocation_size / MB(1)));
  Memory hammering_memory(true);
  hammering_memory.allocate_memory(DRAMConfig::get().memory_size());
  Memory ref_sync_memory(true);
  ref_sync_memory.allocate_memory(DRAMConfig::get().memory_size());

  // initialize the DRAMAddr class to load the proper memory configuration
  DRAMAddr::initialize_mapping(0, hammering_memory.get_starting_address());
  DRAMAddr::initialize_mapping(1, ref_sync_memory.get_starting_address());

  // find address sets that create bank conflicts
  DramAnalyzer dram_analyzer(hammering_memory.get_starting_address());
  dram_analyzer.find_threshold();
  dram_analyzer.find_bank_conflicts();
  DRAMConfig::get().set_sync_ref_threshold(dram_analyzer.find_sync_ref_threshold());
  dram_analyzer.check_sync_ref_threshold(DRAMConfig::get().get_sync_ref_threshold());

  // Initialize bank translation data required to REF sync in the other mapping.
  auto bank_translation = dram_analyzer.get_corresponding_banks_for_mapping(1, ref_sync_memory.get_starting_address());
  DRAMAddr::initialize_bank_translation(0, 1, std::move(bank_translation));

  if (!program_args.load_json_filename.empty()) {
    ReplayingHammerer replayer(hammering_memory);
    if (program_args.sweeping) {
      replayer.replay_patterns_brief(program_args.load_json_filename, program_args.pattern_ids,
          MINISWEEP_ROWS, true);
    } else {
      replayer.replay_patterns(program_args.load_json_filename, program_args.pattern_ids);
    }
  } else if (program_args.do_fuzzing && program_args.use_synchronization) {
    FuzzyHammerer::n_sided_frequency_based_hammering(dram_analyzer, hammering_memory, static_cast<int>(program_args.acts_per_trefi), program_args.runtime_limit,
        program_args.num_address_mappings_per_pattern, program_args.sweeping);
  } else {
    Logger::log_error("Invalid combination of program control-flow arguments given. "
                      "Note: Fuzzing is only supported with synchronized hammering.");
  }

  Logger::close();
  return EXIT_SUCCESS;
}

struct dram_geometry {
  int num_ranks;
  int num_bank_groups;
  int num_banks;
};

namespace argagg::convert {
template <>
dram_geometry arg(const char* s)
{
  dram_geometry result {-1, -1, -1 };
  if (!parse_next_component(s, result.num_ranks, ',')) {
    return result;
  }
  if (!parse_next_component(s, result.num_bank_groups, ',')) {
    return result;
  }
  if (!parse_next_component(s, result.num_banks, ',')) {
    return result;
  }
  return result;
}
} // namespace argagg::convert

void handle_args(int argc, char **argv) {
  // An option is specified by four things:
  //    (1) the name of the option,
  //    (2) the strings that activate the option (flags),
  //    (3) the option's help message,
  //    (4) and the number of arguments the option expects.
  argagg::parser argparser{{
      {"help", {"-h", "--help"}, "shows this help message", 0},
      {"dimm-id", {"-d", "--dimm-id"}, "internal identifier of the currently inserted DIMM (default: 0)", 1},

      {"uarch", {"--uarch"}, "micro architecture/platform identificaton string (e.g., 'coffeelake' or 'zen3')", 1},
      { "geometry", {"--geometry"}, "a triple describing the DRAM geometry: #ranks, #bankgroups, #banks (e.g. '--geometry 2,4,4')", 1},
      { "samsung", {"--samsung"}, "use Samsung style logical-to-physical row address mapping (default: no remapping)", 0},

      {"fuzzing", {"-f", "--fuzzing"}, "perform a fuzzing run (default program mode)", 0},
      {"replay-patterns", {"-y", "--replay-patterns"}, "replays patterns given as comma-separated list of pattern IDs", 1},

      {"load-json", {"-j", "--load-json"}, "loads the specified JSON file generated in a previous fuzzer run, loads patterns given by --replay-patterns or determines the best ones", 1},

      // note that these two parameters don't require a value, their presence already equals a "true"
      {"sync", {"-s", "--sync"}, "synchronize with REFRESH while hammering (default: present)", 0},
      {"sweeping", {"-w", "--sweeping"}, "sweep the best pattern over a contig. memory area after fuzzing (default: absent)", 0},

      {"runtime-limit", {"-t", "--runtime-limit"}, "number of seconds to run the fuzzer before sweeping/terminating (default: 120)", 1},
      {"acts-per-ref", {"-a", "--acts-per-ref"}, "number of activations in a tREF interval, i.e., 7.8us (default: random for each pattern)", 1},
      {"probes", {"-p", "--probes"}, "number of different DRAM locations to try each pattern on (default: NUM_BANKS/4)", 1},

      {"sched-policy", {"--sched-policy"}, "type of scheduling policy to use (one of 'default', 'none', 'full', 'bp', 'half_bp', 'pair', 'rep'; default: 'default')", 1 },
      {"fence-type", {"--fence-type"}, "type of fence to use (one of 'none', 'mfence', 'lfence', 'sfence')", 1 },
    }};

  argagg::parser_results parsed_args;
  try {
    parsed_args = argparser.parse(argc, argv);
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    exit(EXIT_FAILURE);
  }

  if (parsed_args["help"]) {
    std::cerr << argparser;
    exit(EXIT_SUCCESS);
  }

  /**
   * mandatory parameters
   */
  if (parsed_args.has_option("dimm-id")) {
    program_args.dimm_id = parsed_args["dimm-id"].as<int>(0);
    Logger::log_debug(format_string("Set --dimm-id: %ld", program_args.dimm_id));
  } else {
    Logger::log_error("Program argument '--dimm-id <integer>' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }

  if (parsed_args.has_option("uarch")) {
    program_args.uarch_str = parsed_args["uarch"].as<std::string>("");
  } else {
    Logger::log_error("Program argument '--uarch <string>' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }
  if (parsed_args.has_option("geometry")) {
    auto geometry = parsed_args["geometry"].as<dram_geometry>();
    program_args.num_ranks = geometry.num_ranks;
    program_args.num_bank_groups = geometry.num_bank_groups;
    program_args.num_banks = geometry.num_banks;
  } else {
    Logger::log_error("Program argument '--geometry <#ranks:integer>,<#bankgroups:integer>,<#banks:integer>' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }
  program_args.samsung_row_mapping = parsed_args.has_option("samsung") || program_args.samsung_row_mapping;
  Logger::log_debug(format_string("Set --samsung=%s", program_args.samsung_row_mapping ? "true" : "false"));

  /**
  * optional parameters
  */
  program_args.sweeping = parsed_args.has_option("sweeping") || program_args.sweeping;
  Logger::log_debug(format_string("Set --sweeping=%s", (program_args.sweeping ? "true" : "false")));

  program_args.runtime_limit = parsed_args["runtime-limit"].as<unsigned long>(program_args.runtime_limit);
  Logger::log_debug(format_string("Set --runtime_limit=%ld", program_args.runtime_limit));

  program_args.acts_per_trefi = parsed_args["acts-per-ref"].as<size_t>(program_args.acts_per_trefi);
  Logger::log_info(format_string("+++ %d", program_args.acts_per_trefi));
  program_args.fixed_acts_per_ref = (program_args.acts_per_trefi != 0);
  Logger::log_debug(format_string("Set --acts-per-ref=%d", program_args.acts_per_trefi));

  program_args.num_address_mappings_per_pattern = parsed_args["probes"].as<size_t>(program_args.num_address_mappings_per_pattern);
  Logger::log_debug(format_string("Set --probes=%d", program_args.num_address_mappings_per_pattern));

  if (parsed_args.has_option("sched-policy")) {
    auto policy_str = parsed_args["sched-policy"].as<std::string>("");
    if (policy_str == "default") {
      program_args.scheduling_policy = SCHEDULING_POLICY::DEFAULT;
    } else if (policy_str == "none") {
      program_args.scheduling_policy = SCHEDULING_POLICY::NONE;
    } else if (policy_str == "full") {
      program_args.scheduling_policy = SCHEDULING_POLICY::FULL;
    } else if (policy_str == "bp") {
      program_args.scheduling_policy = SCHEDULING_POLICY::BASE_PERIOD;
    } else if (policy_str == "half_bp") {
      program_args.scheduling_policy = SCHEDULING_POLICY::HALF_BASE_PERIOD;
    } else if (policy_str == "pair") {
      program_args.scheduling_policy = SCHEDULING_POLICY::PAIR;
    } else if (policy_str == "rep") {
      program_args.scheduling_policy = SCHEDULING_POLICY::REPETITON;
    } else {
      Logger::log_error("Program argument '--sched-policy' must be one of 'default', 'none', 'full', 'bp', 'half_bp', 'pair', 'rep'. Cannot continue.");
      exit(EXIT_FAILURE);
    }
    Logger::log_info(format_string("Using scheduling policy SCHEDULING_POLICY::%s", to_string(program_args.scheduling_policy).c_str()));
  } else {
    program_args.scheduling_policy = SCHEDULING_POLICY::DEFAULT;
    Logger::log_info("No scheduling policy specified. Using default policy for microarchitecture (SCHEDULING_POLICY::DEFAULT).");
  }

  if (parsed_args.has_option("fence-type")) {
    auto type_str= parsed_args["fence-type"].as<std::string>("");
    if (type_str == "none") {
      program_args.fence_type = FENCE_TYPE::NO_FENCE;
    } else if (type_str == "mfence") {
      program_args.fence_type = FENCE_TYPE::MFENCE;
    } else if (type_str == "lfence") {
      program_args.fence_type = FENCE_TYPE::LFENCE;
    } else if (type_str == "sfence") {
      program_args.fence_type = FENCE_TYPE::SFENCE;
    } else {
      Logger::log_error("Program argument '--fence-type' must be one of 'none', 'mfence', 'lfence', 'sfence'. Cannot continue.");
      exit(EXIT_FAILURE);
    }
  } else {
    Logger::log_error("Program argument '--fence-type [none|mfence|lfence|sfence]' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }
  Logger::log_info(format_string("Set --fence-type=%s", to_string(program_args.fence_type).c_str()));

  /**
   * program modes
   */
  if (parsed_args.has_option("load-json")) {
    program_args.load_json_filename = parsed_args["load-json"].as<std::string>("");
    if (parsed_args.has_option("replay-patterns")) {
      auto vec_pattern_ids = parsed_args["replay-patterns"].as<argagg::csv<std::string>>();
      program_args.pattern_ids = std::unordered_set<std::string>(
          vec_pattern_ids.values.begin(),
          vec_pattern_ids.values.end());
    } else {
      program_args.pattern_ids = std::unordered_set<std::string>();
    }
  } else {
    program_args.do_fuzzing = parsed_args["fuzzing"].as<bool>(true);
    // FIXME: This means synching is always enabled.
    //        It seems that non-synchronized hammering is only supported for TraditionalHammerer.
    const bool default_sync = true;
    program_args.use_synchronization = parsed_args.has_option("sync") || default_sync;
  }
}
