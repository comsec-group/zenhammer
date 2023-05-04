#include "Blacksmith.hpp"

#include <sys/resource.h>

#include "Forges/TraditionalHammerer.hpp"
#include "Forges/FuzzyHammerer.hpp"
#include "Memory/DRAMAddr.hpp"
#include "sys/stat.h"
#include "Utilities/ExperimentConfig.hpp"

#include <argagg/argagg.hpp>
#include <argagg/convert/csv.hpp>

ProgramArguments program_args;

int main(int argc, char **argv) {
  Logger::initialize();

#ifdef DEBUG_SAMSUNG
  Logger::log_debug(
      "\n"
      "=================================================================================================\n"
      "==== ATTENTION // Debugging enabled: DEBUG_SAMSUNG=1 ===========================================\n"
      "=================================================================================================");
#endif

  handle_args(argc, argv);

  // prints the current git commit and some program metadata
  Logger::log_metadata(GIT_COMMIT_HASH, program_args.runtime_limit);

  // give this process the highest CPU priority so it can hammer with less interruptions
  int ret = setpriority(PRIO_PROCESS, 0, -20);
  if (ret != 0) {
    Logger::log_error("Instruction setpriority failed.");
  }

  // allocate a large bulk of contiguous memory
  Memory memory(true);
  memory.allocate_memory(HUGEPAGE_SZ);

  DRAMAddr::initialize((volatile char*)memory.get_starting_address(),
    program_args.num_ranks,
    program_args.num_bankgroups,
    program_args.num_banks);

  // find address sets that create bank conflicts
  DramAnalyzer dram_analyzer(memory.get_starting_address());

  if (program_args.do_fuzzing && program_args.use_synchronization) {
    FuzzyHammerer fuzzyHammerer;
    fuzzyHammerer.n_sided_frequency_based_hammering(
        dram_analyzer,
        memory,
        static_cast<int>(program_args.acts_per_ref),
        program_args.runtime_limit,
        program_args.num_address_mappings_per_pattern,
        program_args.sweeping);
  }

  Logger::close();
  return EXIT_SUCCESS;
}

struct dram_geometry {
  double num_ranks;
  double num_bankgroups;
  double num_banks;
};

namespace argagg {
namespace convert {
  template <>
  dram_geometry arg(const char* s)
  {
    dram_geometry result {0.0, 0.0, 0.0};
    if (!parse_next_component(s, result.num_ranks, ',')) {
      return result;
    }
    if (!parse_next_component(s, result.num_bankgroups, ',')) {
      return result;
    }
    if (!parse_next_component(s, result.num_banks, ',')) {
      return result;
    }
    return result;
  }
} // namespace convert
} // namespace argagg

void handle_args(int argc, char **argv) {
  // An option is specified by four things:
  //    (1) the name of the option,
  //    (2) the strings that activate the option (flags),
  //    (3) the option's help message,
  //    (4) and the number of arguments the option expects.
  argagg::parser argparser{{
      {"help", {"-h", "--help"}, "shows this help message", 0},
      {"dimm-id", {"-d", "--dimm-id"}, "internal identifier of the currently inserted DIMM (default: 0)", 1},

      {"fuzzing", {"-f", "--fuzzing"}, "perform a fuzzing run (default program mode)", 0},
      {"replay-patterns", {"-y", "--replay-patterns"}, "replays patterns given as comma-separated list of pattern IDs", 1},

      {"load-json", {"-j", "--load-json"}, "loads the specified JSON file generated in a previous fuzzer run, loads patterns given by --replay-patterns or determines the best ones", 1},

      // note that these two parameters don't require a value, their presence already equals a "true"
      {"sync", {"-s", "--sync"}, "synchronize with REFRESH while hammering (default: present)", 0},
      {"sweeping", {"-w", "--sweeping"}, "sweep the best pattern over a contig. memory area after fuzzing (default: absent)", 0},

      {"runtime-limit", {"-t", "--runtime-limit"}, "number of seconds to run the fuzzer before sweeping/terminating (default: 120)", 1},
      {"acts-per-ref", {"-a", "--acts-per-ref"}, "number of activations in a tREF interval, i.e., 7.8us (default: random for each pattern)", 1},
      {"probes", {"-p", "--probes"}, "number of different DRAM locations to try each pattern on (default: NUM_BANKS/4)", 1},

      {"yaml-exp-cfg", {"-e", "--exp-cfg"}, "", 1},
      {"yaml-exp-cfg-id", {"-x", "--exp-cfg-id"}, "", 1},

      { "geometry", {"--geometry"},
        "a triple describing the DRAM geometry: #ranks, #bankgroups, #banks (e.g. '--geometry 2,8,4')", 1},
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

  if (parsed_args.has_option("geometry")) {
    auto geom = parsed_args["geometry"].as<dram_geometry>();
    program_args.num_ranks = geom.num_ranks;
    program_args.num_bankgroups = geom.num_bankgroups;
    program_args.num_banks = geom.num_banks;
  } else {
    Logger::log_error("Program argument '--geometry <#ranks:integer>,<#bankgroups:integer>,<#banks:integer>' is mandatory! Cannot continue.");
    exit(EXIT_FAILURE);
  }
  if (parsed_args.has_option("yaml-exp-cfg") || parsed_args.has_option("yaml-exp-cfg-id")) {
    if (!parsed_args.has_option("yaml-exp-cfg") || !parsed_args.has_option("yaml-exp-cfg-id")) {
      Logger::log_error("Program argument '--exp-cfg <filename_yaml>' requires '--exp-cfg-id <int>' and vice versa.");
      exit(EXIT_FAILURE);
    }
    program_args.filepath_exp_cfg = parsed_args["yaml-exp-cfg"].as<std::string>();
    program_args.exp_cfg_id = parsed_args["yaml-exp-cfg-id"].as<int>();
  }

  /**
  * optional parameters
  */
  program_args.sweeping = parsed_args.has_option("sweeping") || program_args.sweeping;
  Logger::log_debug(format_string("Set --sweeping=%s", (program_args.sweeping ? "true" : "false")));

  program_args.runtime_limit = parsed_args["runtime-limit"].as<unsigned long>(program_args.runtime_limit);
  Logger::log_debug(format_string("Set --runtime_limit=%ld", program_args.runtime_limit));

  program_args.acts_per_ref = parsed_args["acts-per-ref"].as<size_t>(program_args.acts_per_ref);
  Logger::log_debug(format_string("Set --acts-per-ref=%d", program_args.acts_per_ref));

  program_args.num_address_mappings_per_pattern = parsed_args["probes"].as<size_t>(program_args.num_address_mappings_per_pattern);
  Logger::log_debug(format_string("Set --probes=%d", program_args.num_address_mappings_per_pattern));

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
    const bool default_sync = true;
    program_args.use_synchronization = parsed_args.has_option("sync") || default_sync;
  }
}
