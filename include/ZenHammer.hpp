#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>
#include <unordered_set>
#include <GlobalDefines.hpp>
#include "Utilities/Enums.hpp"

// defines the program's arguments and their default values
struct ProgramArguments {
  // the duration of the fuzzing run in second
  unsigned long runtime_limit = 120;
  // the micro architecture / platform identification string
  std::string uarch_str;
  // the number of ranks of the DIMM
  int num_ranks = 0;
  // the number of bank groups of the DIMM
  int num_bank_groups = 0;
  // the number of banks per bank group of the DIMM
  int num_banks = 0;
  // use Samsung logical-to-physical row mapping
  bool samsung_row_mapping = false;
  // no. of activations we can do within a refresh interval
  size_t acts_per_trefi = 0;
  // path to JSON file to load
  std::string load_json_filename;
  // the IDs of the patterns to be loaded from a given JSON file
  std::unordered_set<std::string> pattern_ids{};
  // total number of mappings (i.e., Aggressor ID -> DRAM rows mapping) to try for a pattern
  size_t num_address_mappings_per_pattern = 3;
  // number of DRAM locations we use to check a (pattern, address mapping)'s effectiveness
  size_t num_dram_locations_per_mapping = 3;
  // whether to sweep the 'best pattern' that was found during fuzzing afterward over a contiguous chunk of memory
  bool sweeping = false;
  // the ID of the DIMM that is currently inserted
  long dimm_id = -1;
  // these two parameters define the default program mode: do fuzzing and synchronize with REFRESH
  bool do_fuzzing = true;
  bool use_synchronization = true;
  bool fixed_acts_per_ref = false;

  // FENCING EXPERIMENT PARAMS
  SCHEDULING_POLICY scheduling_policy { SCHEDULING_POLICY::DEFAULT };
  FENCE_TYPE fence_type { FENCE_TYPE::NO_FENCE };
};

extern ProgramArguments program_args;

int main(int argc, char **argv);

void handle_args(int argc, char **argv);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
