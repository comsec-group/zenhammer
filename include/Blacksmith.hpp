#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>
#include <unordered_set>
#include <GlobalDefines.hpp>

// defines the program's arguments and their default values
struct ProgramArguments {
  // the duration of the fuzzing run in second
  unsigned long runtime_limit = 120;
  // the number of ranks of the DIMM to hammer
  int num_ranks = 0;
  // no. of activations we can do within a refresh interval
  size_t acts_per_ref = 0;
  // path to JSON file to load
  std::string load_json_filename;
  // the IDs of the patterns to be loaded from a given JSON file
  std::unordered_set<std::string> pattern_ids{};
  // total number of (different) locations (i.e., Aggressor ID -> DRAM rows mapping) where we try a pattern
  size_t probes_per_pattern = NUM_BANKS/4;
  // whether to sweep the 'best pattern' that was found during fuzzing afterward over a contiguous chunk of memory
  bool sweeping = false;
  // the ID of the DIMM that is currently inserted
  long dimm_id = -1;
  // these two parameters define the default program mode: do fuzzing and synchronize with REFRESH
  bool do_fuzzing = true;
  bool use_synchronization = true;
};

extern ProgramArguments program_args;

int main(int argc, char **argv);

void handle_args(int argc, char **argv);

[[ noreturn ]] void handle_arg_generate_patterns(int num_activations, size_t probes_per_pattern);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
