#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>
#include <unordered_set>

// defines the program's arguments and their default values
struct ProgramArguments {
  // the duration of the fuzzing run in second
  long runtime_limit = 120;
  // the number of ranks of the DIMM to hammer
  int num_ranks = 0;
  // no. of activations we can do within a refresh interval
  int acts_per_ref = 0;
  // path to JSON file to load
  char *load_json_filename = nullptr;
  // the IDs of the patterns to be loaded from a given JSON file
  std::unordered_set<std::string> pattern_ids{};
  // total number of (different) locations (i.e., Aggressor ID -> DRAM rows mapping) where we try a pattern
  size_t probes_per_pattern = 3;
  // whether to sweep the 'best pattern' that was found during fuzzing afterward over a contiguous chunk of memory
  bool sweeping = false;
  // the ID of the DIMM that is currently inserted
  long dimm_id = -1;
};

extern ProgramArguments program_args;

int main(int argc, char **argv);

char *get_cmd_parameter(char **begin, char **end, const std::string &parameter_name);

bool cmd_parameter_exists(char **begin, char **end, const std::string &parameter_name);

void handle_args(ProgramArguments &args, int argc, char **argv);

void handle_arg_generate_patterns(char *value, size_t probes_per_pattern);

void handle_arg_replay_patterns(char *pattern_ids, const char *json_filename, std::unordered_set<std::string> &ids);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
