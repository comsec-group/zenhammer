#ifndef BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"

class ReplayingHammerer {
 private:
  static std::vector<HammeringPattern> get_matching_patterns_from_json(const char *json_filename,
                                                                       const char *pattern_ids);

 public:
  static size_t hammer_pattern(Memory &memory,
                               FuzzingParameterSet &fuzz_params,
                               CodeJitter &code_jitter,
                               HammeringPattern &pattern,
                               PatternAddressMapper &mapper,
                               FLUSHING_STRATEGY flushing_strategy,
                               FENCING_STRATEGY fencing_strategy,
                               unsigned long num_reps,
                               bool sync_each_ref,
                               int aggressors_for_sync,
                               int num_activations,
                               bool verbose_sync,
                               bool verbose_memcheck,
                               bool verbose_params);

  static void replay_patterns(Memory &mem, const char *json_filename, const char *pattern_ids, int acts_per_tref);
};

#endif //BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_
