#ifndef BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_
#define BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_

#include "Fuzzer/HammeringPattern.hpp"
#include "Memory/Memory.hpp"

#include <unordered_set>

class ReplayingHammerer {
 private:

  static std::vector<HammeringPattern> load_patterns_from_json(const char *json_filename,
                                                        const std::unordered_set<std::string> &pattern_ids);

 public:

  static double last_reproducibility_score;

  static size_t hammer_pattern(Memory &memory,
                               FuzzingParameterSet &fuzz_params,
                               CodeJitter &code_jitter,
                               HammeringPattern &pattern,
                               PatternAddressMapper &mapper,
                               FLUSHING_STRATEGY flushing_strategy,
                               FENCING_STRATEGY fencing_strategy,
                               unsigned long num_reps,
                               int aggressors_for_sync,
                               int num_activations,
                               bool early_stopping,
                               bool sync_each_ref,
                               bool verbose_sync,
                               bool verbose_memcheck,
                               bool verbose_params,
                               bool wait_before_hammering,
                               bool check_flips_after_each_rep);

  static void replay_patterns(Memory &mem, const char *json_filename,
                              const std::unordered_set<std::string> &pattern_ids);

  static void sweep_pattern(Memory &mem, HammeringPattern &pattern, PatternAddressMapper &mapper, size_t num_reps);
};

#endif //BLACKSMITH_SRC_FORGES_REPLAYINGHAMMERER_HPP_
