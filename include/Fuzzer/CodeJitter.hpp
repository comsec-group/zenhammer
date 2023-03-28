#ifndef CODEJITTER
#define CODEJITTER

#include <unordered_map>
#include <vector>

#include "Utilities/Enums.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"

#ifdef ENABLE_JITTING
#include <asmjit/asmjit.h>
#endif

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

struct synchronization_stats {
  // how often we accessed sync dummies
  size_t num_sync_acts;
  // how often we started the synchronization procedure
  size_t num_sync_rounds;
};

class CodeJitter {
 private:
#ifdef ENABLE_JITTING
  /// runtime for JIT code execution, can be reused by cleaning the function ptr (see cleanup method)
  asmjit::JitRuntime runtime;

  /// a logger that keeps track of the generated ASM instructions - useful for debugging
  asmjit::StringLogger *logger = nullptr;
#endif

  const uint64_t REFRESH_THRESHOLD_CYCLES_LOW  = 500;
  const uint64_t REFRESH_THRESHOLD_CYCLES_HIGH = 900;

  /// a function pointer to a function that takes no input (void) and returns an integer
  int (*fn)() = nullptr;

 public:

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  int total_activations;

  size_t sync_rows_idx = 0;

  size_t sync_rows_size;

  /// constructor
  CodeJitter();
  
  /// destructor
  ~CodeJitter();

  /// generates the jitted function and assigns the function pointer fn to it
  void jit_strict(FLUSHING_STRATEGY flushing,
                  FENCING_STRATEGY fencing,
                  int total_num_activations,
                  const std::vector<volatile char *> &aggressor_pairs,
                  const std::vector<volatile char *> &sync_rows);

  /// does the hammering if the function was previously created successfully, otherwise does nothing
  size_t hammer_pattern(FuzzingParameterSet &fuzzing_parameters, bool verbose);

  /// cleans this instance associated function pointer that points to the function that was jitted at runtime;
  /// cleaning up is required to release memory before jit_strict can be called again
  void cleanup();

  size_t get_next_sync_rows_idx();

#ifdef ENABLE_JITTING
  void sync_ref(const std::vector<volatile char *> &sync_rows,
                asmjit::x86::Assembler &assembler,
                size_t num_timed_accesses);
#endif
  void hammer_pattern_unjitted(FuzzingParameterSet &fuzzing_parameters,
                               bool verbose,
                               FLUSHING_STRATEGY flushing,
                               FENCING_STRATEGY fencing,
                               int total_num_activations,
                               const std::vector<volatile char *> &aggressor_pairs,
                               const std::vector<volatile char *> &sync_rows,
                               size_t ref_threshold);

  void sync_ref_unjitted(const std::vector<volatile char *> &sync_rows,
                         synchronization_stats &sync_stats,
                         size_t ref_threshold, size_t sync_rounds_max) const;

  [[maybe_unused]] static void wait_for_user_input();
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const CodeJitter &p);

void from_json(const nlohmann::json &j, CodeJitter &p);

#endif

#endif /* CODEJITTER */
