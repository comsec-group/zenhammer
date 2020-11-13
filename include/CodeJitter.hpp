#ifndef CODEJITTER
#define CODEJITTER

#include <asmjit/asmjit.h>

#include <unordered_map>
#include <vector>

enum class FLUSHING_STRATEGY {
  // flush an accessed aggressor as soon as it has been accessed (i.e., pairs are flushed in-between)
  EARLIEST_POSSIBLE
};

std::string get_string(FLUSHING_STRATEGY strategy);

enum class FENCING_STRATEGY {
  // add the fence right before the next access of the aggressor if it has been flushed before
  LATEST_POSSIBLE
};

std::string get_string(FENCING_STRATEGY strategy);

// Signature of the generated function.
typedef int (*JittedFunction)(void);

class CodeJitter {
 private:
  /// runtime for JIT code execution
  asmjit::JitRuntime rt;

  /// a logger that keeps track of the generated ASM instructions - useful for debugging
  // asmjit::StringLogger* logger = nullptr;

  void get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices);

 public:
  /// hammering function that was generated at runtime
  JittedFunction fn = nullptr;

  void jit_original(size_t agg_rounds, uint64_t num_refresh_intervals,
                    std::vector<volatile char*>& aggressor_pairs, FENCING_STRATEGY fencing_strategy,
                    FLUSHING_STRATEGY flushing_strategy,
                    std::vector<volatile char*>& dummy_pair);

  void jit_strict(size_t agg_rounds, uint64_t num_refresh_intervals,
                  std::vector<volatile char*>& aggressor_pairs,
                  std::vector<volatile char*>& dummy_pair);

  void cleanup();
};

#endif /* CODEJITTER */
