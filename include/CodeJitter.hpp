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
  LATEST_POSSIBLE,
  // do not fence before accessing an aggressor even if it has been accessed before
  OMIT_FENCING
};

std::string get_string(FENCING_STRATEGY strategy);

class CodeJitter {
 private:
  /// runtime for JIT code execution, can be reused by cleaning the function ptr (see cleanup method)
  asmjit::JitRuntime runtime;

  /// a logger that keeps track of the generated ASM instructions - useful for debugging
  asmjit::StringLogger* logger = nullptr;

  /// a function pointer to a function that takes no input (void) and returns an integer
  int (*fn)(void) = nullptr;

 public:
  /// constructor
  CodeJitter();

  /// destructor
  ~CodeJitter();

  /// generates the jitted function and assigns the function pointer fn to it
  void jit_strict(size_t hammering_total_num_activations,
                  size_t hammering_reps_before_sync,
                  size_t sync_after_every_nth_hammering_rep,
                  FLUSHING_STRATEGY flushing_strategy,
                  FENCING_STRATEGY fencing_strategy,
                  const std::vector<volatile char*>& aggressor_pairs);

  /// does the hammering if the function was previously created successfully, otherwise does nothing
  int hammer_pattern();

  /// cleans this instance associated function pointer that points to the function that was jitted at runtime;
  /// cleaning up is required to release memory before jit_strict can be called again
  void cleanup();
};

#endif /* CODEJITTER */
