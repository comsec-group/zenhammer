#ifndef CODEJITTER
#define CODEJITTER

#ifdef ENABLE_JITTING
#include <asmjit/asmjit.h>
#endif

#include <unordered_map>
#include <vector>
#include "Utilities/Enums.hpp"
#include "FuzzingParameterSet.hpp"

class CodeJitter {
 private:
#ifdef ENABLE_JITTING

  /// runtime for JIT code execution, can be reused by cleaning the function ptr (see cleanup method)
  asmjit::JitRuntime runtime;

  /// a logger that keeps track of the generated ASM instructions - useful for debugging
  asmjit::StringLogger *logger = nullptr;
#endif

  /// a function pointer to a function that takes no input (void) and returns an integer
  int (*fn)() = nullptr;

 public:
  /// constructor
  CodeJitter();

  /// destructor
  ~CodeJitter();

  /// generates the jitted function and assigns the function pointer fn to it
  void jit_strict(FuzzingParameterSet &fuzzing_params,
                  FLUSHING_STRATEGY flushing_strategy,
                  FENCING_STRATEGY fencing_strategy,
                  const std::vector<volatile char *> &aggressor_pairs,
                  bool sync_each_ref);

  /// does the hammering if the function was previously created successfully, otherwise does nothing
  int hammer_pattern();

  /// cleans this instance associated function pointer that points to the function that was jitted at runtime;
  /// cleaning up is required to release memory before jit_strict can be called again
  void cleanup();

  void sync_ref(const std::vector<volatile char *> &aggressor_pairs,
                       int NUM_TIMED_ACCESSES,
                       asmjit::x86::Assembler &assembler);
};

#endif /* CODEJITTER */
