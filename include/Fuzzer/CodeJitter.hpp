/*
 * Copyright (c) 2024 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef CODEJITTER
#define CODEJITTER

#include <unordered_map>
#include <vector>

#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Memory/DRAMAddr.hpp"
#include "Utilities/Enums.hpp"

#include <asmjit/asmjit.h>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

// NOTE: The members of this struct should not be re-arranged, as they are written to from Assembly.
struct RefSyncData {
  // first sync: immediately after the function starts
  uint32_t first_sync_act_count { 0 };
  uint32_t first_sync_tsc_delta { 0 };
  // second sync: REF-to-REF, after first sync
  uint32_t second_sync_act_count { 0 };
  uint32_t second_sync_tsc_delta { 0 };
  // last sync: after configurable number of aggressors
  uint32_t last_sync_act_count { 0 };
  uint32_t last_sync_tsc_delta { 0 };
};

struct HammeringData {
  uint64_t tsc_delta { 0 };
  uint64_t total_acts { 0 };
};

class CodeJitter {
 private:
  /// runtime for JIT code execution, can be reused by cleaning the function ptr (see cleanup method)
  asmjit::JitRuntime runtime;

  /// a logger that keeps track of the generated ASM instructions - useful for debugging
  asmjit::StringLogger *logger = nullptr;

  int (*fn)(HammeringData*) = nullptr;
  size_t (*fn_ref_sync)(RefSyncData*) = nullptr;

 public:
  bool pattern_sync_each_ref;

  FLUSHING_STRATEGY flushing_strategy;

  FENCING_STRATEGY fencing_strategy;

  int total_activations;

  int num_aggs_for_sync;

  /// constructor
  CodeJitter();
  
  /// destructor
  ~CodeJitter();

  /// generates the jitted function and assigns the function pointer fn to it
  void jit_strict(
    FLUSHING_STRATEGY flushing,
    FENCING_STRATEGY fencing,
    const std::vector<volatile char *> &aggressor_pairs,
    FENCE_TYPE fence_type,
    int total_num_activations
  );

  /// does the hammering if the function was previously created successfully, otherwise does nothing
  int hammer_pattern(FuzzingParameterSet &fuzzing_parameters, bool verbose, bool print_act_data = false);

  /// cleans this instance associated function pointer that points to the function that was jitted at runtime;
  /// cleaning up is required to release memory before jit_strict can be called again
  void cleanup();

  void jit_ref_sync(
    FLUSHING_STRATEGY flushing,
    FENCING_STRATEGY fencing,
    std::vector<volatile char*> const& aggressors,
    DRAMAddr sync_ref_initial_aggr,
    size_t sync_ref_threshold);

  size_t run_ref_sync(RefSyncData* ref_sync_data) {
    if (fn_ref_sync == nullptr) {
      Logger::log_error("Cannot run fn_ref_sync as it is NULL.");
      exit(1);
    }
    return (*fn_ref_sync)(ref_sync_data);
  }

  static void sync_ref(const std::vector<volatile char *> &aggressor_pairs, asmjit::x86::Assembler &assembler);
  static void sync_ref_nonrepeating(DRAMAddr initial_aggressor, size_t sync_ref_threshold, asmjit::x86::Assembler &assembler);

  static constexpr size_t SYNC_REF_NUM_AGGRS = 128;
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const CodeJitter &p);

void from_json(const nlohmann::json &j, CodeJitter &p);

#endif

#endif /* CODEJITTER */
