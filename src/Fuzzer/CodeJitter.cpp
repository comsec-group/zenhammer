#include "Fuzzer/CodeJitter.hpp"
#include "GlobalDefines.hpp"

CodeJitter::CodeJitter()
    : pattern_sync_each_ref(false),
      flushing_strategy(FLUSHING_STRATEGY::EARLIEST_POSSIBLE),
      fencing_strategy(FENCING_STRATEGY::OMIT_FENCING),
      total_activations(5000000),
      num_aggs_for_sync(2) {
  logger = new asmjit::StringLogger;
}

CodeJitter::~CodeJitter() {
  cleanup();
}

void CodeJitter::cleanup() {
  if (fn!=nullptr) {
    runtime.release(fn);
    fn = nullptr;
  }
  if (fn_ref_sync != nullptr) {
    runtime.release(fn_ref_sync);
    fn_ref_sync = nullptr;
  }
  if (logger!=nullptr) {
    delete logger;
    logger = nullptr;
  }
}

int CodeJitter::hammer_pattern(FuzzingParameterSet &fuzzing_parameters, bool verbose, bool print_act_data) {
  if (fn==nullptr) {
    Logger::log_error("Skipping hammering pattern as pattern could not be created successfully.");
    return -1;
  }
  HammeringData data {};
  if (verbose) Logger::log_info("Hammering the last generated pattern.");
  int total_sync_acts = fn(&data);

  if (verbose) {
    Logger::log_info("Synchronization stats:");
    Logger::log_data(format_string("Total sync acts: %d", total_sync_acts));

    const auto total_acts_pattern = fuzzing_parameters.get_total_acts_pattern();
    auto pattern_rounds = fuzzing_parameters.get_hammering_total_num_activations()/total_acts_pattern;
    auto acts_per_pattern_round = pattern_sync_each_ref
                                  // sync after each num_acts_per_tREFI: computes how many activations are necessary
                                  // by taking our pattern's length into account
                                  ? (total_acts_pattern/fuzzing_parameters.get_num_activations_per_t_refi())
                                  // beginning and end of pattern; for simplicity we only consider the end of the
                                  // pattern here (=1) as this is the sync that is repeated after each hammering run
                                  : 1;
    auto num_synced_refs = pattern_rounds*acts_per_pattern_round;
    Logger::log_data(format_string("Number of pattern reps while hammering: %d", pattern_rounds));
    Logger::log_data(format_string("Number of total synced REFs (est.): %d", num_synced_refs));
    Logger::log_data(format_string("Avg. number of acts per sync: %d", total_sync_acts/num_synced_refs));
  }

  if (print_act_data) {
    // Print total ACTs + TSC delta.
    Logger::log_data(format_string("ACT DATA: %llu ACTs, %llu cycles", data.total_acts, data.tsc_delta));
  }

  return total_sync_acts;
}

void CodeJitter::jit_strict(
  FLUSHING_STRATEGY flushing,
  FENCING_STRATEGY fencing,
  const std::vector<volatile char *> &aggressor_pairs,
  FENCE_TYPE fence_type,
  int total_num_activations
) {

  // this is used by hammer_pattern but only for some stats calculations
  this->pattern_sync_each_ref = false;
  this->flushing_strategy = flushing;
  this->fencing_strategy = fencing;
  this->total_activations = total_num_activations;

  // FIXME: This is unused, remove it.
  this->num_aggs_for_sync = 2;


  // some sanity checks
  if (fn!=nullptr) {
    Logger::log_error(
        "Function pointer is not NULL, cannot continue jitting code without leaking memory. Did you forget to call cleanup() before?");
    exit(1);
  }

  asmjit::CodeHolder code;
  code.init(runtime.environment());
  code.setLogger(logger);
  asmjit::x86::Assembler a(&code);

  asmjit::Label for_begin = a.newLabel();
  asmjit::Label for_end = a.newLabel();

  a.push(asmjit::x86::r12);
  a.push(asmjit::x86::r13);
  a.push(asmjit::x86::r14);
  a.push(asmjit::x86::r15);

  // Move pointer to struct HammeringData to %r12.
  a.mov(asmjit::x86::r12, asmjit::x86::rdi);

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in zenHammer.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // Get the inital aggressor for sync_ref_nonrepeating().
  auto hammer_bank = DRAMAddr((void*)aggressor_pairs.front()).bank;
  // sync_bank is the same bank as hammer_bank, but it may be indexed differently due to differing MSBs.
  auto sync_bank = DRAMAddr::translate_bank(0, 1, hammer_bank);
  auto sync_ref_initial_aggr = DRAMAddr(sync_bank, 0, 0, /* mapping_id */ 1);

  sync_ref_nonrepeating(sync_ref_initial_aggr, DRAMConfig::get().get_sync_ref_threshold(), a);

  // ------- part 2: perform hammering ---------------------------------------------------------------------------------

  // Time the start. Move full TSC to %r13.
  a.rdtscp();
  a.mov(asmjit::x86::r13d, asmjit::x86::edx);
  a.shl(asmjit::x86::r13, 32);
  a.or_(asmjit::x86::r13, asmjit::x86::rax);

  // Start counting ACTs now.

  // initialize variables
  a.mov(asmjit::x86::rsi, total_num_activations);
  a.mov(asmjit::x86::edx, 0);  // num activations counter

  a.bind(for_begin);
  a.cmp(asmjit::x86::rsi, 0);
  a.jle(for_end);

  // a map to keep track of aggressors that have been accessed before and need a fence before their next access
  std::unordered_map<uint64_t, bool> accessed_before;

  size_t cnt_total_activations = 0;

  // hammer each aggressor once
  for (auto* aggr : aggressor_pairs) {
    if (aggr == nullptr) {
      if (fence_type == MFENCE) {
        a.mfence();
      } else if (fence_type == LFENCE) {
        a.lfence();
      } else if (fence_type == SFENCE) {
        a.sfence();
      }
      continue;
    }

    auto cur_addr = (uint64_t)aggr;
    if (accessed_before[cur_addr]) {
      // flush
      if (flushing==FLUSHING_STRATEGY::LATEST_POSSIBLE) {
        a.mov(asmjit::x86::rax, cur_addr);
        a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
        accessed_before[cur_addr] = false;
      }
      // fence to ensure flushing finished and defined order of aggressors is guaranteed
      if (fencing==FENCING_STRATEGY::LATEST_POSSIBLE) {
        a.mfence();
        accessed_before[cur_addr] = false;
      }
    }

    // hammer
    a.mov(asmjit::x86::rax, cur_addr);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    accessed_before[cur_addr] = true;
    a.dec(asmjit::x86::rsi);
    a.inc(asmjit::x86::edx);
    cnt_total_activations++;

    // flush
    if (flushing==FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
      a.mov(asmjit::x86::rax, cur_addr);
      a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }
  }

  // fences -> ensure that aggressors are not interleaved, i.e., we access aggressors always in same order
  if (fencing != FENCING_STRATEGY::OMIT_FENCING) {
    a.mfence();
  }

  // ------- part 3: synchronize with the end  -----------------------------------------------------------------------

  sync_ref_nonrepeating(sync_ref_initial_aggr, DRAMConfig::get().get_sync_ref_threshold(), a);

  a.jmp(for_begin);
  a.bind(for_end);

  // Move ACT count to %r14.
  a.mov(asmjit::x86::r14d, asmjit::x86::edx);
  // Time the end.
  a.rdtscp();
  a.shl(asmjit::x86::rdx, 32);
  a.or_(asmjit::x86::rdx, asmjit::x86::rax);
  a.sub(asmjit::x86::rdx, asmjit::x86::r13);
  // TSC delta is now in %rdx. Store it into the struct.

  // Store data into the struct pointed to by %r12.
  a.mov(asmjit::x86::ptr(asmjit::x86::r12, offsetof(HammeringData, tsc_delta)), asmjit::x86::rdx);
  a.mov(asmjit::x86::ptr(asmjit::x86::r12, offsetof(HammeringData, total_acts)), asmjit::x86::r14);

  // Move ACT count back to %edx.
  a.mov(asmjit::x86::edx, asmjit::x86::r14d);

  a.pop(asmjit::x86::r15);
  a.pop(asmjit::x86::r14);
  a.pop(asmjit::x86::r13);
  a.pop(asmjit::x86::r12);

  // now move our counter for no. of activations in the end of interval sync. to the 1st output register %eax
  a.mov(asmjit::x86::eax, asmjit::x86::edx);
  a.ret();  // this is ESSENTIAL otherwise execution of jitted code creates a segfault

  // add the generated code to the runtime.
  asmjit::Error err = runtime.add(&fn, &code);
  if (err) throw std::runtime_error("[-] Error occurred while jitting code. Aborting execution!");

  // uncomment the following line to see the jitted ASM code
  // printf("[DEBUG] asmjit logger content:\n%s\n", logger->corrupted_data());
}

void CodeJitter::sync_ref(const std::vector<volatile char *> &aggressor_pairs, asmjit::x86::Assembler &assembler) {
  asmjit::Label wbegin = assembler.newLabel();
  asmjit::Label wend = assembler.newLabel();

  assembler.bind(wbegin);

  assembler.mfence();
  assembler.lfence();

  assembler.push(asmjit::x86::edx);
  assembler.rdtscp();  // result of rdtscp is in [edx:eax]
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  assembler.mov(asmjit::x86::ebx, asmjit::x86::eax);
  assembler.lfence();
  assembler.pop(asmjit::x86::edx);

  for (auto agg : aggressor_pairs) {
    // flush
    assembler.mov(asmjit::x86::rax, (uint64_t) agg);
    assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));

    // access
    assembler.mov(asmjit::x86::rax, (uint64_t) agg);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));

    // we do not deduct the sync aggressors from the total number of activations because the number of sync activations
    // varies for different patterns; if we deduct it from the total number of activations, we cannot ensure anymore
    // that we are hammering long enough/as many times as needed to trigger bit flips
//    assembler.dec(asmjit::x86::rsi);

    // update counter that counts the number of activation in the trailing synchronization
    assembler.inc(asmjit::x86::edx);
  }

  assembler.push(asmjit::x86::edx);
  assembler.rdtscp();  // result: edx:eax
  assembler.lfence();
  assembler.pop(asmjit::x86::edx);

  // if ((after - before) > SYNC_REF_THRESHOLD) break;
  assembler.sub(asmjit::x86::eax, asmjit::x86::ebx);
  assembler.cmp(asmjit::x86::eax, (uint64_t)SYNC_REF_THRESHOLD);

  // depending on the cmp's outcome...
  assembler.jg(wend);     // ... jump out of the loop
  assembler.jmp(wbegin);  // ... or jump back to the loop's beginning
  assembler.bind(wend);
}

// This function accesses a list of rows starting from initial_aggressors. It measures the access time between
// aggressors until REF is detected. Then it flushes all aggressors using clflush and hands control back.
void CodeJitter::sync_ref_nonrepeating(DRAMAddr inital_aggressor, size_t sync_ref_threshold, asmjit::x86::Assembler& assembler) {
  asmjit::Label out = assembler.newLabel();

  // PRE: %edx is an in-out argument containing the number of ACTs done for synchronization.

  // Move ACT count from %edx to %r10d.
  assembler.mov(asmjit::x86::r10d, asmjit::x86::edx);

  // Serialize rdtscp from above.
  assembler.lfence();
  // %ebx always contains the previous access timestamp.
  assembler.rdtscp(); // Returns result in [edx:eax]. We discard the upper 32 bits.
  assembler.mov(asmjit::x86::ebx, asmjit::x86::eax);
  // Serialize rdtscp from below.
  assembler.lfence();

  // Weird row increment to hopefully not trigger the prefetcher.
  constexpr size_t AGGR_ROW_INCREMENT = 17;

  auto current_aggr = inital_aggressor;
  for (size_t i = 0; i < SYNC_REF_NUM_AGGRS; i++) {
    auto current = current_aggr.to_virt();
    assembler.mov(asmjit::x86::rax, (uint64_t)current);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    current_aggr.add_inplace(0, AGGR_ROW_INCREMENT, 0);

    // Increment %r10, which counts the number of ACTs.
    assembler.inc(asmjit::x86::r10d);

    // Measure time.
    assembler.lfence();
    assembler.rdtscp();
    assembler.lfence();

    // %edx = %eax (current timestamp) - %ebx (previous timestamp).
    assembler.mov(asmjit::x86::edx, asmjit::x86::eax);
    assembler.sub(asmjit::x86::edx, asmjit::x86::ebx);

    // Ignore first 4 iterations for warmup.
    if (i >= 4) {
      // if (%edx > sync_ref_threshold) { break; }
      assembler.cmp(asmjit::x86::edx, sync_ref_threshold);
      assembler.jg(out);
    }

    // else { %ebx = %eax; }
    assembler.mov(asmjit::x86::ebx, asmjit::x86::eax);
  }

  assembler.bind(out);

  // Flush all aggressors from cache.
  current_aggr = inital_aggressor;
  for (size_t i = 0; i < SYNC_REF_NUM_AGGRS; i++) {
    auto current = current_aggr.to_virt();
    assembler.mov(asmjit::x86::rax, (uint64_t)current);
    assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    current_aggr.add_inplace(0, AGGR_ROW_INCREMENT, 0);
  }

  // Move ACT count from %r10d back to %edx.
  assembler.mov(asmjit::x86::edx, asmjit::x86::r10d);
}

void CodeJitter::jit_ref_sync(
  FLUSHING_STRATEGY flushing,
  FENCING_STRATEGY fencing,
  std::vector<volatile char*> const& aggressors,
  DRAMAddr sync_ref_initial_aggr,
  size_t sync_ref_threshold) {
  if (flushing != FLUSHING_STRATEGY::EARLIEST_POSSIBLE || fencing != FENCING_STRATEGY::OMIT_FENCING) {
    Logger::log_error("jit_ref_sync() implicitly assumes FLUSHING_STRATEGY::EARLIEST_POSSIBLE and FENCING_STRATEGY::OMIT_FENCING");
    exit(1);
  }

  if (fn_ref_sync != nullptr) {
    Logger::log_error( "Function pointer is not NULL, cannot continue jitting code without leaking memory. Did you forget to call cleanup() before?");
    exit(1);
  }

  // Initialize assembler.
  asmjit::CodeHolder code;
  code.init(runtime.environment());
  asmjit::x86::Assembler assembler(&code);

  // PRE: %rdi (first register) contains a pointer to a struct RefSyncData, used to return the results.

  // FIRST SYNC: Initially synchronize with REF.

  // Store time stamp into %r8d.
  assembler.rdtscp();
  assembler.mov(asmjit::x86::r8d, asmjit::x86::eax);

  // Initialize ACT count.
  assembler.mov(asmjit::x86::edx, 0);
  sync_ref_nonrepeating(sync_ref_initial_aggr, sync_ref_threshold, assembler);
  // Move ACT count to %r9d to store it for later use.
  assembler.mov(asmjit::x86::r9d, asmjit::x86::edx);

  // Obtain time stamp.
  assembler.rdtscp(); // clobbers %eax, %edx.
  // Keep new timestamp in %eax (for later use), also copy it to %edx.
  assembler.mov(asmjit::x86::edx, asmjit::x86::eax);

  // Subtract initial timestamp (in %r8d) from current timestamp (in %edx) to get TSC delta (in %edx).
  assembler.sub(asmjit::x86::edx, asmjit::x86::r8d);
  // Move new timestamp (in %eax) to %r8d for use after next sync.
  assembler.mov(asmjit::x86::r8d, asmjit::x86::eax);

  // Store time stamp delta (from %edx) and ACT count (from %r9d) into struct. Store as 32 bit.
  assembler.mov(asmjit::x86::ptr(asmjit::x86::rdi, offsetof(RefSyncData, first_sync_tsc_delta)), asmjit::x86::edx);
  assembler.mov(asmjit::x86::ptr(asmjit::x86::rdi, offsetof(RefSyncData, first_sync_act_count)), asmjit::x86::r9d);

  // SECOND SYNC: Synchronize REF to REF.

  // Previous timestamp is still in %r8d.
  // Initialize ACT count.
  assembler.mov(asmjit::x86::edx, 0);
  sync_ref_nonrepeating(sync_ref_initial_aggr, sync_ref_threshold, assembler);
  // Move ACT count to %r9d to store it for later use.
  assembler.mov(asmjit::x86::r9d, asmjit::x86::edx);

  // Obtain time stamp.
  assembler.rdtscp(); // clobbers %eax, %edx.

  // Subtract initial timestamp (in %r8d) from current timestamp (in %eax) to get TSC delta (in %eax).
  assembler.sub(asmjit::x86::eax, asmjit::x86::r8d);

  // Store time stamp delta (from %edx) and ACT count (from %r9d) into struct. Store as 32 bit.
  assembler.mov(asmjit::x86::ptr(asmjit::x86::rdi, offsetof(RefSyncData, second_sync_tsc_delta)), asmjit::x86::eax);
  assembler.mov(asmjit::x86::ptr(asmjit::x86::rdi, offsetof(RefSyncData, second_sync_act_count)), asmjit::x86::r9d);

  // AGGRESSOR ACTIVATIONS
  // Access each given agressor once, and clflush it.
  for (auto* aggressor : aggressors) {
    assembler.mov(asmjit::x86::rax, (uint64_t)aggressor);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }

  // LAST SYNC

  // Store time stamp into %r8d.
  assembler.rdtscp();
  assembler.mov(asmjit::x86::r8d, asmjit::x86::eax);

  // Initialize ACT count.
  assembler.mov(asmjit::x86::edx, 0);
  sync_ref_nonrepeating(sync_ref_initial_aggr, sync_ref_threshold, assembler);
  // Move ACT count to %r9d to store it for later use.
  assembler.mov(asmjit::x86::r9d, asmjit::x86::edx);

  // Obtain time stamp.
  assembler.rdtscp(); // clobbers %eax, %edx.
  // Subtract initial timestamp (in %r8d) from current timestamp (in %eax) to get TSC delta (in %eax).
  assembler.sub(asmjit::x86::eax, asmjit::x86::r8d);

  // Store time stamp delta (from %edx) and ACT count (from %r9d) into struct. Store as 32 bit.
  assembler.mov(asmjit::x86::ptr(asmjit::x86::rdi, offsetof(RefSyncData, last_sync_tsc_delta)), asmjit::x86::eax);
  assembler.mov(asmjit::x86::ptr(asmjit::x86::rdi, offsetof(RefSyncData, last_sync_act_count)), asmjit::x86::r9d);

  // return 0;
  assembler.mov(asmjit::x86::rax, 0);
  assembler.ret();

  // Add the generated code to the runtime.
  asmjit::Error err = runtime.add(&fn_ref_sync, &code);
  if (err) throw std::runtime_error("[-] Error occurred while jitting code. Aborting execution!");
}
#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const CodeJitter &p) {
  j = {{"pattern_sync_each_ref", p.pattern_sync_each_ref},
       {"flushing_strategy", to_string(p.flushing_strategy)},
       {"fencing_strategy", to_string(p.fencing_strategy)},
       {"total_activations", p.total_activations},
       {"num_aggs_for_sync", p.num_aggs_for_sync}
  };
}

void from_json(const nlohmann::json &j, CodeJitter &p) {
  j.at("pattern_sync_each_ref").get_to(p.pattern_sync_each_ref);
  from_string(j.at("flushing_strategy"), p.flushing_strategy);
  from_string(j.at("fencing_strategy"), p.fencing_strategy);
  j.at("total_activations").get_to(p.total_activations);
  j.at("num_aggs_for_sync").get_to(p.num_aggs_for_sync);
}

#endif
