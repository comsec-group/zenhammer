#include "../include/CodeJitter.hpp"

#include <algorithm>
#include <numeric>
#include <set>
#include <unordered_map>

CodeJitter::CodeJitter() {
  logger = new asmjit::StringLogger;
}

CodeJitter::~CodeJitter() {
  cleanup();
}

void CodeJitter::cleanup() {
  if (fn != nullptr) {
    runtime.release(fn);
    fn = nullptr;
  }
  if (logger != nullptr) {
    delete logger;
    logger = nullptr;
  }
}

std::string get_string(FENCING_STRATEGY strategy) {
  std::unordered_map<FENCING_STRATEGY, std::string> map =
      {{FENCING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"}};
  return map.at(strategy);
}

std::string get_string(FLUSHING_STRATEGY strategy) {
  std::unordered_map<FLUSHING_STRATEGY, std::string> map =
      {{FLUSHING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"}};
  return map.at(strategy);
}

int CodeJitter::hammer_pattern() {
  if (fn != nullptr) {
    printf("[+] Hammering pattern... ");
    fflush(stdout);
    int ret = fn();
    printf("done.\n");
    return ret;
  } else {
    printf("[-] Skipping hammering pattern as pattern could not be created successfully.\n");
    return -1;
  }
}

void CodeJitter::jit_strict(size_t pattern_hammering_reps,
                            FLUSHING_STRATEGY flushing_strategy,
                            FENCING_STRATEGY fencing_strategy,
                            std::vector<volatile char*>& aggressor_pairs) {
  // decides the number of aggressors of the beginning/end to be used for detecting the refresh interval
  // e.g., 10 means use the first 10 aggs in aggressor_pairs (repeatedly, if necessary) to detect the start refresh
  // (i.e., at the beginning) and the last 10 aggs in aggressor_pairs to detect the last refresh (at the end)
  const int NUM_TIMED_ACCESSES = 4;

  // check whether the NUM_TIMED_ACCESSES value works at all - otherwise just return from this function
  // this is safe as hammer_pattern checks whether there's a valid function
  if (NUM_TIMED_ACCESSES > aggressor_pairs.size()) {
    printf("[-] NUM_TIMED_ACCESSES (%d) is larger than #aggressor_pairs (%zu).\n", NUM_TIMED_ACCESSES, aggressor_pairs.size());
    return;
  }

  // some sanity checks
  if (fn != nullptr) {
    printf(
        "[-] Function pointer is not NULL, cannot continue jitting code without leaking memory. "
        "Did you forget to call cleanup() before?\n");
    exit(1);
  }
  if (flushing_strategy != FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
    printf("jit_strict does not support given FLUSHING_STRATEGY (%s).\n", get_string(flushing_strategy).c_str());
  }
  if (fencing_strategy != FENCING_STRATEGY::EARLIEST_POSSIBLE) {
    printf("jit_strict does not support given FENCING_STRATEGY (%s).\n", get_string(fencing_strategy).c_str());
  }

  asmjit::CodeHolder code;
  code.init(runtime.environment());
  // code.setLogger(logger);
  asmjit::x86::Assembler a(&code);

  asmjit::Label while1_begin = a.newLabel();
  asmjit::Label while1_end = a.newLabel();
  asmjit::Label for1_begin = a.newLabel();
  asmjit::Label for1_end = a.newLabel();
  asmjit::Label while2_begin = a.newLabel();
  asmjit::Label while2_end = a.newLabel();

  // do some preprocessing: count number of accesses (= access frequency) for each aggressor
  std::unordered_map<volatile char*, int> access_frequency;
  for (const auto& addr : aggressor_pairs) access_frequency[addr]++;

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in blacksmith.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // access first sync_start_indices aggressors as part of the synchronization
  for (size_t idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[idx]);
    a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));
  }

  // while (true) { ...
  a.bind(while1_begin);
  // clflushopt both NOPs
  for (size_t idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();

  a.rdtscp();  // result of rdtscp is in [edx:eax]
  a.lfence();
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);

  // access both NOPs once
  for (size_t idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[idx]);
    a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));
  }

  // if ((after - before) > 1000) break;
  a.rdtscp();  // result: edx:eax
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t)1000);

  // depending on the cmp's outcome, jump out of loop or to the loop's beginning
  a.jg(while1_end);
  a.jmp(while1_begin);

  // end of while(true) {...}
  a.bind(while1_end);

  // ------- part 2: perform hammering and then check for next ACTIVATE after finishing hammering --------

  printf("[DEBUG] pattern_hammering_reps: %zu\n", pattern_hammering_reps);
  a.mov(asmjit::x86::rsi, pattern_hammering_reps);  // loop counter
  a.mov(asmjit::x86::edx, 0);                       // initialize num activations counter

  a.bind(for1_begin);
  a.cmp(asmjit::x86::rsi, 0);
  a.jle(for1_end);
  // a.dec(asmjit::x86::rsi);

  // as agg_rounds is typically a relatively low number, we do not encode the loop in ASM but instead
  // unroll the instructions to avoid the additional jump the loop would cause

  // hammer each aggressor once
  printf("[DEBUG] aggressor_pairs.size(): %zu\n", aggressor_pairs.size());

  for (size_t i = 0; i < aggressor_pairs.size(); i++) {
    // hammer
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
    a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));
    a.dec(asmjit::x86::rsi);

    // fence -> ensure that access order is not interleaved
    a.lfence();

    // flush
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));

    // fences -> ensure that accesses are not interleaved, i.e., we acccess aggressors always in same order
    a.mfence();
    a.lfence();
  }

  a.jmp(for1_begin);
  a.bind(for1_end);

  // // synchronize with the end of the refresh interval: while (true) { ... }
  a.bind(while2_begin);
  // clflushopt both NOPs
  for (size_t idx = aggressor_pairs.size() - NUM_TIMED_ACCESSES; idx < aggressor_pairs.size(); idx++) {
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();
  a.lfence();

  a.push(asmjit::x86::edx);
  a.rdtscp();  // result of rdtscp is in [edx:eax]
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);
  a.lfence();
  a.pop(asmjit::x86::edx);

  // access last NUM_TIMED_ACCESSES aggressors
  for (size_t idx = aggressor_pairs.size() - NUM_TIMED_ACCESSES; idx < aggressor_pairs.size(); idx++) {
    a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[idx]);
    a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));
    a.inc(asmjit::x86::edx);
  }

  a.push(asmjit::x86::edx);
  a.rdtscp();  // result: edx:eax
  a.lfence();
  a.pop(asmjit::x86::edx);

  // if ((after - before) > 1000) break;
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t)1000);

  // depending on the cmp's outcome...
  a.jg(while2_end);     // ... jump out of the loop
  a.jmp(while2_begin);  // ... or jump back to the loop's beginning

  a.bind(while2_end);

  // now move our counter for no. of activations in the end of interval sync. to the 1st output register %eax
  a.mov(asmjit::x86::eax, asmjit::x86::edx);
  a.ret();  // this is ESSENTIAL otherwise execution of jitted code creates a segfault

  // add the generated code to the runtime.
  asmjit::Error err = runtime.add(&fn, &code);
  if (err) throw std::runtime_error("[-] Error occurred while jitting code. Aborting execution!");

  printf("[+] Successfully created jitted hammering code.\n");

  // uncomment the following line to see the jitted ASM code
  // printf("[DEBUG] asmjit logger content:\n%s\n", logger->data());
}
