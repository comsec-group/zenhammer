#include "Fuzzer/CodeJitter.hpp"

#include <algorithm>
#include <set>
#include <map>
#include <string>

CodeJitter::CodeJitter() {
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
  if (logger!=nullptr) {
    delete logger;
    logger = nullptr;
  }
}

std::string get_string(FENCING_STRATEGY strategy) {
  std::map<FENCING_STRATEGY, std::string> map =
      {
          {FENCING_STRATEGY::LATEST_POSSIBLE, "LATEST_POSSIBLE"},
          {FENCING_STRATEGY::OMIT_FENCING, "OMIT_FENCING"}
      };
  return map.at(strategy);
}

std::string get_string(FLUSHING_STRATEGY strategy) {
  std::map<FLUSHING_STRATEGY, std::string> map =
      {
          {FLUSHING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"}
      };
  return map.at(strategy);
}

int CodeJitter::hammer_pattern() {
  if (fn==nullptr) {
    printf("[-] Skipping hammering pattern as pattern could not be created successfully.\n");
    return -1;
  }
  printf("[+] Hammering pattern.\n");
  fflush(stdout);
  int ret = fn();
  return ret;
}

void CodeJitter::jit_strict(size_t hammering_total_num_activations,
                            FLUSHING_STRATEGY flushing_strategy,
                            FENCING_STRATEGY fencing_strategy,
                            const std::vector<volatile char *> &aggressor_pairs) {
  // decides the number of aggressors of the beginning/end to be used for detecting the refresh interval
  // e.g., 10 means use the first 10 aggs in aggressor_pairs (repeatedly, if necessary) to detect the start refresh
  // (i.e., at the beginning) and the last 10 aggs in aggressor_pairs to detect the last refresh (at the end)
  const int NUM_TIMED_ACCESSES = 2;

  // check whether the NUM_TIMED_ACCESSES value works at all - otherwise just return from this function
  // this is safe as hammer_pattern checks whether there's a valid function
  if (NUM_TIMED_ACCESSES > aggressor_pairs.size()) {
    printf("[-] NUM_TIMED_ACCESSES (%d) is larger than #aggressor_pairs (%zu).\n",
           NUM_TIMED_ACCESSES,
           aggressor_pairs.size());
    return;
  }

  // some sanity checks
  if (fn!=nullptr) {
    printf(
        "[-] Function pointer is not NULL, cannot continue jitting code without leaking memory. "
        "Did you forget to call cleanup() before?\n");
    exit(1);
  }
  if (flushing_strategy!=FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
    printf("jit_strict does not support given FLUSHING_STRATEGY (%s).\n", get_string(flushing_strategy).c_str());
  }
  if (fencing_strategy!=FENCING_STRATEGY::LATEST_POSSIBLE && fencing_strategy!=FENCING_STRATEGY::OMIT_FENCING) {
    printf("jit_strict does not support given FENCING_STRATEGY (%s).\n", get_string(fencing_strategy).c_str());
  }

  printf("[+] Creating ASM code for hammering.\n");
  fflush(stdout);

  asmjit::CodeHolder code;
  code.init(runtime.environment());
  code.setLogger(logger);
  asmjit::x86::Assembler a(&code);

  asmjit::Label while1_begin = a.newLabel();
  asmjit::Label while1_end = a.newLabel();
  asmjit::Label for_begin = a.newLabel();
  asmjit::Label for_end = a.newLabel();
  asmjit::Label while2_begin = a.newLabel();
  asmjit::Label while2_end = a.newLabel();

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in blacksmith.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // warmup
  for (size_t idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.mov(asmjit::x86::rbx, asmjit::x86::ptr(asmjit::x86::rax));
  }

  a.bind(while1_begin);
  // clflushopt addresses involved in sync
  for (size_t idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();

  // retrieve timestamp
  a.rdtscp();  // result of rdtscp is in [edx:eax]
  a.lfence();
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);  // discard upper 32 bits, store lower 32b in ebx for later

  // use first NUM_TIMED_ACCESSES addresses for sync
  for (size_t idx = 0; idx < NUM_TIMED_ACCESSES; idx++) {
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
  }

  // if ((after - before) > 1000) break;
  a.rdtscp();  // result: edx:eax
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t) 1000);

  // depending on the cmp's outcome, jump out of loop or to the loop's beginning
  a.jg(while1_end);
  a.jmp(while1_begin);
  a.bind(while1_end);

  // ------- part 2: perform hammering ---------------------------------------------------------------------------------

  // initialize variables
  a.mov(asmjit::x86::rsi, hammering_total_num_activations);
  a.mov(asmjit::x86::edx, 0);  // num activations counter

  a.bind(for_begin);
  a.cmp(asmjit::x86::rsi, 0);
  a.jle(for_end);

  // a map to keep track of aggressors that have been accessed before and need a fence before their next access
  std::unordered_map<uint64_t, bool> accessed_before;

  // hammer each aggressor once
  for (size_t i = NUM_TIMED_ACCESSES; i < aggressor_pairs.size() - NUM_TIMED_ACCESSES; i++) {
    auto cur_addr = (uint64_t) aggressor_pairs[i];

    // fence to ensure flushing finshed and defined order of accesses
    if (fencing_strategy==FENCING_STRATEGY::LATEST_POSSIBLE && accessed_before[cur_addr]) {
      a.mfence();
      accessed_before[cur_addr] = false;
    }

    // hammer
    a.mov(asmjit::x86::rax, cur_addr);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    accessed_before[cur_addr] = true;
    a.dec(asmjit::x86::rsi);

    // flush
    if (flushing_strategy==FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
      // flush
      a.mov(asmjit::x86::rax, cur_addr);
      a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }
  }

  // fences -> ensure that accesses are not interleaved, i.e., we acccess aggressors always in same order
  a.mfence();

  // ------- part 3: synchronize with the end  -----------------------------------------------------------------------

  // synchronize with the end of the refresh interval: while (true) { ... }
  a.bind(while2_begin);

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
    // flush
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    // access
    a.mov(asmjit::x86::rax, (uint64_t) aggressor_pairs[idx]);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    a.dec(asmjit::x86::rsi);
    // update counter that counts the number of activation in the trailing synchronization
    a.inc(asmjit::x86::edx);
  }

  a.push(asmjit::x86::edx);
  a.rdtscp();  // result: edx:eax
  a.lfence();
  a.pop(asmjit::x86::edx);

  // if ((after - before) > 1000) break;
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t) 1000);

  // depending on the cmp's outcome...
  a.jg(while2_end);     // ... jump out of the loop
  a.jmp(while2_begin);  // ... or jump back to the loop's beginning
  a.bind(while2_end);

  a.jmp(for_begin);
  a.bind(for_end);

  // now move our counter for no. of activations in the end of interval sync. to the 1st output register %eax
  a.mov(asmjit::x86::eax, asmjit::x86::edx);
  a.ret();  // this is ESSENTIAL otherwise execution of jitted code creates a segfault

  // add the generated code to the runtime.
  asmjit::Error err = runtime.add(&fn, &code);
  if (err) throw std::runtime_error("[-] Error occurred while jitting code. Aborting execution!");

  printf("[+] Successfully created jitted hammering code.\n");
  fflush(stdout);

  // uncomment the following line to see the jitted ASM code
  // printf("[DEBUG] asmjit logger content:\n%s\n", logger->data());
}
