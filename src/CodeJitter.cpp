#include "../include/CodeJitter.hpp"

#include <algorithm>
#include <numeric>
#include <set>
#include <unordered_map>

void CodeJitter::cleanup() {
  rt.release(fn);
}

std::string get_string(FENCING_STRATEGY strategy) {
  std::unordered_map<FENCING_STRATEGY, std::string> map =
      {{FENCING_STRATEGY::LATEST_POSSIBLE, "LATEST_POSSIBLE"}};
  return map.at(strategy);
}

std::string get_string(FLUSHING_STRATEGY strategy) {
  std::unordered_map<FLUSHING_STRATEGY, std::string> map =
      {{FLUSHING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"}};
  return map.at(strategy);
}

void CodeJitter::get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices) {
  // use all numbers in range (0, ..., num_indices-1 = max) if there is only this one possibility
  indices.resize(num_indices);
  if (max == (num_indices - 1)) {
    std::iota(indices.begin(), indices.end(), 0);
    return;
  }
  // use random numbers between [0, num_indices-1] where num_indices-1 < max
  // use a set to avoid adding the same number multiple times
  std::set<size_t> nums;
  while (nums.size() < num_indices) {
    int candidate = rand() % max;
    if (nums.count(candidate) > 0) continue;
    nums.insert(candidate);
  }
  indices.insert(indices.end(), nums.begin(), nums.end());
}

void CodeJitter::jit_hammering_code_fenced(size_t agg_rounds, uint64_t num_refresh_intervals,
                                           std::vector<volatile char*>& aggressor_pairs, FENCING_STRATEGY fencing_strategy,
                                           FLUSHING_STRATEGY flushing_strategy,
                                           std::vector<volatile char*>& dummy_pair) {
  logger = new asmjit::StringLogger;
  asmjit::CodeHolder code;
  code.init(rt.environment());
  code.setLogger(logger);
  asmjit::x86::Assembler a(&code);

  asmjit::Label while1_begin = a.newLabel();
  asmjit::Label while1_end = a.newLabel();
  asmjit::Label for1_begin = a.newLabel();
  asmjit::Label for1_end = a.newLabel();
  asmjit::Label while2_begin = a.newLabel();
  asmjit::Label while2_end = a.newLabel();

  // do some preprocessing
  // count access frequency for each aggressor
  std::unordered_map<volatile char*, int> access_frequency;
  for (const auto& addr : aggressor_pairs) {
    access_frequency[addr]++;
  }

  // if the dummy_pair is empty, use the two aggressors with the lowest frequency count as dummies
  if (dummy_pair.empty()) {
    std::vector<std::pair<volatile char*, int>> elems(access_frequency.begin(), access_frequency.end());
    std::sort(elems.begin(), elems.end(), [](std::pair<volatile char*, int> a, std::pair<volatile char*, int> b) {
      return a.second < b.second;
    });
    dummy_pair.push_back(elems.at(0).first);
    dummy_pair.push_back(elems.at(1).first);
  }

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in blacksmith.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // choose two random addresses (more precisely, indices) of the aggressor_pairs set
  const std::vector<size_t> dummy_indices = {0, 1};

  // access first two NOPs as part of synchronization
  for (const auto& idx : dummy_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)dummy_pair[idx]);
    a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));
  }

  // while (true) { ...
  a.bind(while1_begin);
  // clflushopt both NOPs
  for (const auto& idx : dummy_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)dummy_pair[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();

  a.rdtscp();  // result of rdtscp is in [edx:eax]
  a.lfence();
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);

  // access both NOPs once
  for (const auto& idx : dummy_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)dummy_pair[idx]);
    a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));
  }

  a.rdtscp();  // result: edx:eax
  // if ((after - before) > 1000) break;
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t)1000);
  // depending on the cmp's outcome, jump out of loop or to the loop's beginning
  a.jg(while1_end);
  a.jmp(while1_begin);

  a.bind(while1_end);

  // ------- part 2: perform hammering and then check for next ACTIVATE ---------------------------

  a.mov(asmjit::x86::rsi, num_refresh_intervals);  // loop counter
  a.mov(asmjit::x86::edx, 0);                    // counter for number of accesses in sync at end of refresh interval

  a.bind(for1_begin);
  a.cmp(asmjit::x86::rsi, 0);
  a.jz(for1_end);
  a.dec(asmjit::x86::rsi);

  // as agg_rounds is typically a relatively low number, we do not encode the loop in ASM but instead
  // unroll the instructions to avoid the additional jump the loop would cause

  // hammering loop
  for (size_t i = 0; i < agg_rounds; i++) {
    for (size_t i = 0; i < aggressor_pairs.size(); i++) {
      // if this has aggressor has been accessed in the past, first add a mfence to make sure that any flushing finished
      if (fencing_strategy == FENCING_STRATEGY::LATEST_POSSIBLE && access_frequency.count(aggressor_pairs[i]) > 0) {
        a.mfence();
      }

      // "hammer": now perform the access
      a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
      a.mov(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rax));

      // flush the accessed aggressor even if it will not be accessed in this aggressor round anymore it will be
      // accessed in the next round, hence we need to always flush it
      if (flushing_strategy == FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
        a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
        a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
      }
    }

    for (size_t i = 0; i < aggressor_pairs.size(); i++) {
      a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
      a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }

    a.mfence();
  }

  // loop for synchronization after hammering: while (true) { ... }
  a.bind(while2_begin);
  // clflushopt both NOPs
  for (const auto& idx : dummy_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)dummy_pair[idx]);
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

  // access both NOPs once
  for (const auto& idx : dummy_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)dummy_pair[idx]);
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
  a.jmp(for1_begin);

  a.bind(for1_end);

  // now move our counter for no. of activations in the end of interval sync. to the 1st output register %eax
  a.mov(asmjit::x86::eax, asmjit::x86::edx);
  a.ret();  // this is ESSENTIAL otherwise execution of jitted code creates segfault

  // add the generated code to the runtime.
  asmjit::Error err = rt.add(&fn, &code);
  if (err) throw std::runtime_error("[-] Error occurred when trying to jit code. Aborting execution!");

  // uncomment the following line to see the jitted ASM code
  // printf("[DEBUG] asmjit logger content:\n%s\n", logger->data());
}
