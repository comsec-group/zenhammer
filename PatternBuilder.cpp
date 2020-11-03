#include "PatternBuilder.h"

#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "DramAnalyzer.h"
#include "GlobalDefines.h"
#include "utils.h"

PatternBuilder::PatternBuilder(int num_activations) : num_activations(num_activations) {
  randomize_parameters();
}

void PatternBuilder::randomize_parameters() {
  printf(FCYAN "[+] Generating new set of random parameters: ");
  num_hammering_pairs = Range(5, 10).get_random_even_number();
  multiplicator_hammering_pairs = Range(2, 12).get_random_number();
  agg_inter_distance = Range(1, 16).get_random_number();
  agg_intra_distance = Range(2, 2).get_random_number();

  // must always be >=2 because we use two NOPs for hammering synchronization
  num_nops = Range(2, 2).get_random_number();
  multiplicator_nops = Range(1, 22).get_random_number();

  agg_rounds = num_activations / (num_hammering_pairs * 2);
  auto hammer_rounds = Range(850000, 1150000).get_random_number();
  num_refresh_intervals = hammer_rounds / agg_rounds;

  printf("num_hammering_pairs: %d, ", num_hammering_pairs);
  printf("multiplicator_hammering_pairs: %d, ", multiplicator_hammering_pairs);
  printf("agg_inter_distance: %d, ", agg_inter_distance);
  printf("agg_intra_distance: %d, ", agg_intra_distance);
  printf("num_nops: %d, ", num_nops);
  printf("multiplicator_nops: %d, ", multiplicator_nops);
  printf("num_refresh_intervals: %d", num_refresh_intervals);
  printf(NONE "\n");
}

int PatternBuilder::get_total_duration_pi(int num_ref_intervals) { return num_ref_intervals * duration_full_refresh; }

// TODO: Measure how many accesses are possible in a given interval

void PatternBuilder::access_pattern() {
  printf("[+] Hammering using jitted code...\n");
  fn();
}

void PatternBuilder::cleanup_and_rerandomize() {
  rt.release(fn);
  aggressor_pairs.clear();
  nops.clear();
  randomize_parameters();
}

void PatternBuilder::get_random_indices(size_t max, size_t num_indices, std::vector<size_t>& indices) {
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

void PatternBuilder::jit_hammering_code(size_t agg_rounds, uint64_t hammering_intervals) {
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

  asmjit::x86::Gp dur;
  asmjit::x86::Gp intervals;
  if (ASMJIT_ARCH_BITS == 64) {
#if defined(_WIN32)
    intervals = x86::rcx;
#else
    intervals = asmjit::x86::rdi;  // 1st argument: the number of intervals
#endif
  } else {
    fprintf(stderr, "Code jitting not implemented for x86. Aborting.");
  }

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in blacksmith.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // access first two NOPs as part of synchronization
  if (nops.size() < 2) fprintf(stderr, "[-] Hammering requires at least 2 NOPs for synchronization.\n");
  std::vector<size_t> random_indices;
  get_random_indices(1, 2, random_indices);
  for (const auto& idx : random_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)nops[idx]);
    asmjit::x86::Mem m = asmjit::x86::ptr(asmjit::x86::rax);
    a.mov(asmjit::x86::rbx, m);
  }

  // while (true) { ...
  a.bind(while1_begin);
  // clflushopt both NOPs
  for (const auto& idx : random_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)nops[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();

  a.rdtscp();  // result of rdtscp is in [edx:eax]
  a.lfence();
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);

  // access both NOPs once
  for (const auto& idx : random_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)nops[idx]);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
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

  a.mov(asmjit::x86::rsi, hammering_intervals);

  // instead of "HAMMER_ROUNDS / ref_rounds" we use "intervals" which is an input parameter to this jitted function
  a.bind(for1_begin);
  // a.cmp(intervals, 0);
  a.cmp(asmjit::x86::rsi, 0);
  a.jz(for1_end);
  // a.dec(intervals);
  a.dec(asmjit::x86::rsi);

  // as agg_rounds is typically a relatively low number, we do not encode the loop in ASM but instead
  // unroll the instructions to avoid the additional jump the loop would cause

  // hammering loop: for (int j = 0; j < agg_rounds; j++) { ... }
  for (size_t i = 0; i < agg_rounds; i++) {
    for (size_t i = 0; i < aggressor_pairs.size(); i++) {
      a.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
      a.mov(asmjit::x86::rbx, asmjit::x86::ptr(asmjit::x86::rax));
    }
    for (size_t i = 0; i < aggressor_pairs.size(); i++) {
      a.mov(asmjit::x86::rax, aggressor_pairs[i]);
      a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }
    a.mfence();
  }

  // loop for synchronization after hammering: while (true) { ... }
  a.bind(while2_begin);
  // clflushopt both NOPs
  for (const auto& idx : random_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)nops[idx]);
    a.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }
  a.mfence();
  a.lfence();

  a.rdtscp();  // result of rdtscp is in [edx:eax]
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);
  a.lfence();

  // access both NOPs once
  for (const auto& idx : random_indices) {
    a.mov(asmjit::x86::rax, (uint64_t)nops[idx]);
    a.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
  }

  a.rdtscp();  // result: edx:eax
  a.lfence();
  // if ((after - before) > 1000) break;
  a.sub(asmjit::x86::eax, asmjit::x86::ebx);
  a.cmp(asmjit::x86::eax, (uint64_t)1000);

  // depending on the cmp's outcome, jump out of loop or to the loop's beginning
  a.jg(while2_end);
  a.jmp(while2_begin);

  a.bind(while2_end);
  a.jmp(for1_begin);

  a.bind(for1_end);
  // ! This RET statement at the end is ESSENTIAL otherwise execution of jitted code creates segfault
  a.ret();

  // add the generated code to the runtime.
  asmjit::Error err = rt.add(&fn, &code);
  if (err) throw std::runtime_error("[-] Error occurred when trying to jit code. Aborting execution!");

  // uncomment the following line to see the jitted ASM code
  // printf("[DEBUG] asmjit logger content:\n%s\n", logger->data());
}

std::pair<volatile char*, volatile char*> PatternBuilder::generate_random_pattern(
    volatile char* target, std::vector<uint64_t> bank_rank_masks[], std::vector<uint64_t>& bank_rank_functions,
    u_int64_t row_function, u_int64_t row_increment, int num_activations, int bank_no) {
  
  // === utility functions ===========
  // a wrapper around normalize_addr_to_bank that eliminates the need to pass the two last parameters
  auto normalize_address = [&](volatile char* address) {
    return normalize_addr_to_bank(address, bank_rank_masks[bank_no], bank_rank_functions);
  };
  // a wrapper for the logic required to get an address to hammer (or dummy)
  auto get_address = [&](volatile char* cur_next_addr, std::vector<int> offsets,
                         std::vector<volatile char*>& addresses) -> volatile char* {
    for (const auto& val : offsets) {
      cur_next_addr = normalize_address(cur_next_addr + (val * row_increment));
      printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
      addresses.push_back(cur_next_addr);
    }
    return cur_next_addr;
  };
  // ==================================

  // sanity check
  if (aggressor_pairs.size() > 0 || nops.size() > 0) {
    fprintf(stderr, "[-] Cannot generate new pattern without prior cleanup. Call cleanup_and_rerandomize before.\n");
    exit(1);
  }

  printf("[+] Generating a random hammering pattern.\n");

  // const int accesses_per_pattern = 100;  // TODO: make this a parameter
  // auto get_remaining_accesses = [&](size_t num_cur_accesses) -> int { return accesses_per_pattern - num_cur_accesses; };
  auto cur_start_addr = target + MB(100) + (((rand() % (MEM_SIZE - MB(200)))) / PAGE_SIZE) * PAGE_SIZE;

  // TODO: build sets of aggressors
  std::unordered_set<volatile char*> aggressors;
  printf("[+] Start address: %p\n", cur_start_addr);
  aggressor_pairs.clear();
  nops.clear();

  cur_start_addr = normalize_address(cur_start_addr);
  volatile char* cur_next_addr = cur_start_addr;
  printf("[+] Agg rows: ");
  for (int i = 0; i < num_hammering_pairs; i++) {
    cur_next_addr = get_address(cur_next_addr, {agg_inter_distance, agg_intra_distance}, aggressor_pairs);
  }
  printf("\n");

  // TODO: build sets of NOPs
  std::vector<int> nop_offsets = {100, agg_intra_distance};
  printf("[+] NOP rows: ");
  for (int i = 0; i < num_nops; i++) {
    cur_next_addr = get_address(cur_next_addr, {nop_offsets.at(i % nop_offsets.size())}, nops);
  }
  printf("\n");

  // TODO: Add fuzzing logic (from bottom) that determines which of the addresses in aggressors and NOPs are accessed

  jit_hammering_code(agg_rounds, num_refresh_intervals);

  return std::make_pair(aggressor_pairs.front(), aggressor_pairs.back());

  // // generate pattern and generate jitted code
  // // consider that we need to insert clflush before accessing an address again
  // int accesses_counter = 0;
  // auto get_remaining_accesses = [&]() -> int { return accesses_per_pattern - accesses_counter; };
  // while (accesses_counter < accesses_per_pattern) {
  //   auto selection = rand() % 2;
  //   if (selection % 2 == 0) {
  //     // use a randomly picked hammering pair
  //     volatile char* pair = *select_randomly(aggressor_pairs.begin(), aggressor_pairs.end());

  //     std::stringstream result;
  //     int multiplicator = multiplicator_hammering_pairs.get_random_number(get_remaining_accesses() / 2);
  //     if (multiplicator == -1) {
  //       std::cout << "[-] Skipping choice and rolling the dice again." << std::endl;
  //       continue;
  //     }
  //     accesses_counter += 2 * multiplicator;
  //     while (multiplicator--) {
  //       result << pair;
  //       result << " ";
  //     }
  //     // result.seekp(-1, std::ios_base::end);
  //     // result << "|";
  //     patterns[i].push_back(result.str());
  //   } else if (selection % 2 == 1) {
  //     // use a randomly picked nop
  //     std::string pair = *select_randomly(Ns.begin(), Ns.end());

  //     std::stringstream result;
  //     int multiplicator = multiplicator_nops.get_random_number(get_remaining_accesses());
  //     if (multiplicator == -1) {
  //       std::cout << "[-] Skipping choice and rolling the dice again." << std::endl;
  //       continue;
  //     }
  //     accesses_counter += multiplicator;
  //     while (multiplicator--) {
  //       result << pair;
  //       result << " ";
  //     }
  //     // result << "|";
  //     // result.seekp(-1, std::ios_base::end);
  //     patterns[i].push_back(result.str());
  //   }
  // }
}
