#include "PatternBuilder.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>
#include <set>

#include "DramAnalyzer.h"
#include "GlobalDefines.h"
#include "utils.h"

std::ostream& operator<<(std::ostream& o, const FormattedNumber& a) {
  o.fill(a.fill);
  o.width(a.width);
  return o;
}

PatternBuilder::PatternBuilder()
    : num_refresh_intervals(Range(1, 8)),
      num_hammering_pairs(Range(12, 38)),
      num_nops(Range(2, 4)),  // must always be at least 2
      multiplicator_hammering_pairs(Range(2, 12)),
      multiplicator_nops(Range(1, 22)) {
  alphabeticus = new int(32);
}

int PatternBuilder::get_total_duration_pi(int num_ref_intervals) { return num_ref_intervals * duration_full_refresh; }

// TODO: Measure how many accesses are possible in a given interval

std::vector<std::string> gen_random_pairs(size_t N) {
  std::vector<std::string> all_pairs;
  while (all_pairs.size() < N) {
    int i = rand() % 98;
    std::stringstream ss;
    ss << "H_" << FormattedNumber() << i << " H_" << FormattedNumber() << i + 1;
    all_pairs.push_back(ss.str());
  }
  return all_pairs;
}

std::vector<std::string> gen_random_accesses(size_t N) {
  std::vector<std::string> all_accesses;
  while (all_accesses.size() < N) {
    int i = rand() % 98;
    std::stringstream ss;
    // expand the digits to always have two digits
    ss << "N_" << FormattedNumber() << i;
    all_accesses.push_back(ss.str());
  }
  return all_accesses;
}

void PatternBuilder::print_patterns(int num_patterns, int accesses_per_pattern) {
  std::cout << "Printing generated patterns..." << std::endl;

  std::vector<std::vector<std::string>> patterns(num_patterns, std::vector<std::string>());
  for (int i = 0; i < num_patterns; i++) {
    int H = num_hammering_pairs.get_random_number();
    std::cout << "[+] Selected random params: H = " << H << ", ";
    int N = num_nops.get_random_number();
    std::cout << "N = " << N << std::endl;

    std::vector<std::string> Hs = gen_random_pairs(H);
    std::vector<std::string> Ns = gen_random_accesses(N);
    std::cout << "[+] Generated random pairs (#Hs: " << Hs.size() << ", #Ns: " << Ns.size() << ")" << std::endl;

    int accesses_counter = 0;
    auto get_remaining_accesses = [&]() -> int { return accesses_per_pattern - accesses_counter; };
    while (accesses_counter < accesses_per_pattern) {
      auto selection = rand() % 2;
      if (selection % 2 == 0) {
        // use a randomly picked hammering pair
        std::string pair = *select_randomly(Hs.begin(), Hs.end());

        std::stringstream result;
        int multiplicator = multiplicator_hammering_pairs.get_random_number(get_remaining_accesses() / 2);
        if (multiplicator == -1) {
          std::cout << "[-] Skipping choice and rolling the dice again." << std::endl;
          continue;
        }
        accesses_counter += 2 * multiplicator;
        while (multiplicator--) {
          result << pair;
          result << " ";
        }
        // result.seekp(-1, std::ios_base::end);
        // result << "|";
        patterns[i].push_back(result.str());
      } else if (selection % 2 == 1) {
        // use a randomly picked nop
        std::string pair = *select_randomly(Ns.begin(), Ns.end());

        std::stringstream result;
        int multiplicator = multiplicator_nops.get_random_number(get_remaining_accesses());
        if (multiplicator == -1) {
          std::cout << "[-] Skipping choice and rolling the dice again." << std::endl;
          continue;
        }
        accesses_counter += multiplicator;
        while (multiplicator--) {
          result << pair;
          result << " ";
        }
        // result << "|";
        // result.seekp(-1, std::ios_base::end);
        patterns[i].push_back(result.str());
      }
    }

    // print the recently generated pattern
    std::ostringstream vts;
    // Convert all but the last element to avoid a trailing ","
    std::copy(patterns[i].begin(), patterns[i].end() - 1, std::ostream_iterator<std::string>(vts, ""));
    vts << patterns[i].back();
    std::cout << "[+] Generated pattern (" << accesses_counter << "):\t\t\t\t" << vts.str() << std::endl;

    // TODO: determine how long the pattern should be, i.e., how many accesses
    //  by printing stats from n_sided_hammer
  }
}

// void PatternBuilder::get_access_pattern() {
//   asmjit::CodeHolder code;      // Holds code and relocation information.
//   code.init(rt.environment());  // Initialize CodeHolder to match JIT environment.

//   asmjit::x86::Assembler a(&code);  // Create and attach x86::Assembler to `code`.
//   a.mov(asmjit::x86::eax, 1);       // Move one to 'eax' register.
//   a.ret();                          // Return from function.
//   // ----> x86::Assembler is no longer needed from here and can be destroyed <----

//   asmjit::Error err = rt.add(&fn, &code);  // Add the generated code to the runtime.
//   if (err) {
//     throw std::runtime_error("[-] Error occurred when trying to jit code. Aborting execution!");
//   }
//   // ----> CodeHolder is no longer needed from here and can be destroyed <----

//   int result = fn();       // Execute the generated code.
//   printf("%d\n", result);  // Print the resulting "1".
// }

void PatternBuilder::access_pattern() {
  std::cout << "[+] Hammering... " << std::endl;

  printf("access_pattern: d1 = %p, d2 = %p\n", d1, d2);
  fflush(stdout);

  int ref_rounds = activations / aggressor_pairs.size();
  if (ref_rounds == 0) {
    printf("[-] Aborting because computed ref_rounds = 0 (activations: %d, #aggressor_pairs: %zu).\n", activations, aggressor_pairs.size());
    exit(1);
  } else {
    printf("[+] Running with activations: %d, #aggressor_pairs: %zu.\n", activations, aggressor_pairs.size());
  }


  printf("Running jitted code...");
  fflush(stdout);
  fn(HAMMER_ROUNDS / ref_rounds);
  printf(" done!\n");
  return;

  // int agg_rounds = ref_rounds;
  // uint64_t before = 0;
  // uint64_t after = 0;

  // *d1;
  // *d2;

  // // synchronize with the beginning of an interval
  // while (true) {
  //   clflushopt(d1);
  //   clflushopt(d2);
  //   mfence();
  //   before = rdtscp();
  //   lfence();
  //   *d1;
  //   *d2;
  //   after = rdtscp();
  //   // check if an ACTIVATE was issued
  //   if ((after - before) > 1000) {
  //     break;
  //   }
  // }

  // // perform hammering for HAMMER_ROUNDS/ref_rounds times
  // for (int i = 0; i < HAMMER_ROUNDS / ref_rounds; i++) {
  //   for (int j = 0; j < agg_rounds; j++) {
  //     // fn();
  //     for (auto& a : aggressor_pairs) {
  //       *a;
  //     }
  //     for (auto& a : aggressor_pairs) {
  //       clflushopt(a);
  //     }
  //     mfence();
  //   }

  //   // after HAMMER_ROUNDS/ref_rounds times hammering, check for next ACTIVATE
  //   while (true) {
  //     clflushopt(d1);
  //     clflushopt(d2);
  //     mfence();
  //     lfence();
  //     before = rdtscp();
  //     lfence();
  //     *d1;
  //     *d2;
  //     after = rdtscp();
  //     lfence();
  //     // stop if an ACTIVATE was issued
  //     if ((after - before) > 1000) break;
  //   }
  // }
}

void PatternBuilder::cleanup_pattern() {
  std::cout << "[+] Cleaning up jitted function." << std::endl;
  rt.release(fn);
}

void PatternBuilder::get_random_indices(int max, size_t num_indices, std::vector<size_t> &indices) {
  std::set<size_t> nums;
  while (nums.size() < num_indices) {
    int candidate = rand() % max;
    if (nums.count(candidate) > 0) continue;
    nums.insert(candidate);
  }
  indices.insert(indices.end(), nums.begin(), nums.end());
}

void PatternBuilder::generate_random_pattern(volatile char* target, std::vector<uint64_t> bank_rank_masks[],
                                             std::vector<uint64_t>& bank_rank_functions, u_int64_t row_function,
                                             u_int64_t row_increment, int num_activations, int ba) {
  std::cout << "[+] Generating a random hammering pattern..." << std::endl;

  activations = num_activations;

  // determine fuzzy parameters randomly
  int N_aggressor_pairs = num_hammering_pairs.get_random_number();  // TODO: Make this random again
  N_aggressor_pairs = 13;
  int N_nop_addresses = num_nops.get_random_number();  // TODO: Make this random again
  N_nop_addresses = 2;
  printf("[+] Selected fuzzing params: #aggressor_pairs = %d, #nop_addrs = %d\n", N_aggressor_pairs, N_nop_addresses);

  // const int accesses_per_pattern = 100;  // TODO: make this a parameter
  // auto get_remaining_accesses = [&](size_t num_cur_accesses) -> int { return accesses_per_pattern - num_cur_accesses; };

  // build sets of aggressors
  std::unordered_set<volatile char*> aggressors;
  // int aggressor_rows_size = (rand() % (MAX_ROWS - 3)) + 3;
  int d = (rand() % 16);  // inter-distance between aggressor pairs
  // int ba = rand() % 4;    // bank
  int v = 2;  // intra-distance between aggressors
  // skip the first and last 100MB (just for convenience to avoid hammering on non-existing/illegal locations)
  auto cur_start_addr = target + MB(100) + (((rand() % (MEM_SIZE - MB(200)))) / PAGE_SIZE) * PAGE_SIZE;
  printf("[+] Using start address: %p\n", cur_start_addr);
  aggressor_pairs.clear();
  nops.clear();
  int aggressor_rows_size = (rand() % (MAX_ROWS - 3)) + 3;

  cur_start_addr = normalize_addr_to_bank(cur_start_addr, bank_rank_masks[ba], bank_rank_functions);
  volatile char* cur_next_addr = cur_start_addr;

  for (int i = 0; i < N_aggressor_pairs; i++) {
    cur_next_addr = normalize_addr_to_bank(cur_next_addr + (d * row_increment),
                                           bank_rank_masks[ba],
                                           bank_rank_functions);
    // printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
    aggressor_pairs.push_back(cur_next_addr);
    aggressors.insert(cur_next_addr);
    cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                           bank_rank_masks[ba],
                                           bank_rank_functions);
    // printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
    aggressor_pairs.push_back(cur_next_addr);
    aggressors.insert(cur_next_addr);
  }
  if ((aggressor_rows_size % 2)) {
    // ? Is this correct: Why don't we use the return value?
    normalize_addr_to_bank(cur_next_addr + (d * row_increment), bank_rank_masks[ba], bank_rank_functions);
    // printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
    aggressor_pairs.push_back(cur_next_addr);
    aggressors.insert(cur_next_addr);
  }
  printf("[+] Generated %zu random aggressor pairs.\n", aggressor_pairs.size() / 2);

  // build sets of NOPs
  printf("[+] NOPs to be added in row (address) format:\n");
  // for (int i = 0; nops.size() < (unsigned long)N_nop_addresses; i++) {
  //   cur_next_addr = normalize_addr_to_bank(cur_next_addr + (100 * row_increment),
  //                                          bank_rank_masks[ba],
  //                                          bank_rank_functions);
  //   printf("\t%" PRIu64 " (%p)\n", get_row_index(cur_next_addr, row_function), cur_next_addr);
  //   // make sure that NOP access is not an aggressor
  //   if (aggressors.count(cur_next_addr) == 0) {
  //     printf("[+] d row %" PRIu64 "\n", get_row_index(d1, row_function));
  //     nops.push_back(cur_next_addr);
  //     if (d1 == nullptr)
  //       d1 = cur_next_addr;
  //     else if (d2 == nullptr)
  //       d2 = cur_next_addr;
  //     printf("d1: %p, d2: %p\n", d1, d2);
  //   }
  // }
  cur_next_addr = normalize_addr_to_bank(cur_next_addr + (100 * row_increment),
                                         bank_rank_masks[ba],
                                         bank_rank_functions);
  d1 = cur_next_addr;
  nops.push_back(d1);
  cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                         bank_rank_masks[ba],
                                         bank_rank_functions);
  d2 = cur_next_addr;
  nops.push_back(d2);
  printf("[+] Generated %zu random NOPs accesses.\n", nops.size());

  size_t agg_rounds = activations / aggressor_pairs.size();

  // TODO: Generate a known (fix) pattern that is known to be working
  logger = new asmjit::StringLogger;  // Logger should always survive CodeHolder.
  asmjit::CodeHolder code;            // Holds code and relocation information.
  code.init(rt.environment());        // Initialize CodeHolder to match JIT environment.
  code.setLogger(logger);             // Attach the `logger` to `code` holder.
  asmjit::x86::Assembler a(&code);    // Create and attach x86::Assembler to `code`.

  asmjit::Label while1_begin = a.newLabel();
  asmjit::Label while1_end = a.newLabel();
  asmjit::Label for1_begin = a.newLabel();
  asmjit::Label for1_end = a.newLabel();
  asmjit::Label while2_begin = a.newLabel();
  asmjit::Label while2_end = a.newLabel();

  // TODO: pass HAMMER_ROUNDS / (acts / aggressors.size()) as first parameter
  asmjit::x86::Gp intervals;
  if (ASMJIT_ARCH_BITS == 64) {
#if defined(_WIN32)
    fprintf(stderr, "Code jitting not implemented for Windows on x64. Aborting.");
#else
    intervals = asmjit::x86::rdi;  // 1st argument: the number of intervals
#endif
  } else {
    fprintf(stderr, "Code jitting not implemented for x86. Aborting.");
  }

  // here start's the actual program (see hammer_sync for the plaintext version) ------------------------------------

  // Synchronize with the beginning of an interval. The following asmjit code performs exactly the following:
  //    while (true) {
  //      clflushopt(d1);
  //      clflushopt(d2);
  //      mfence();
  //      before = rdtscp();
  //      lfence();
  //      *d1;
  //      *d2;
  //      after = rdtscp();
  //      if ((after - before) > 1000) break;
  //    }

  // access two (random) NOPs as part of synchronization  
  std::vector<size_t> random_indices = {0, 1};
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
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  a.mov(asmjit::x86::ebx, asmjit::x86::eax);

  a.lfence();

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

  // ----------

  a.bind(for1_begin);

  // while (intervals) { ... }
  a.cmp(intervals, 0);
  a.jz(for1_end);
  a.dec(intervals);

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

  // while (true) { ...
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
  a.ret();  // ! The return statement at the end of the jitted code is ESSENTIAL!

  asmjit::Error err = rt.add(&fn, &code);  // Add the generated code to the runtime.
  if (err) {
    throw std::runtime_error("[-] Error occurred when trying to jit code. Aborting execution!");
  }

  // printf("[D] asmjit logger content:\n%s\n", logger->data());
  // fflush(stdout);
  // exit(0);

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

void PatternBuilder::print_pattern() {
  std::cout << "[+] Generated pattern: " << std::endl;
}
