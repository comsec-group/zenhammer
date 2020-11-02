#include "PatternBuilder.h"

#include <iomanip>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

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
      num_hammering_pairs(Range(13, 13)),
      num_nops(Range(2, 2)),  // must always be at least 2
      multiplicator_hammering_pairs(Range(2, 12)),
      multiplicator_nops(Range(1, 22)) {
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
  }
}

void PatternBuilder::access_pattern(int acts) {
  int ref_rounds = acts / aggressor_pairs.size();
  if (ref_rounds == 0) {
    printf("[-] Aborting because computed ref_rounds = 0 (activations: %d, #aggressor_pairs: %zu).\n", acts, aggressor_pairs.size());
    exit(1);
  }
  printf("[+] Hammering using jitted code (activations: %d, #aggressor_pairs: %zu)\n", acts, aggressor_pairs.size());
  fn(HAMMER_ROUNDS / ref_rounds);
}

void PatternBuilder::cleanup_pattern() {
  rt.release(fn);
}

void PatternBuilder::get_random_indices(int max, size_t num_indices, std::vector<size_t>& indices) {
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
  // determine fuzzy parameters randomly
  std::cout << "[+] Generating a random hammering pattern." << std::endl;
  int N_aggressor_pairs = num_hammering_pairs.get_random_number();
  int N_nop_addresses = num_nops.get_random_number();
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
  printf("[+] Start address: %p\n", cur_start_addr);
  aggressor_pairs.clear();
  nops.clear();
  int aggressor_rows_size = (rand() % (MAX_ROWS - 3)) + 3;

  cur_start_addr = normalize_addr_to_bank(cur_start_addr, bank_rank_masks[ba], bank_rank_functions);
  volatile char* cur_next_addr = cur_start_addr;
  printf("[+] Agg rows ");
  for (int i = 0; i < N_aggressor_pairs; i++) {
    cur_next_addr = normalize_addr_to_bank(cur_next_addr + (d * row_increment),
                                           bank_rank_masks[ba],
                                           bank_rank_functions);
    printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
    aggressor_pairs.push_back(cur_next_addr);
    aggressors.insert(cur_next_addr);
    cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                           bank_rank_masks[ba],
                                           bank_rank_functions);
    printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
    aggressor_pairs.push_back(cur_next_addr);
    aggressors.insert(cur_next_addr);
  }
  if ((aggressor_rows_size % 2)) {
    normalize_addr_to_bank(cur_next_addr + (d * row_increment), bank_rank_masks[ba], bank_rank_functions);
    printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
    aggressor_pairs.push_back(cur_next_addr);
    aggressors.insert(cur_next_addr);
  }
  printf("\n");

  // build sets of NOPs
  printf("[+] NOPs: ");
  // for (int i = 0; nops.size() < (unsigned long)N_nop_addresses; i++) {
  //   cur_next_addr = normalize_addr_to_bank(cur_next_addr + (100 * row_increment),
  //                                          bank_rank_masks[ba],
  //                                          bank_rank_functions);
  //   printf("    %" PRIu64 " (%p)\n", get_row_index(cur_next_addr, row_function), cur_next_addr);
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
  nops.push_back(cur_next_addr);
  printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
  cur_next_addr = normalize_addr_to_bank(cur_next_addr + (v * row_increment),
                                         bank_rank_masks[ba],
                                         bank_rank_functions);
  nops.push_back(cur_next_addr);
  printf("%" PRIu64 " ", get_row_index(cur_next_addr, row_function));
  printf("\n");

  size_t agg_rounds = num_activations / aggressor_pairs.size();

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
