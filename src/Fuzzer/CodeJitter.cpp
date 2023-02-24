#include <iostream>
#include <ctime>

#include "Fuzzer/CodeJitter.hpp"
#include "Utilities/AsmPrimitives.hpp"

#define MEASURE_TIME (1)

CodeJitter::CodeJitter()
    : flushing_strategy(FLUSHING_STRATEGY::EARLIEST_POSSIBLE),
      fencing_strategy(FENCING_STRATEGY::LATEST_POSSIBLE),
      total_activations(5000000) {
#ifdef ENABLE_JITTING
  logger = new asmjit::StringLogger;
#endif
}

CodeJitter::~CodeJitter() {
  cleanup();
}

void CodeJitter::cleanup() {
#ifdef ENABLE_JITTING
  if (fn!=nullptr) {
    runtime.release(fn);
    fn = nullptr;
  }
  if (logger!=nullptr) {
    delete logger;
    logger = nullptr;
  }
#endif
}

size_t CodeJitter::hammer_pattern(FuzzingParameterSet &fuzzing_parameters, bool verbose) {
  if (fn==nullptr) {
    Logger::log_error("Skipping hammering pattern as pattern could not be created successfully.");
    return -1;
  }
  if (verbose) Logger::log_info("Hammering the last generated pattern.");

  assert(fn != nullptr && "jitting hammering code failed!");
  size_t total_sync_acts = 0;
//  total_sync_acts = fn();
  while (true) {
    (void)fn();
  }

  if (verbose) {
    Logger::log_data(format_string("#sync_acts: %d", total_sync_acts));
    const auto total_acts_pattern = fuzzing_parameters.get_total_acts_pattern();
    const auto pattern_rounds = fuzzing_parameters.get_hammering_total_num_activations()/total_acts_pattern;
    // as we sync after each pattern execution, #pattern reps equals to #synced REFs
    Logger::log_data(format_string("#pattern_reps/syncs: %d", pattern_rounds));
    Logger::log_data(format_string("avg_acts_per_sync: %d", total_sync_acts/pattern_rounds));
  }

  return total_sync_acts;
}

size_t CodeJitter::get_next_sync_rows_idx() {
  return sync_rows_idx++%(sync_rows_size-1);
};

void CodeJitter::jit_strict(FLUSHING_STRATEGY flushing,
                            FENCING_STRATEGY fencing,
                            int total_num_activations,
                            const std::vector<volatile char *> &aggressor_pairs,
                            const std::vector<volatile char *> &sync_rows) {
#if (DEBUG==1)
  bool bit_flip_injected = false;
#endif
  sync_rows_idx = 0;
  sync_rows_size = sync_rows.size();

//  Logger::log_debug(format_string("sync_rows_size: %ld", sync_rows_size));
//  for (const auto &sr : sync_rows) {
//    Logger::log_data(format_string("%p", sr));
//  }
//  Logger::log_debug(format_string("aggressor_pairs_size: %ld", aggressor_pairs.size()));
//  for (const auto &agg : aggressor_pairs) {
//    Logger::log_data(format_string("%p", agg));
//  }

  // this is used by hammer_pattern but only for some stats calculations
  this->flushing_strategy = flushing;
  this->fencing_strategy = fencing;
  this->total_activations = total_num_activations;

  //  we need to distinguish between how many rows we use for syncing (always 2) and the number of different rows we
  //  use in total across all synchronizations (e.g., 64)
  const size_t NUM_TIMED_ACCESSES = 2;

  // some sanity checks
  if (fn != nullptr) {
    Logger::log_error(
        "Function pointer is not NULL, cannot continue jitting code without leaking memory. "
        "Did you forget to call cleanup() before?");
    exit(EXIT_FAILURE);
  }

#ifdef ENABLE_JITTING
  asmjit::CodeHolder code;
  code.init(runtime.environment());
#if (DEBUG==1)
  code.setLogger(logger);
#endif
  asmjit::x86::Assembler assembler(&code);

  asmjit::Label while1_begin = assembler.newLabel();
  asmjit::Label while1_end = assembler.newLabel();
  asmjit::Label for_begin = assembler.newLabel();
  asmjit::Label for_end = assembler.newLabel();

  // ==== here start's the actual program ====================================================
  // The following JIT instructions are based on hammer_sync in blacksmith.cpp, git commit 624a6492.

  // ------- part 1: synchronize with the beginning of an interval ---------------------------

  // warmup: access all sync rows once
//  for (size_t idx = 0; idx < sync_rows_size; idx++) {
//    a.mov(asmjit::x86::rax, (uint64_t) sync_rows[idx]);
//    a.mov(asmjit::x86::rbx, asmjit::x86::ptr(asmjit::x86::rax));
//  }

  assembler.bind(while1_begin);
  // clflushopt all sync rows
  for (size_t idx = 0; idx < sync_rows_size; idx++) {
    assembler.mov(asmjit::x86::rax, (uint64_t) sync_rows[idx]);
    assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
  }

  // no fence needed here, there is enough time until we are accessing all sync rows again
//  a.mfence();

  // retrieve timestamp
  assembler.rdtscp();  // result of rdtscp is in [edx:eax]
  assembler.lfence();
  assembler.mov(asmjit::x86::ebx, asmjit::x86::eax);  // discard upper 32 bits, store lower 32b in ebx for later

  // use first NUM_TIMED_ACCESSES addresses for sync
  for (size_t iteration_cnt = 0; iteration_cnt < NUM_TIMED_ACCESSES; iteration_cnt++) {
    assembler.mov(asmjit::x86::rax, (uint64_t) sync_rows[get_next_sync_rows_idx()]);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
  }

  // if ((after - before) > REFRESH_THRESHOLD_CYCLES) break;
  assembler.lfence();
  assembler.rdtscp();  // result: edx:eax
  assembler.sub(asmjit::x86::eax, asmjit::x86::ebx);
  assembler.cmp(asmjit::x86::eax, (uint64_t) REFRESH_THRESHOLD_CYCLES_LOW);

  // depending on the cmp's outcome, jump out of loop or to the loop's beginning
  assembler.jg(while1_end);
  assembler.jmp(while1_begin);
  assembler.bind(while1_end);

  // ------- part 2: perform hammering ---------------------------------------------------------------------------------

  // initialize variables
  assembler.mov(asmjit::x86::rsi, total_num_activations);
  assembler.mov(asmjit::x86::edx, 0);  // num activations counter

  assembler.bind(for_begin);
  assembler.cmp(asmjit::x86::rsi, 0);
  assembler.jle(for_end);

  // a map to keep track of aggressors that have been accessed before and need a fence before their next access
  std::unordered_map<uint64_t, bool> accessed_before;

  // hammer each aggressor once
  for (size_t i = 0; i < aggressor_pairs.size(); i++) {
    auto cur_addr = (uint64_t) aggressor_pairs[i];

    bool cur_addr_in_rax = false;
    if (accessed_before[cur_addr]) {
      // flush
      if (flushing==FLUSHING_STRATEGY::LATEST_POSSIBLE) {
        assembler.mov(asmjit::x86::rax, cur_addr);
        cur_addr_in_rax = true;
        assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
        accessed_before[cur_addr] = false;
      }
      // fence to ensure flushing finished and defined order of aggressors is guaranteed
      if (fencing==FENCING_STRATEGY::LATEST_POSSIBLE) {
        assembler.mfence();
        accessed_before[cur_addr] = false;
      }
    }

    // hammer
    if (not cur_addr_in_rax)
      assembler.mov(asmjit::x86::rax, cur_addr);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));
    accessed_before[cur_addr] = true;


#if (DEBUG==1)
    if (false && !bit_flip_injected) {
      Logger::log_debug(format_string("intentionally injecting bug into address %p to check bit flip detection!", (void*)cur_addr));
      assembler.mov(asmjit::x86::dword_ptr(asmjit::x86::rax), 0x5);
      bit_flip_injected = true;
      assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
      // this works: *(int*)aggressor_pairs[i] = 0x4;
    }
#endif
    assembler.dec(asmjit::x86::rsi);

    // flush after a single aggressor has been hammered
    if (flushing==FLUSHING_STRATEGY::EARLIEST_POSSIBLE) {
      assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }

  } // end of the hammering loop

  // flush after finishing hammering all aggressor rows
  if (flushing==FLUSHING_STRATEGY::BATCHED) {
    for (size_t i = 0; i < aggressor_pairs.size(); i++) {
      assembler.mov(asmjit::x86::rax, (uint64_t)aggressor_pairs[i]);
      assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));
    }
  }

  // fences -> ensure that aggressors are not interleaved, i.e., we access aggressors always in same order
  assembler.mfence();

  // ------- part 3: synchronize with the end  -----------------------------------------------------------------------
  sync_ref(sync_rows, assembler, NUM_TIMED_ACCESSES);

  assembler.jmp(for_begin);
  assembler.bind(for_end);

  // now move our counter for no. of activations in the end of interval sync. to the 1st output register %eax
  assembler.mov(asmjit::x86::eax, asmjit::x86::edx);
  assembler.ret();  // this is ESSENTIAL otherwise execution of jitted code creates a segfault

  // add the generated code to the runtime.
  asmjit::Error err = runtime.add(&fn, &code);
  if (err) {
    throw std::runtime_error("[-] Error occurred while jitting code. Aborting execution!");
  }
#if (DEBUG==1)
//   uncomment the following line to see the jitted ASM code
  if (logger != nullptr) {
    printf("[DEBUG] asmjit logger content:\n%s\n", logger->_content.data());
    exit(0);
  }
#endif
#else
  Logger::log_error("Cannot do code jitting. Set option ENABLE_JITTING to ON in CMakeLists.txt and do a rebuild.");
#endif
}

[[maybe_unused]] void CodeJitter::wait_for_user_input() {
  // TODO: move this into a helper class
  do {
    std::cout << '\n' << "Are you sure you want to hammer innocent rows? "
                         "Press any key to continue..." << std::endl;
  } while (std::cin.get() != '\n');
}

#pragma GCC push_options
#pragma GCC optimize ("unroll-loops")
void CodeJitter::sync_ref_unjitted(const std::vector<volatile char *> &sync_rows,
                                   int num_acts_per_trefi,
                                   synchronization_stats &sync_stats,
                                   size_t ref_threshold) const {
  const size_t sync_rows_max = sync_rows.size();
  const size_t sync_cnt_max = num_acts_per_trefi;

  size_t sync_cnt = 0;
  size_t sync_idx = 0;

  uint64_t before;
  uint64_t ts_diff;

  uint64_t after = rdtscp();
  // make sure rdtscp finished before we start with the loop
  lfence();
  do {
    // the last 'after' value becomes the new 'before' value
    before = after;
    // one address is from (same bg, diff bk) and the other is from (diff bg, same bk)
    // relative to the addresses that we are hammering
    *sync_rows[sync_idx];
    *sync_rows[sync_idx + 1];
    lfence();
    after = rdtscp();
    ts_diff = after - before;
    clflushopt(sync_rows[sync_idx]);
    clflushopt(sync_rows[sync_idx + 1]);
    // no need to (m|s)fence as there's enough time until we access the same sync_idx again
    sync_idx = (sync_idx + 2) % sync_rows_max;
  } while (++sync_cnt < sync_cnt_max && ts_diff < ref_threshold);
//      && (ts_diff < REFRESH_THRESHOLD_CYCLES_LOW || ts_diff > REFRESH_THRESHOLD_CYCLES_HIGH));

  // take sync_cnt times 2 because we do two accesses each time
  sync_stats.num_sync_acts += sync_cnt*2;
}
#pragma GCC pop_options

#pragma GCC push_options
#pragma GCC optimize ("unroll-loops")
void CodeJitter::hammer_pattern_unjitted(FuzzingParameterSet &fuzzing_parameters,
                                         bool verbose,
                                         FLUSHING_STRATEGY flushing,
                                         FENCING_STRATEGY fencing,
                                         int total_num_activations,
                                         const std::vector<volatile char *> &aggressor_pairs,
                                         const std::vector<volatile char *> &sync_rows,
                                         size_t ref_threshold) {

  if (verbose) {
    Logger::log_debug("CodeJitter::hammer_pattern_unjitted stats:");
    Logger::log_data(format_string("#aggressor pairs: %lu", aggressor_pairs.size()));
    Logger::log_data(format_string("#sync rows: %lu", sync_rows.size()));
    Logger::log_data(format_string("num_acts_per_trefi: %d\n", fuzzing_parameters.get_num_activations_per_t_refi()));
  }

  if (flushing != FLUSHING_STRATEGY::BATCHED)
    throw std::runtime_error("[-] FLUSHING_STRATEGY must be BATCHED");
  if (fencing!= FENCING_STRATEGY::LATEST_POSSIBLE)
    throw std::runtime_error(" [-] FENCING_STRATEGY must be LATEST_POSSIBLE");

  // flush all sync rows but keep array holding addresses cached
  for (size_t i = 0; i < sync_rows.size(); ++i) {
    *sync_rows[i];
    clflushopt(sync_rows[i]);
  }

  // flush all aggressor rows but keep array holding addresses cached
  for (size_t i = 0; i < aggressor_pairs.size(); ++i) {
    *aggressor_pairs[i];
    clflushopt(aggressor_pairs[i]);
    // validate pattern as we clflush only after every second aggressor, i.e.,
    // hammering consecutively the same aggressor is useless as it's causing a cache hit ayway
    if (aggressor_pairs[i] == aggressor_pairs[i + 1]) {
      Logger::log_error(format_string("unexpected: aggressor_pairs[i] == aggressor_pairs[i+1], skipping pattern..."));
      return;
    }
  }

  // make sure flushing finished before we start
  mfence();

  const int num_acts_per_trefi = fuzzing_parameters.get_num_activations_per_t_refi();
  const size_t NUM_AGG_PAIRS = aggressor_pairs.size();

  FILE* logfile = fopen("logfile", "a");
  synchronization_stats sync_stats{.num_sync_acts = 0, .num_sync_rounds = 0};

  size_t agg_idx = 0;
  for (; total_num_activations > 0; agg_idx = (agg_idx+2)%NUM_AGG_PAIRS, total_num_activations -= 2) {
    // sync with every REF
    if (agg_idx % num_acts_per_trefi == 0) {
      // make sure that no hammering accesses overload with sync accesses
      lfence();
      // SYNC
      sync_ref_unjitted(sync_rows, num_acts_per_trefi, sync_stats, ref_threshold);
      sync_stats.num_sync_rounds = (sync_stats.num_sync_rounds+1);
    }
    // HAMMER
    *aggressor_pairs[agg_idx];
    *aggressor_pairs[agg_idx + 1];
    // FLUSH
    clflushopt(aggressor_pairs[agg_idx]);
    clflushopt(aggressor_pairs[agg_idx + 1]);
    // FENCE
    sfence();

    lfence();
  }

  fprintf(logfile, "%2d,%zu\n", num_acts_per_trefi, sync_stats.num_sync_acts/sync_stats.num_sync_rounds);
  fclose(logfile);
}
#pragma GCC pop_options

#ifdef ENABLE_JITTING
void CodeJitter::sync_ref(const std::vector<volatile char *> &sync_rows,
                          asmjit::x86::Assembler &assembler,
                          size_t num_timed_accesses) {
  asmjit::Label wbegin = assembler.newLabel();
  asmjit::Label wend = assembler.newLabel();

  assembler.bind(wbegin);

  assembler.push(asmjit::x86::edx);
  assembler.rdtscp();  // result of rdtscp is in [edx:eax]
//  assembler.lfence();
  // discard upper 32 bits and store lower 32 bits in ebx to compare later
  assembler.mov(asmjit::x86::ebx, asmjit::x86::eax);
  assembler.pop(asmjit::x86::edx);

  for (size_t i = 0; i < num_timed_accesses; i++) {
    assembler.mov(asmjit::x86::rax, (uint64_t) sync_rows[get_next_sync_rows_idx()]);
    assembler.mov(asmjit::x86::rcx, asmjit::x86::ptr(asmjit::x86::rax));  // access
    assembler.clflushopt(asmjit::x86::ptr(asmjit::x86::rax));  // flush
    // update counter that counts the number of ACTs in the trailing synchronization
    assembler.inc(asmjit::x86::edx);
  }

  assembler.lfence();
  assembler.push(asmjit::x86::edx);
  assembler.rdtscp();  // result: edx:eax
  assembler.pop(asmjit::x86::edx);

  // if ((after - before) > REFRESH_THRESHOLD_CYCLES) break;
  assembler.sub(asmjit::x86::eax, asmjit::x86::ebx);
  assembler.cmp(asmjit::x86::eax, (uint64_t) REFRESH_THRESHOLD_CYCLES_LOW);

  // depending on the cmp's outcome...
  assembler.jg(wend);     // ... jump out of the loop
  assembler.jmp(wbegin);  // ... or jump back to the loop's beginning
  assembler.bind(wend);
}
#endif

#ifdef ENABLE_JSON
void to_json(nlohmann::json &j, const CodeJitter &p) {
  j = {{"flushing_strategy", to_string(p.flushing_strategy)},
       {"fencing_strategy", to_string(p.fencing_strategy)},
       {"total_activations", p.total_activations},
  };
}
#endif

#ifdef ENABLE_JSON
void from_json(const nlohmann::json &j, CodeJitter &p) {
  from_string(j.at("flushing_strategy"), p.flushing_strategy);
  from_string(j.at("fencing_strategy"), p.fencing_strategy);
  j.at("total_activations").get_to(p.total_activations);
}
#endif
