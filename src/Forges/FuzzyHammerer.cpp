#include "Forges/FuzzyHammerer.hpp"

#include <unordered_set>
#include <complex>

#include "Utilities/TimeHelper.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/CodeJitter.hpp"

size_t FuzzyHammerer::cnt_pattern_probes = 0UL;
HammeringPattern FuzzyHammerer::hammering_pattern = HammeringPattern(); /* NOLINT */

void FuzzyHammerer::n_sided_frequency_based_hammering(Memory &memory,
                                                      int acts,
                                                      long runtime_limit,
                                                      const size_t probes_per_pattern) {
  Logger::log_info("Starting frequency-based hammering.");

  // the number of successful hammering probes (note: if a pattern works on different locations, we increase this
  // counter once for each successful location)
  size_t num_successful_probes = 0;

  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

  std::random_device rd;
  std::mt19937 gen(rd());

#ifdef ENABLE_JSON
  nlohmann::json arr = nlohmann::json::array();
#endif

  long execution_time_limit = get_timestamp_sec() + runtime_limit;

  int cur_round = 0;
  while (get_timestamp_sec() < execution_time_limit) {
    cur_round++;

    Logger::log_timestamp();
    Logger::log_highlight(format_string("Generating hammering pattern #%d.", cur_round));
    fuzzing_params.randomize_parameters(true);

    // generate a hammering pattern: this is like a general access pattern template without concrete addresses
    FuzzyHammerer::hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
    PatternBuilder pattern_builder(hammering_pattern);
    pattern_builder.generate_frequency_based_pattern(fuzzing_params);

    // randomize the order of AggressorAccessPatterns to avoid biasing the PatternAddressMapper as it always assigns
    // rows in order of the AggressorAccessPatterns map
    // (e.g., the first element in AggressorAccessPatterns is assigned to the lowest DRAM row).
    std::shuffle(hammering_pattern.agg_access_patterns.begin(),
                 hammering_pattern.agg_access_patterns.end(),
                 gen);

    // then test this pattern with N different address sets
    while (cnt_pattern_probes++ < probes_per_pattern) {
      // choose random addresses for pattern
      PatternAddressMapper mapper;
      CodeJitter &code_jitter = mapper.get_code_jitter();

      Logger::log_info(format_string("Running pattern #%d (%s) for address set %d (%s).",
          cur_round,
          hammering_pattern.instance_id.c_str(),
          cnt_pattern_probes,
          mapper.get_instance_id().c_str()));

      // randomize the aggressor ID -> DRAM row mapping
      mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns);

      // now fill the pattern with these random addresses
      std::vector<volatile char *> hammering_accesses_vec;
      mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, hammering_accesses_vec);
      Logger::log_info("Aggressor ID to DRAM address mapping (bank, rank, column):");
      Logger::log_data(mapper.get_mapping_text_repr());

      // now create instructions that follow this pattern (i.e., do jitting of code)
      bool sync_at_each_ref = fuzzing_params.get_random_sync_each_ref();
      int num_aggs_for_sync = fuzzing_params.get_random_num_aggressors_for_sync();
      Logger::log_info("Creating ASM code for hammering.");
      code_jitter.jit_strict(fuzzing_params,
          FLUSHING_STRATEGY::EARLIEST_POSSIBLE,
          FENCING_STRATEGY::LATEST_POSSIBLE,
          hammering_accesses_vec,
          sync_at_each_ref,
          num_aggs_for_sync,
          fuzzing_params.get_hammering_total_num_activations());

      // wait for a random time before starting to hammer, while waiting access random rows that are not part of the
      // currently hammering pattern; this wait interval serves for two purposes: to reset the sampler and start from a
      // clean state before hammering, and also to fuzz a possible dependence at which REF we start hammering
      auto wait_until_hammering_us = fuzzing_params.get_random_wait_until_start_hammering_microseconds();
      FuzzingParameterSet::print_dynamic_parameters2(sync_at_each_ref, wait_until_hammering_us, num_aggs_for_sync);
      std::vector<volatile char *> random_rows;
      if (wait_until_hammering_us > 0) {
        random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
        do_random_accesses(random_rows, wait_until_hammering_us);
      }

      // TODO: Integrate and test REPS_PER_PATTERN

#ifdef DEBUG_SAMSUNG
      const int reproducibility_rounds = 20;
#else
      const int reproducibility_rounds = 150;
#endif
      int cur_reproducibility_round = 1;
      int reproducibility_rounds_with_bitflips = 0;
      bool reproducibility_mode = false;
      std::stringstream ss;
      do {
        // do hammering
        code_jitter.hammer_pattern(fuzzing_params, !reproducibility_mode);

        // check if any bit flips happened
        auto flipped_bits = memory.check_memory(mapper, reproducibility_mode, !reproducibility_mode);
        if (flipped_bits > 0) reproducibility_rounds_with_bitflips++;

        // this if/else block is only executed in the very first round: it decides whether to start the reproducibility
        // check (if any bit flips were found) or not
        if (!reproducibility_mode && flipped_bits==0) {
          // don't do reproducibility check if this pattern does not seem to be working
          break;
        } else if (!reproducibility_mode && flipped_bits > 0) {
          // mark this probe as successful (but only once, not each reproducibility round!)
          num_successful_probes++;
        }

        // start/continue reproducibility check
        ss << flipped_bits;
        if (cur_reproducibility_round < reproducibility_rounds) ss << " ";
        if (!reproducibility_mode) {
          reproducibility_mode = true;
          Logger::log_info("Testing bit flip's reproducibility.");
        }

        // last round: finish reproducibility check by printing pattern's reproducibility coefficient
        if (cur_reproducibility_round==reproducibility_rounds) {
          Logger::log_info(format_string("Bit flip's reproducibility score: %d/%d (#flips: %s)",
              reproducibility_rounds_with_bitflips,
              reproducibility_rounds,
              ss.str().c_str()));

          // derive number of reps we need to do to trigger a bit flip based on the current reproducibility coefficient
          // this might look counterintuitive but makes sense, assume we trigger bit flips in 3 of 20 runs, so we need
          // to hammer on average 20/3 ≈ 7 times to see a bit flip
//          reproducibility_score =
//              (int) std::ceil((float) reproducibility_rounds/(float) reproducibility_rounds_with_bitflips);

          // this code is used to dynamically adapt REPS_PER_PATTERN (the number of repeated hammerings of a pattern),
          // note that REPS_PER_PATTERN is not used antywhere yet!
//          auto old_reps_per_pattern = REPS_PER_PATTERN;
          // it's important to use max here, otherwise REPS_PER_PATTERN can become 0 (i.e., stop hammering)
//          REPS_PER_PATTERN =
//              std::max(1,
//                  (int) std::ceil((float) REPS_PER_PATTERN
//                      + ((1.0f/(float) num_successful_probes) * (float) (reproducibility_score - REPS_PER_PATTERN))));
//          Logger::log_info(format_string("Updated REPS_PER_PATTERN: %d → %lu", old_reps_per_pattern, REPS_PER_PATTERN));
        }

        // wait a bit and do some random accesses before checking reproducibility of the pattern
        if (random_rows.empty()) {
          random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
        }
        do_random_accesses(random_rows, 64000); // 64000us (retention time)

        cur_reproducibility_round++;
      } while (cur_reproducibility_round <= reproducibility_rounds);

      // assign the computed reproducibility score to this pattern s.t. it is included in the JSON export
      mapper.reproducibility_score = (double)reproducibility_rounds_with_bitflips / (double)reproducibility_rounds;

      // it is important that we store this mapper after we did memory.check_memory to include the found BitFlip
      hammering_pattern.address_mappings.push_back(mapper);

      // cleanup the jitter for its next use
      code_jitter.cleanup();
    }
    cnt_pattern_probes = 0;

#ifdef ENABLE_JSON
    // export the current HammeringPattern including all of its associated PatternAddressMappers
    arr.push_back(hammering_pattern);
#endif

  } // end of fuzzing

#ifdef ENABLE_JSON
  // export everything to JSON, this includes the HammeringPattern, AggressorAccessPattern, and BitFlips
  std::ofstream json_export;
  json_export.open("raw_data.json");
  json_export << arr;
  json_export.close();
#endif
}

void FuzzyHammerer::generate_pattern_for_ARM(int acts,
                                             int *rows_to_access,
                                             int max_accesses,
                                             const size_t probes_per_pattern) {
  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();
  fuzzing_params.randomize_parameters(true);

  hammering_pattern.aggressors.clear();
  if (cnt_pattern_probes > 1 && cnt_pattern_probes < probes_per_pattern) {
    cnt_pattern_probes++;
  } else {
    cnt_pattern_probes = 0;
    hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
  }

  PatternBuilder pattern_builder(hammering_pattern);
  pattern_builder.generate_frequency_based_pattern(fuzzing_params);

  // choose random addresses for pattern
  PatternAddressMapper mapper;
  mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns, true);
  mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, rows_to_access, max_accesses);
  Logger::log_info("Aggressor ID to DRAM address mapping (bank, rank, column):");
  Logger::log_data(mapper.get_mapping_text_repr());
}

void FuzzyHammerer::do_random_accesses(const std::vector<volatile char *> random_rows, const size_t duration_us) {
  const auto random_access_limit = get_timestamp_us() + duration_us;
  while (get_timestamp_us() < random_access_limit) {
    for (volatile char *e : random_rows) {
      *e; // this should be fine as random_rows are volatile
    }
  }
}
