#include "Forges/FuzzyHammerer.hpp"

#include <Blacksmith.hpp>

#include "Utilities/TimeHelper.hpp"
#include "Fuzzer/PatternBuilder.hpp"

// initialize the static variables
size_t FuzzyHammerer::cnt_pattern_probes = 0UL;
std::unordered_map<std::string, std::unordered_map<std::string, int>> FuzzyHammerer::map_pattern_mappings_bitflips;
HammeringPattern FuzzyHammerer::hammering_pattern = HammeringPattern(); /* NOLINT */

void FuzzyHammerer::n_sided_frequency_based_hammering(DramAnalyzer &dramAnalyzer, Memory &memory, int acts,
                                                      unsigned long runtime_limit, const size_t probes_per_pattern,
                                                      bool sweep_best_pattern) {
  Logger::log_info(
      format_string("Starting frequency-based fuzzer run with time limit of %l minutes.", runtime_limit/60));

  map_pattern_mappings_bitflips.clear();

  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

  std::random_device rd;
  std::mt19937 gen(rd());

  ReplayingHammerer replaying_hammerer(memory);

#ifdef ENABLE_JSON
  nlohmann::json arr = nlohmann::json::array();
#endif

  // all patterns that triggered bit flips
  std::vector<HammeringPattern> effective_patterns;

  HammeringPattern best_hammering_pattern;
  PatternAddressMapper best_mapping;
  size_t best_mapping_bitflips = 0;
  size_t best_hammering_pattern_bitflips = 0;
  const auto start_ts = get_timestamp_sec();
  const auto execution_time_limit = static_cast<int64_t>(start_ts + runtime_limit);
  size_t current_round = 1;
  for (; get_timestamp_sec() < execution_time_limit; ++current_round) {
    Logger::log_timestamp();
    Logger::log_highlight(format_string("Generating hammering pattern #%lu.", current_round));
    fuzzing_params.randomize_parameters(true);

    // generate a hammering pattern: this is like a general access pattern template without concrete addresses
    FuzzyHammerer::hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
    PatternBuilder pattern_builder(hammering_pattern);
    pattern_builder.generate_frequency_based_pattern(fuzzing_params);

    Logger::log_info("Abstract pattern based on aggressor IDs:");
    Logger::log_data(hammering_pattern.get_pattern_text_repr());
    Logger::log_info("Aggressor pairs, given as \"(id ...) : freq, amp, start_offset\":");
    Logger::log_data(hammering_pattern.get_agg_access_pairs_text_repr());

    // randomize the order of AggressorAccessPatterns to avoid biasing the PatternAddressMapper as it always assigns
    // rows in order of the AggressorAccessPatterns map (e.g., first element is assigned to the lowest DRAM row).
    std::shuffle(hammering_pattern.agg_access_patterns.begin(), hammering_pattern.agg_access_patterns.end(), gen);

    // then test this pattern with N different address sets
    size_t sum_flips_one_pattern_all_mappings = 0;
    for (cnt_pattern_probes = 0; cnt_pattern_probes < probes_per_pattern; ++cnt_pattern_probes) {
      PatternAddressMapper mapper;
      Logger::log_info(format_string("Running pattern #%lu (%s) for address set %d (%s).",
          current_round, hammering_pattern.instance_id.c_str(), cnt_pattern_probes, mapper.get_instance_id().c_str()));
      probe_mapping_and_scan(mapper, memory, fuzzing_params, false);
      sum_flips_one_pattern_all_mappings += mapper.bit_flips.size();
      // it is important that we store this mapper after we did memory.check_memory to include the found BitFlip
      hammering_pattern.address_mappings.push_back(mapper);
    }

    if (sum_flips_one_pattern_all_mappings > 0) {
      effective_patterns.push_back(hammering_pattern);
    }

    // TODO additionally consider the number of locations where this pattern triggers bit flips besides the total
    //  number of bit flips only because we want to find a pattern that generalizes well
    // if this pattern is better than every other pattern tried out before, mark this as 'new best pattern'
    if (sum_flips_one_pattern_all_mappings > best_hammering_pattern_bitflips) {
      best_hammering_pattern = hammering_pattern;
      best_hammering_pattern_bitflips = sum_flips_one_pattern_all_mappings;

      // find the best mapping of this pattern (generally it doesn't matter as we're sweeping anyway over a chunk of
      // memory but the mapper also contains a reference to the CodeJitter, which in turn uses some parameters that we
      // want to reuse during sweeping; other mappings could differ in these parameters)
      for (const auto &m : hammering_pattern.address_mappings) {
        const size_t num_bitlfips = m.bit_flips.size();
        if (num_bitlfips > best_mapping_bitflips) {
          best_mapping = m;
          best_mapping_bitflips = num_bitlfips;
        }
      }
    }

    // dynamically change num acts per tREF after every 100 patterns; this is to avoid that we made a bad choice at the
    // beginning and then get stuck with that value
    // if the user provided a fixed num acts per tREF value via the program arguments, then we will not change it
    if (current_round%100==0 && program_args.acts_per_ref != 0) {
      auto old_nacts = fuzzing_params.get_num_activations_per_t_refi();
      // repeat measuring the number of possible activations per tREF as it might be that the current value is not optimal
      fuzzing_params.set_num_activations_per_t_refi(static_cast<int>(dramAnalyzer.count_acts_per_ref()));
      Logger::log_info(
          format_string("Recomputed number of ACTs per tREF (old: %d, new: %d).",
              old_nacts,
              fuzzing_params.get_num_activations_per_t_refi()));
    }

  } // end of fuzzing

  log_overall_statistics(probes_per_pattern, current_round, best_mapping.get_instance_id(), best_mapping_bitflips);

  // start the post-analysis stage ============================
  if (effective_patterns.empty()) {
    Logger::log_info("Skipping post-analysis stage as no effective patterns were found.");
  } else {
    Logger::log_info("Starting post-analysis stage.");
    Logger::log_info("Checking reproducibility of bit flips.");
  }

  Logger::log_info("Choosing a subset of max. 5 patterns for the reproducibility check to reduce compute time.");
  // checking reproducibility for all found patterns takes too long on DIMMs with many patterns, therefore we limit the
  // reproducibility check to the top-5 patterns we found (top-5 = the 5 patterns that triggered the most bit flips)
  std::map<size_t, HammeringPattern, std::greater<>> best_patterns;
  std::unordered_set<std::string> patterns_for_reproducibility_check;
  for (auto &pattern : effective_patterns) {
    size_t total_bitflips = 0;
    for (const auto& mapper : pattern.address_mappings) {
      total_bitflips += mapper.bit_flips.size();
    }
    best_patterns[total_bitflips] = pattern;
  }
  size_t cnt = 0;
  for (auto &entry : best_patterns) {
    Logger::log_info(format_string("Pick %d: Pattern %s triggered %d bit flips.",
        cnt, entry.second.instance_id.c_str(), entry.first));
    patterns_for_reproducibility_check.insert(entry.second.instance_id);
    cnt++;
    if (cnt == 5) break;
  }

  for (auto &pattern : effective_patterns) {
    //  check if this is one of the selected patterns for the reproducibility check
    if (patterns_for_reproducibility_check.count(pattern.instance_id) > 0) {

      // FIXME: this is a dirty hack, instead modify the ReplayingHammerer so that it takes a pattern as input
      hammering_pattern = pattern;

      // do the repeatability check for the pattern/mappings that worked and store result in JSON
      for (auto &mapper : hammering_pattern.address_mappings) {
        if (mapper.bit_flips.empty())
          continue;
        Logger::log_info(format_string("Running pattern %s for address set %s.",
            pattern.instance_id.c_str(), mapper.get_instance_id().c_str()));
        replaying_hammerer.load_parameters_from_pattern(pattern, mapper);
        probe_mapping_and_scan(mapper, memory, replaying_hammerer.params, true);
      }

      // FIXME: this is part of the dirty hack and required to write back the results of the ReplayingHammerer
#ifdef ENABLE_JSON
      hammering_pattern.remove_mappings_without_bitflips();
      arr.push_back(hammering_pattern);
    } else {
      pattern.remove_mappings_without_bitflips();
      arr.push_back(pattern);
    }
#else
    }
#endif
}

  if (sweep_best_pattern && best_hammering_pattern_bitflips > 0) {
    // do experiment with best pattern to figure out whether during the sweep we need to move all aggressors or only
    // those that actually triggered the bit flip
    test_location_dependence(replaying_hammerer, best_hammering_pattern);
  }

  // we need to do the fuzz-summary.json export after test_location_dependence, otherwise the attribute value
  // is_location_dependent will not be included into the JSON; similarly,we do the JSON export after the repeatability
  // experiment because the export should include the repeatability data
#ifdef ENABLE_JSON
  // export everything to JSON, this includes the HammeringPattern, AggressorAccessPattern, and BitFlips
  std::ofstream json_export("fuzz-summary.json");

  nlohmann::json meta;
  meta["start"] = start_ts;
  meta["end"] = get_timestamp_sec();
  meta["num_patterns"] = arr.size();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["dimm_id"] = program_args.dimm_id;

  nlohmann::json root;
  root["metadata"] = meta;
  root["hammering_patterns"] = arr;

  json_export << root << std::endl;
  json_export.close();
#endif

  if (sweep_best_pattern && best_hammering_pattern_bitflips > 0) {
    // apply the 'best' pattern over a contiguous chunk of memory
    // note that log_overall_statistics shows the number of bit flips of the best pattern's most effective mapping, as
    // metric to determine the best pattern we use the number of bit flips over all mappings of that pattern
    replaying_hammerer.set_params(fuzzing_params);

    // do sweep with 1x256MB of memory
    replaying_hammerer.replay_patterns_brief({best_hammering_pattern}, MB(256), 1, true);
    // do sweep with 8x32MB of memory
//    replaying_hammerer.replay_patterns_brief({best_hammering_pattern}, MB(32), 8, true);
  }
}

void FuzzyHammerer::test_location_dependence(ReplayingHammerer &rh, HammeringPattern &pattern) {
  // find the most effective mapping of the given pattern by looking into data collected before
  Logger::log_info(format_string("[test_location_dependence] Finding best mapping for given pattern (%s).",
      pattern.instance_id.c_str()));
  PatternAddressMapper &best_mapping = pattern.get_most_effective_mapping();
  Logger::log_info(format_string("[test_location_dependence] Best mapping (%s) triggered %d bit flips.",
      best_mapping.get_instance_id().c_str(), best_mapping.bit_flips.size()));

  // determine the aggressor pairs that triggered the bit flip
  Logger::log_info("[test_location_dependence] Finding the direct effective aggressors.");
  std::unordered_set<AggressorAccessPattern> direct_effective_aggs;
  ReplayingHammerer::find_direct_effective_aggs(pattern, best_mapping, direct_effective_aggs);
  Logger::log_info(format_string("[test_location_dependence] Found %zu direct effective aggressors.",
      direct_effective_aggs.size()));

  // copy the mapping
  Logger::log_info("[test_location_dependence] Copying the original pattern.");

  // do a sweep over N rows where we move all aggressor pairs each time by 1 row
  Logger::log_info("[test_location_dependence] Doing sweep 1/2: moving all aggressor pairs.");
  SweepSummary ss_move_all = rh.sweep_pattern(pattern, best_mapping, 1, MB(8));

  // restore the copied mapping to have the same start position (this should help in avoiding wrong results due to
  // memory regions that are differently vulnerable)
  Logger::log_info("[test_location_dependence] Restoring original mapping to get same start row.");

  // do a sweep over N rows where we only move the aggressor pair that triggered the bit flip each time by 1 row
  Logger::log_info("[test_location_dependence] Doing sweep 2/2: moving only effective agg pairs.");
  SweepSummary ss_move_selected = rh.sweep_pattern(pattern, best_mapping, 1, MB(8), direct_effective_aggs);

  // compare number of bit flips
  bool is_location_dependent = (ss_move_selected.observed_bitflips.size() > ss_move_all.observed_bitflips.size());
  Logger::log_info(format_string(
      "[test_location_dependence] Comparing #bit flips: all %zu vs selected %zu  => location-dependent: %s",
      ss_move_all.observed_bitflips.size(),
      ss_move_selected.observed_bitflips.size(),
      is_location_dependent ? "YES" : "NO"));

  // write True in is_location_dependent in HammeringPattern in case that fixing the 'random' aggressors leads to better
  // results than moving everything
  Logger::log_info("[test_location_dependence] Writing is_location_dependent into HammeringPattern.");
  pattern.is_location_dependent = is_location_dependent;
}

void FuzzyHammerer::probe_mapping_and_scan(PatternAddressMapper &mapper, Memory &memory,
                                           FuzzingParameterSet &fuzzing_params, const bool check_reproducibility) {

  // ATTENTION: This method uses the global variable hammering_pattern to refer to the pattern that is to be hammered

  CodeJitter &code_jitter = mapper.get_code_jitter();

  if (!check_reproducibility) {
    // randomize the aggressor ID -> DRAM row mapping
    mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns, true);
  }

  // now fill the pattern with these random addresses
  std::vector<volatile char *> hammering_accesses_vec;
  mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, hammering_accesses_vec);
  Logger::log_info("Aggressor ID to DRAM address mapping (bank, row, column):");
  Logger::log_data(mapper.get_mapping_text_repr());

  // now create instructions that follow this pattern (i.e., do jitting of code)
  bool sync_at_each_ref = fuzzing_params.get_random_sync_each_ref();
  int num_aggs_for_sync = fuzzing_params.get_random_num_aggressors_for_sync();
  Logger::log_info("Creating ASM code for hammering.");
  code_jitter.jit_strict(fuzzing_params.get_num_activations_per_t_refi(),
      FLUSHING_STRATEGY::EARLIEST_POSSIBLE, FENCING_STRATEGY::LATEST_POSSIBLE,
      hammering_accesses_vec, sync_at_each_ref, num_aggs_for_sync,
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

  if (check_reproducibility)
    Logger::log_info("Testing bit flip's reproducibility.");

#ifdef DEBUG_SAMSUNG
  const int reproducibility_rounds = 20;
#else
  const int reproducibility_rounds = 30;
#endif
  int cur_reproducibility_round = 1;
  int reproducibility_rounds_with_bitflips = 0;
  std::stringstream ss;
  do {
    // do hammering
    code_jitter.hammer_pattern(fuzzing_params, !check_reproducibility);

    // check if any bit flips happened
    auto flipped_bits = memory.check_memory(mapper, check_reproducibility, !check_reproducibility);
    reproducibility_rounds_with_bitflips += (flipped_bits > 0);

    if (!check_reproducibility) {
      // don't do reproducibility check if this pattern does not seem to be working
      if (flipped_bits==0) break;

      // mark this probe as successful (but only once, not each reproducibility round!)

      // store info about this bit flip (pattern ID, mapping ID, no. of bit flips)
      auto map_record = std::make_pair(mapper.get_instance_id(), flipped_bits);
      map_pattern_mappings_bitflips[hammering_pattern.instance_id].insert(map_record);
    }

    // add no. of flipped bits to printed output
    ss << flipped_bits;

    if (check_reproducibility && cur_reproducibility_round < reproducibility_rounds) {
      // not last round: we add a whitespace to separate the number of bit flips in each repeatability round
      ss << " ";
    } else if (check_reproducibility && cur_reproducibility_round==reproducibility_rounds) {
      // last round: finish reproducibility check by printing pattern's reproducibility coefficient
      Logger::log_info(format_string("Bit flip's reproducibility score: %d/%d (#flips: %s)",
          reproducibility_rounds_with_bitflips, reproducibility_rounds, ss.str().c_str()));
    }

    // wait a bit and do some random accesses before checking reproducibility of the pattern
    if (random_rows.empty()) random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
    do_random_accesses(random_rows, 64000); // 64ms (retention time)

    cur_reproducibility_round++;
  } while (check_reproducibility && cur_reproducibility_round <= reproducibility_rounds);

  // assign the computed reproducibility score to this pattern s.t. it is included in the JSON export;
  // a reproducibility of -1 indicates that reproducibility was not tested
  if (check_reproducibility) {
    mapper.reproducibility_score = static_cast<int>(
        (static_cast<double>(reproducibility_rounds_with_bitflips)/static_cast<double>(reproducibility_rounds))*100);
  }

  // cleanup the jitter for its next use
  code_jitter.cleanup();
}

void FuzzyHammerer::log_overall_statistics(const size_t probes_per_pattern, size_t cur_round,
                                           const std::string &best_mapping_id, size_t best_mapping_num_bitflips) {
  Logger::log_info("Fuzzing run finished successfully. Printing basic statistics:");
  Logger::log_data(format_string("Number of tested patterns: %lu", cur_round));
  Logger::log_data(format_string("Number of tested locations per pattern: %lu", probes_per_pattern));
  Logger::log_data(format_string("Number of effective patterns: %lu", map_pattern_mappings_bitflips.size()));
  Logger::log_data(format_string("Best pattern ID: %s", best_mapping_id.c_str()));
  Logger::log_data(format_string("Best pattern #bitflips: %ld", best_mapping_num_bitflips));
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

  Logger::log_info("Aggressor pairs, given as \"(id ...) : freq, amp, start_offset\":");
  Logger::log_data(hammering_pattern.get_agg_access_pairs_text_repr());

  // choose random addresses for pattern
  PatternAddressMapper mapper;
  mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns, true);
  mapper.export_pattern(hammering_pattern.aggressors, hammering_pattern.base_period, rows_to_access, max_accesses);
  Logger::log_info("Aggressor ID to DRAM address mapping (bank, rank, column):");
  Logger::log_data(mapper.get_mapping_text_repr());
}

void FuzzyHammerer::do_random_accesses(const std::vector<volatile char *> &random_rows, const int duration_us) {
  const auto random_access_limit = get_timestamp_us() + static_cast<int64_t>(duration_us);
  while (get_timestamp_us() < random_access_limit) {
    for (volatile char *e : random_rows) {
      (void)*e; // this should be fine as random_rows are volatile
    }
  }
}
