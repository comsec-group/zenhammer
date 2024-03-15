#include "Forges/FuzzyHammerer.hpp"

#include "ZenHammer.hpp"
#include "Forges/ReplayingHammerer.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Memory/DRAMConfig.hpp"
#include "Utilities/TimeHelper.hpp"

// initialize the static variables
size_t FuzzyHammerer::cnt_pattern_probes = 0UL;
size_t FuzzyHammerer::cnt_generated_patterns = 0UL;
std::unordered_map<std::string, std::unordered_map<std::string, int>> FuzzyHammerer::map_pattern_mappings_bitflips;
HammeringPattern FuzzyHammerer::hammering_pattern = HammeringPattern(); /* NOLINT */

void FuzzyHammerer::n_sided_frequency_based_hammering(DramAnalyzer &dramAnalyzer, Memory &memory, int acts,
                                                      unsigned long runtime_limit, const size_t probes_per_pattern,
                                                      bool sweep_best_pattern) {
  // FIXME: If these arguments are really not needed, we should just remove them.
  (void)dramAnalyzer;
  (void)acts;

  std::mt19937 gen = std::mt19937(std::random_device()());

  Logger::log_info(
      format_string("Starting frequency-based fuzzer run with time limit of %l minutes.", runtime_limit/60));

  // make sure that this is empty (e.g., from previous call to this function)
  map_pattern_mappings_bitflips.clear();

  FuzzingParameterSet fuzzing_params;
  if (program_args.fixed_acts_per_ref) {
    Logger::log_info(format_string("Setting ACTs/tREFI to %d as given as command line argument.", program_args.acts_per_trefi));
    fuzzing_params.set_acts_per_trefi((int)program_args.acts_per_trefi);
  }
  fuzzing_params.print_static_parameters();

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

  for (; get_timestamp_sec() < execution_time_limit; ++cnt_generated_patterns) {
    Logger::log_timestamp();
    Logger::log_highlight(format_string("Generating hammering pattern #%lu.", cnt_generated_patterns));
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
    // rows in order of the AggressorAccessPatterns map (e.g., first element is assigned to the lowest DRAM row).]
    std::shuffle(hammering_pattern.agg_access_patterns.begin(), hammering_pattern.agg_access_patterns.end(), gen);

    // then test this pattern with N different mappings (i.e., address sets)
    size_t sum_flips_one_pattern_all_mappings = 0;
    for (cnt_pattern_probes = 0; cnt_pattern_probes < probes_per_pattern; ++cnt_pattern_probes) {
      PatternAddressMapper mapper;
//      Logger::log_info(format_string("Running pattern #%lu (%s) for address set %d (%s).",
//          current_round, hammering_pattern.instance_id.c_str(), cnt_pattern_probes, mapper.get_instance_id().c_str()));
//
      // we test this combination of (pattern, mapping) at three different DRAM locations
      probe_mapping_and_scan(mapper, memory, fuzzing_params, program_args.num_dram_locations_per_mapping);
      auto bit_flips_this_mapping = mapper.count_bitflips();
      sum_flips_one_pattern_all_mappings += bit_flips_this_mapping;

      if (bit_flips_this_mapping > 0) {
        // it is important that we store this mapper only after we did memory.check_memory to include the found BitFlip
        hammering_pattern.address_mappings.push_back(mapper);
      }
    }

    if (sum_flips_one_pattern_all_mappings > 0) {
      assert(!hammering_pattern.address_mappings.empty() && "At least one mapping has some bit flips.");
      effective_patterns.push_back(hammering_pattern);
      arr.push_back(hammering_pattern);
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
        size_t num_bitflips = m.count_bitflips();
        if (num_bitflips > best_mapping_bitflips) {
          best_mapping = m;
          best_mapping_bitflips = num_bitflips;
        }
      }
    }
  } // end of fuzzing

  log_overall_statistics(
      cnt_generated_patterns,
      best_mapping.get_instance_id(),
      best_mapping_bitflips,
      effective_patterns.size());

  // start the post-analysis stage ============================
  if (arr.empty()) {
    Logger::log_info("No effective patterns were found! Scanning entire memory for bitflips.");
    auto bitflips = memory.check_memory(memory.get_starting_address(), memory.get_starting_address() + memory.get_allocation_size());
    if (bitflips > 0) {
      Logger::log_highlight(format_string(
        "Found %zu bitflips during post-fuzzing memory scan, even though no bitflips were detected during the fuzzing run.\n"
        "Maybe the DRAM configuration is wrong, and the rows with bitflips were thus not scanned?",
        bitflips));
    }

    Logger::log_info("Skipping post-analysis stage as no effective patterns were found.");
  } else {
    Logger::log_info("Starting post-analysis stage.");
  }

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

  if (effective_patterns.empty()) {
    return;
  }

  // define the location where we are going to do the large sweep
  DRAMAddr sweep_start = DRAMAddr(
      Range<int>(0, DRAMConfig::get().banks() - 1).get_random_number(gen),
      Range<int>(0, DRAMConfig::get().rows() - 1).get_random_number(gen),
      0);

  Logger::log_info(format_string("Doing a sweep of %d rows to determine most effective pattern.", MINISWEEP_ROWS));

  // store for each (pattern, mapping) the number of observed bit flips during sweep
  struct PatternMappingStat {
    const HammeringPattern* pattern;
    std::string pattern_id;
    std::string mapping_id;
    size_t num_bit_flips { 0 };
  };
  std::vector<PatternMappingStat> patterns_stat;

  for (auto &patt : effective_patterns) {
    for (auto &mapping : patt.address_mappings) {
      //  move the pattern to the target DRAM location
      mapping.remap_aggressors(sweep_start);

      // do the minisweep
      SweepSummary summary = replaying_hammerer.sweep_pattern(patt, mapping, 10, MINISWEEP_ROWS, {});

      PatternMappingStat pms {
        .pattern = &patt,
        .pattern_id = patt.instance_id,
        .mapping_id = mapping.get_instance_id(),
        .num_bit_flips = summary.observed_bitflips.size()
      };
      patterns_stat.push_back(std::move(pms));
    }
  }
  assert(!patterns_stat.empty() && "For each pattern in effective_patterns, there should be at least one entry in this vector.");

  std::stable_sort(patterns_stat.begin(), patterns_stat.end(), [](const auto& a, const auto& b) {
    return a.num_bit_flips > b.num_bit_flips;
  });

  // printout - just for debugging
  Logger::log_info("Summary of minisweep:");
  Logger::log_data(
      format_string("%4s\t%-6s\t%-8s\t%-8s", "Rank", "#Flips", "Pattern ID", "Mapping ID\n"));

  auto last_rank_bit_flips = std::numeric_limits<size_t>::max();
  size_t last_rank = 0;
  for (size_t i = 0; i < patterns_stat.size(); i++) {
    if (patterns_stat[i].num_bit_flips == last_rank_bit_flips) {
      // Equal rank. Do nothing.
    } else {
      // Update rank.
      last_rank = i + 1;
      last_rank_bit_flips = patterns_stat[i].num_bit_flips;
    }
    auto pattern_id_short = patterns_stat[i].pattern_id.substr(0, 8);
    auto mapping_id_short = patterns_stat[i].mapping_id.substr(0, 8);
    Logger::log_data(format_string("%4d\t%6d\t%-8s\t%-8s",
                                   last_rank, patterns_stat[i].num_bit_flips, pattern_id_short.c_str(), mapping_id_short.c_str()));
  }

  // Do sweep with the pattern that performed best in the minisweep.
  const auto& best = patterns_stat.front();
  Logger::log_info(format_string("best_pattern_id = %s", best.pattern_id.c_str()));
  Logger::log_info(format_string("best_pattern_mapping_id = %s", best.mapping_id.c_str()));

  if (!sweep_best_pattern) {
    return;
  }

  // Copy the best pattern out to modify it.
  auto best_pattern = *best.pattern;
  // Remove all mappings from best pattern except the 'best mapping' because the sweep function does otherwise not
  // know which the best mapping is.
  std::erase_if(best_pattern.address_mappings, [&](const auto& mapping) { return mapping.get_instance_id() != best.mapping_id; });

  // do sweep
  replaying_hammerer.set_params(fuzzing_params);
  replaying_hammerer.replay_patterns_brief({ best_pattern }, FULL_SWEEP_ROWS, 1, true);
}

void FuzzyHammerer::test_location_dependence(ReplayingHammerer &rh, HammeringPattern &pattern) {
  // find the most effective mapping of the given pattern by looking into data collected before
  Logger::log_info(format_string("[test_location_dependence] Finding best mapping for given pattern (%s).",
      pattern.instance_id.c_str()));
  PatternAddressMapper &best_mapping = pattern.get_most_effective_mapping();
  Logger::log_info(format_string("[test_location_dependence] Best mapping (%s) triggered %d bit flips.",
      best_mapping.get_instance_id().c_str(), best_mapping.count_bitflips()));

  // determine the aggressor pairs that triggered the bit flip
  Logger::log_info("[test_location_dependence] Finding the direct effective aggressors.");
  std::unordered_set<AggressorAccessPattern> direct_effective_aggs;
  ReplayingHammerer::find_direct_effective_aggs(pattern, best_mapping, direct_effective_aggs);
  Logger::log_info(format_string("[test_location_dependence] Found %zu direct effective aggressors.",
      direct_effective_aggs.size()));

  // copy the mapping
  Logger::log_info("[test_location_dependence] Copying the original pattern.");

  constexpr size_t SWEEP_ROWS = 64;

  // do a sweep over N rows where we move all aggressor pairs each time by 1 row
  Logger::log_info("[test_location_dependence] Doing sweep 1/2: moving all aggressor pairs.");
  SweepSummary ss_move_all = rh.sweep_pattern(pattern, best_mapping, 1, SWEEP_ROWS);

  // restore the copied mapping to have the same start position (this should help in avoiding wrong results due to
  // memory regions that are differently vulnerable)
  Logger::log_info("[test_location_dependence] Restoring original mapping to get same start row.");

  // do a sweep over N rows where we only move the aggressor pair that triggered the bit flip each time by 1 row
  Logger::log_info("[test_location_dependence] Doing sweep 2/2: moving only effective agg pairs.");
  SweepSummary ss_move_selected = rh.sweep_pattern(pattern, best_mapping, 1, SWEEP_ROWS, direct_effective_aggs);

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
                                           FuzzingParameterSet &fuzzing_params, size_t num_dram_locations) {

  // ATTENTION: This method uses the global variable hammering_pattern to refer to the pattern that is to be hammered

  CodeJitter &code_jitter = mapper.get_code_jitter();

  // randomize the aggressor ID -> DRAM row mapping
  mapper.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns, true);

  size_t flipped_bits = 0;
  for (size_t dram_location = 0; dram_location < num_dram_locations; ++dram_location) {
    mapper.bit_flips.emplace_back();

    Logger::log_info(format_string("Running pattern #%lu (%s) for address set %d (%s) at DRAM location #%ld.",
        cnt_generated_patterns,
        hammering_pattern.instance_id.c_str(),
        cnt_pattern_probes,
        mapper.get_instance_id().c_str(),
        dram_location));

    // wait for a random time before starting to hammer, while waiting access random rows that are not part of the
    // currently hammering pattern; this wait interval serves for two purposes: to reset the sampler and start from a
    // clean state before hammering, and also to fuzz a possible dependence at which REF we start hammering
    auto wait_until_hammering_us = fuzzing_params.get_random_wait_until_start_hammering_us();
    FuzzingParameterSet::print_dynamic_parameters2(wait_until_hammering_us);

    std::vector<volatile char *> random_rows;
    if (wait_until_hammering_us > 0) {
      random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
      do_random_accesses(random_rows, wait_until_hammering_us);
    }

    // now fill the pattern with these random addresses
    auto hammering_accesses_vec = mapper.export_pattern(hammering_pattern, program_args.scheduling_policy);
    Logger::log_info("Aggressor ID to DRAM address mapping (bank, row, column):");
    Logger::log_data(mapper.get_mapping_text_repr());

// #define PATTERN_WITH_FENCES_DEBUG 1
#if PATTERN_WITH_FENCES_DEBUG
    std::stringstream ss;
    auto it = addrs.begin();
    for (size_t i = 0; i < hammering_pattern.aggressors.size(); i++) {
      // Check if there is a fence before this aggressor.
      if (*it == nullptr) {
        ss << "|";
        ++it;
      } else {
        ss << " ";
      }

      const auto& aggr = hammering_pattern.aggressors[i];
      ++it;
      ss << std::setw(3) << aggr.id;

      if ((i + 1) % hammering_pattern.base_period == 0) {
        ss << "\n";
      }
    }
    Logger::log_info("Abstract pattern with inserted fences:");
    Logger::log_data(ss.str());
#endif

    // now create instructions that follow this pattern (i.e., do jitting of code)
    Logger::log_info("Creating ASM code for hammering.");
    code_jitter.jit_strict(fuzzing_params.flushing_strategy, fuzzing_params.fencing_strategy,
        hammering_accesses_vec, program_args.fence_type,
        fuzzing_params.get_hammering_total_num_activations());

    // do hammering
    code_jitter.hammer_pattern(fuzzing_params, true, true);

    code_jitter.cleanup();

    // check if any bit flips happened
    flipped_bits += memory.check_memory(mapper, false, true);

    // now shift the mapping to another location
    std::mt19937 gen = std::mt19937(std::random_device()());
    mapper.shift_mapping(Range<int>(1,32).get_random_number(gen), {});

    if (dram_location + 1 < num_dram_locations) {
      // wait a bit and do some random accesses before checking reproducibility of the pattern
      if (random_rows.empty()) random_rows = mapper.get_random_nonaccessed_rows(fuzzing_params.get_max_row_no());
      do_random_accesses(random_rows, 64000); // 64ms (retention time)
    }
  }

  // store info about this bit flip (pattern ID, mapping ID, no. of bit flips)
  map_pattern_mappings_bitflips[hammering_pattern.instance_id].emplace(mapper.get_instance_id(), flipped_bits);

  // cleanup the jitter for its next use
  code_jitter.cleanup();
}

void FuzzyHammerer::log_overall_statistics(size_t cur_round, const std::string &best_mapping_id,
                                           size_t best_mapping_num_bitflips, size_t num_effective_patterns) {
  Logger::log_info("Fuzzing run finished successfully.");
  Logger::log_data(format_string("Number of generated patterns: %lu", cur_round));
  Logger::log_data(format_string("Number of generated mappings per pattern: %lu",
      program_args.num_address_mappings_per_pattern));
  Logger::log_data(format_string("Number of tested locations per pattern: %lu",
      program_args.num_dram_locations_per_mapping));
  Logger::log_data(format_string("Number of effective patterns: %lu", num_effective_patterns));
  Logger::log_data(format_string("Best pattern ID: %s", best_mapping_id.c_str()));
  Logger::log_data(format_string("Best pattern #bitflips: %ld", best_mapping_num_bitflips));
}

void FuzzyHammerer::do_random_accesses(const std::vector<volatile char *> &random_rows, const int duration_us) {
  const auto random_access_limit = get_timestamp_us() + static_cast<int64_t>(duration_us);
  while (get_timestamp_us() < random_access_limit) {
    for (volatile char *e : random_rows) {
      (void)*e; // this should be fine as random_rows are volatile
    }
  }
}
