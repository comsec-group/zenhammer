#include "Forges/ReplayingHammerer.hpp"

#include <unordered_set>
#include <Fuzzer/PatternBuilder.hpp>

#include "Forges/FuzzyHammerer.hpp"

#define M(VAL) (VAL ## 000000)
#define K(VAL) (VAL ## 000)

void ReplayingHammerer::replay_patterns(Memory &mem,
                                        const char *json_filename,
                                        const char *pattern_ids,
                                        int acts_per_tref) {
  std::vector<HammeringPattern> patterns = get_matching_patterns_from_json(json_filename, pattern_ids);
  FuzzingParameterSet params(acts_per_tref);
  std::random_device rd;
  std::mt19937 gen(rd());

  // replay each loaded patter
  for (auto &patt : patterns) {

    const int pattern_total_acts = patt.total_activations;

    // ==== 1:1 Replaying to test if original pattern/replaying works =================================================

    // try the original location where this pattern initially triggered a bit flip to be sure we are trying a pattern
    // that actually works when replaying it
    Logger::log_analysis_stage("1:1 REPLAYING");
    const auto num_reps_org_replaying = 1;
    size_t best_mapping_bitflips = 0;
    std::string best_mapping_instance_id = "ANY";
    for (auto it = patt.address_mappings.begin(); it!=patt.address_mappings.end(); ++it) {
      Logger::log_info(format_string("Mapping %s given as agg ID -> (bank,rank,column):",
          (*it).get_instance_id().c_str()));
      Logger::log_data((*it).get_mapping_text_repr());

      CodeJitter &jitter = *(*it).code_jitter;
      size_t triggered_bitflips = hammer_pattern(mem, params, jitter, patt, *it, jitter.flushing_strategy,
          jitter.fencing_strategy, num_reps_org_replaying, jitter.pattern_sync_each_ref, jitter.num_aggs_for_sync,
          jitter.total_activations, false, false, false);

      Logger::log_success(format_string("Mapping triggered %d bit flips.", triggered_bitflips));
      if (triggered_bitflips > best_mapping_bitflips) {
        best_mapping_bitflips = triggered_bitflips;
        best_mapping_instance_id = (*it).get_instance_id();
      }

      // strategy: keep all mappings that produce bit flips
//      if (triggered_bitflips==0) {
//        Logger::log_info(format_string("Removing mapping %s that didn't trigger any bit flips.", (*it).get_instance_id().c_str()));
//        it = patt.address_mappings.erase(it);
//      } else {
//        Logger::log_info(format_string("Keeping mapping as it triggered %lu bit flips", triggered_bitflips));
//        it++;
//      }
    }

    // strategy: remove all patterns except the one that triggered the most bit flips
    Logger::log_info(format_string("Keeping mapping %s as it triggered the most bit flips.",
        best_mapping_instance_id.c_str()));
    // if we run this on another DIMM, we just want to take any mapping because none of the existing mappings may work
    if (best_mapping_bitflips == 0) {
      best_mapping_instance_id = patt.address_mappings.begin()->get_instance_id();
    }
    for (auto it = patt.address_mappings.begin(); it!=patt.address_mappings.end();) {
      if ((*it).get_instance_id()!=best_mapping_instance_id) {
        it = patt.address_mappings.erase(it);
      } else {
        it++;
      }
    }

    // ==== Slightly modify execution/pattern by changing single parameters ============================================

    // configuration
    const auto num_reps = 2;
    bool verbose_sync = false;
    bool verbose_memcheck = false;
    bool verbose_params = false;

    // now start analyzing the impact of parameter choices on the success of this pattern
    for (auto &mapper : patt.address_mappings) {
      CodeJitter &jitter = *mapper.code_jitter;
      // save these original values as each call to jit_strict (see hammer_pattern) overwrites them by the passed values
      const auto flushing_strategy = jitter.flushing_strategy;
      const auto fencing_strategy = jitter.fencing_strategy;
      const int total_acts = jitter.total_activations;
      const bool sync_each_ref = jitter.pattern_sync_each_ref;
      const int num_sync_aggs = jitter.num_aggs_for_sync;

      Logger::log_highlight(format_string("Analyzing pattern %s using mapping %s.",
          patt.instance_id.c_str(), mapper.get_instance_id().c_str()));

      // execution probing: systematically randomize parameters that decide how a pattern is executed
      Logger::log_analysis_stage("CODE JITTING PARAMS PROBING");
      // - FLUSHING_STRATEGY / FENCING_STRATEGY
      for (const auto &ff_strategy : get_valid_strategies()) {
        auto num_bit_flips = hammer_pattern(mem, params, jitter, patt, mapper, ff_strategy.first, ff_strategy.second,
            num_reps, sync_each_ref, num_sync_aggs, total_acts, verbose_sync, verbose_memcheck, verbose_params);
        Logger::log_info(format_string("FLUSHING_STRATEGY = %-17s, FENCING_STRATEGY = %-19s => %d bit flips",
            to_string(ff_strategy.first).c_str(),
            to_string(ff_strategy.second).c_str(),
            num_bit_flips));
      }

      // - sync_each_ref
      for (auto &sync : {true, false}) {
        auto num_bit_flips = hammer_pattern(mem, params, jitter, patt, mapper, flushing_strategy, fencing_strategy,
            num_reps, sync, num_sync_aggs, total_acts, verbose_sync, verbose_memcheck, verbose_params);
        Logger::log_info(format_string("sync_each_ref = %-8s => %d bit flips",
            (sync ? "true" : "false"), num_bit_flips));
      }

      // - num_aggs_for_sync
      for (const auto &sync_aggs : {1, 2, 3, 4}) {
        auto num_bit_flips = hammer_pattern(mem, params, jitter, patt, mapper, flushing_strategy, fencing_strategy,
            num_reps, sync_each_ref, sync_aggs, total_acts, verbose_sync, verbose_memcheck, verbose_params);
        Logger::log_info(format_string("num_aggs_for_sync = %-7d => %d bit flips", sync_aggs, num_bit_flips));
      }

      // - hammering_total_num_activations
      for (int a = M(10); a > K(500); a -= K(500)) {
        auto num_bit_flips = hammer_pattern(mem, params, jitter, patt, mapper, flushing_strategy, fencing_strategy,
            num_reps, sync_each_ref, num_sync_aggs, a, verbose_sync, verbose_memcheck, verbose_params);
        Logger::log_info(format_string("total_num_acts_hammering = %-12d => %d bit flips", a, num_bit_flips));
      }

      // spatial probing
      Logger::log_analysis_stage("SPATIAL PROBING");
      // a. sweep over a chunk of N MByte to see whether this pattern also works on other locations
      // compute the bound of the memory area we want to check using this pattern
      auto sweep_MB = 64;
#ifdef DEBUG_SAMSUNG
      sweep_MB = 1; // 8 rows
#endif
      auto row_start = DRAMAddr((void *) mem.get_starting_address()).row;
      auto max_address = (__uint64_t) mem.get_starting_address() + (__uint64_t) MB(sweep_MB);
      auto row_end = DRAMAddr((void *) max_address).row;
      auto num_rows = row_end - row_start;
      const int num_reps_per_address = 2;
      Logger::log_info(format_string("Sweeping pattern over %d MB, equiv. to %d rows, with each %d repetitions.",
          sweep_MB, num_rows, num_reps_per_address));

      auto init_ss = [](std::stringstream &stringstream) {
        stringstream.str("");
        stringstream.clear();
        stringstream << std::setfill(' ') << std::left;
      };
      std::stringstream ss;
      init_ss(ss);
      ss << std::setw(10) << "Offset" << std::setw(12) << "Min. Row"
         << std::setw(12) << "Max. Row" << std::setw(13) << "#Bit Flips" << "Flipped Rows"
         << std::endl << "--------------------------------------------------------------";
      Logger::log_data(ss.str());

      for (unsigned long r = 1; r <= num_rows; ++r) {
        // modify assignment of agg ID to DRAM address by shifting rows by 1
        mapper.shift_mapping(1);

        // call hammer_pattern
        size_t num_flips = hammer_pattern(mem, params, jitter, patt, mapper, flushing_strategy, fencing_strategy,
            1, sync_each_ref, num_sync_aggs, total_acts, verbose_sync, false, false);

        init_ss(ss);
        ss << std::setw(10) << r << std::setw(12) << mapper.min_row
           << std::setw(12) << mapper.max_row << std::setw(13) << num_flips << mem.get_flipped_rows_text_repr();
        Logger::log_data(ss.str());
      }

      // temporal probing
      Logger::log_analysis_stage("TEMPORAL/SPATIAL RELATIONSHIP PROBING");
      Logger::log_info("Determining AggressorAccessPattern that most probably triggered bit flip.");
      // prerequisite: know which aggressor pair triggered a bit flip
      // get all flipped rows
      std::set<int> flipped_rows;
      for (const auto &bf : mapper.bit_flips) flipped_rows.insert(bf.address.row);

      // map to keep track of best guess which AggressorAccessPattern caused a bit flip.
      // maps (aggressor ID) to (distance, AggressorAccessPattern)
      std::unordered_map<int, std::pair<int, AggressorAccessPattern>> matches;

      // iterate over all (unique) bit flips and compute the distance to all AggressorAccessPatterns, remember the
      // AggressorAccessPattern with the lowest distance - this is probably the one that triggered the bit flip
      // TODO: handle the case where multiple aggressors have the same distance to the flipped row
      // TODO: add threshold, e.g., if smallest distance of AggressorAccessPatterns and flipped row is larger than
      //  X rows, there's probably remapping going on and we cannot tell which AggressorAccessPattern caused the flip
      auto &cur_mapping = mapper.aggressor_to_addr;
      for (const auto &flipped_row : flipped_rows) {
        for (auto &agg_pair : patt.agg_access_patterns) {
          // take the smaller distance of the aggressors as the distance of the aggressor pair
          int min_distance = std::numeric_limits<int>::max();
          for (const auto &agg : agg_pair.aggressors) {
            // measure distance between aggs in agg pairs and flipped bit
            auto cur_distance = std::abs((int) cur_mapping.at(agg.id).row - flipped_row);
            min_distance = std::min(min_distance, cur_distance);
          }
          // check if we don't have any 'best' candidate for this bit flip yet (a) or whether this distance is lower
          // than the distance of the best candidate found so far (b)
          if (matches.count(flipped_row)==0  // (a)
              || (matches.count(flipped_row) > 0 && matches.at(flipped_row).first > min_distance)) { // (b)
            auto data = std::make_pair(min_distance, agg_pair);
            matches[flipped_row] = data;
          }
        }
      }
      // direct_effective_aggs contains an AggressorAccessPattern for each flipped row, that's the pattern with the
      // lowest distance to the flipped row
      std::unordered_set<AggressorAccessPattern> direct_effective_aggs;
      for (const auto &fr : matches) {
        std::stringstream sstream;
        sstream << "[";
        for (auto &agg : fr.second.second.aggressors) {
          sstream << mapper.aggressor_to_addr.at(agg.id).to_string_compact();
          if (agg.id!=fr.second.second.aggressors.rbegin()->id) sstream << ",";
        }
        sstream << "]";
        Logger::log_data(format_string("Flip in row %d, probably caused by [%s] -> %s due to minimum distance %d.",
            fr.first, fr.second.second.to_string().c_str(), sstream.str().c_str(), fr.second.first));
        direct_effective_aggs.insert(fr.second.second);
      }

//      // a. change temporal access pattern
//      // change mapping of AggressorAccessPatterns, those which don't cause the bit flip, one-by-one then check if pattern still
//      // triggers bit flips, if so, continue checking the next one otherwise revert change and the continue with next one
//      // at the end report which of the AggressorAccessPattern are really necessary to trigger the bit flip
      std::unordered_set<AggressorAccessPattern> indirect_effective_aggs;
//      for (const auto &agg_pair : patt.agg_access_patterns) {
//        // if this is the aggressor access pattern that caused the bit flip: skip it
//        if (direct_effective_aggs.count(agg_pair) > 0) continue;
//
//        // store old location of aggressors in this aggressor access pattern
//        std::unordered_map<int, DRAMAddr> old_mappings;
//        // store the lowest row number of the aggressors as we will later need it to compute its new row
//        unsigned long lowest_row_no = std::numeric_limits<unsigned long>::max();
//        for (const auto agg : agg_pair.aggressors) {
//          old_mappings[agg.id] = cur_mapping.at(agg.id);
//          lowest_row_no = std::min(lowest_row_no, old_mappings[agg.id].row);
//        }
//
//        // randomize row of this aggressor by mapping it to a row outside of the [min,max] area of the current pattern
//        auto max_row = params.get_max_row_no();
//        auto offset = (mapper.max_row - lowest_row_no + Range<int>(1, 256).get_random_number(gen))%max_row;
//        for (const auto agg : agg_pair.aggressors) {
//          cur_mapping.at(agg.id).row += offset;
//        }
//
//        // do jitting + hammering
//        size_t num_triggered_bitflips = hammer_pattern(mem, params, jitter, patt, mapper, jitter.flushing_strategy,
//            jitter.fencing_strategy, num_reps, jitter.pattern_sync_each_ref,
//            jitter.num_aggs_for_sync, jitter.total_activations, false, false, false);
//
//        // check if pattern still triggers bit flip to see whether this AggressorAccessPattern matters
//        if (num_triggered_bitflips > 0) {
//          Logger::log_info(
//              format_string("Shifting agg pair [%s] by %d rows.\n"
//                            "Found %d bit flips  => agg pair is non-essential.",
//                  agg_pair.to_string().c_str(), offset, num_triggered_bitflips));
//        } else {
//          Logger::log_success(
//              format_string("Shifting agg pair [%s] by %d rows.\n"
//                            "Found no bit flips anymore  => agg pair is essential.",
//                  agg_pair.to_string().c_str(), offset));
//          // mark this AggressorAccessPattern as effective/essential for trigger bit flips
//          indirect_effective_aggs.insert(agg_pair);
//          // restore the original mapping as this AggressorAccessPattern matters!
//          for (const auto agg : agg_pair.aggressors) cur_mapping[agg.id] = old_mappings[agg.id];
//        }
//      }
//      Logger::log_info("Mapping after randomizing all non-effective aggressor pairs:");
//      Logger::log_data(mapper.get_mapping_text_repr());

      // b. change temporal props, which decide how the pattern is accessed, only for agg(s) that triggered bit flip
      // systematically test combinations of (amplitude, frequency, phase) for this aggressor access pattern

      // transform std::unordered_set<AggressorAccessPattern> into std::vector<AggressorAccessPattern> because
      // std::unordered_set only provides const iterators that do not allow modifying the element's attributes
      std::vector<AggressorAccessPattern> direct_effective_aggs_vec(
          direct_effective_aggs.begin(),
          direct_effective_aggs.end());

      PatternBuilder builder(patt);

      auto sort_by_idx_dist = [](std::vector<int> &vec, int index) {
        // for a given vector v={a, b, c, d, e} and index k, returns a vector
        //    {v[k], v[k+1], v[k-1], v[k+2], v[k-2], ...}
        // that is, the elements at index k, k+dist(k,1), k+dist(k,2), etc.
        std::vector<int> result;
        auto num_elements = (int) vec.size();
        auto it = vec.begin() + index;
        result.push_back(*it);
        for (int i = 1; i < num_elements; ++i) {
          if (index + i < num_elements) result.push_back(*(it + i));
          if (index - i >= 0) result.push_back(*(it - i));
        }
        vec = result;
      };

      auto get_index = [](const std::vector<int> &vec, int elem) -> int {
        // returns the index of a given element in a given vector
        auto it = std::find(vec.begin(), vec.end(), elem);
        if (it!=vec.end()) {
          return it - vec.begin();
        } else {
          std::stringstream ss;
          for (auto &n : vec) { ss << n << ","; };
          Logger::log_error(
              format_string("ReplayingHammerer.cpp:get_index(...) could not find given element (%d) in vector (%s).",
                  elem, ss.str().c_str()));
          exit(1);
        }
      };

      const auto base_period = patt.base_period;
      std::vector<int> allowed_frequencies = builder.get_available_multiplicators(total_acts/base_period);

      size_t max_trials_per_aap = 48;
      const auto fpa_probing_num_reps = 5;

      // The strategy that we use here is motivated by the following:
      // Given a AggressorAccessPattern AAP(freq,phase,amplitude)=(f,p,a) that triggers a bit flip, we cannot try out
      // all possible combinations of freq, phase, and amplitude as it simply would take too long. We could just try out
      // randomly chosen combinations but, well, we already did this to find that pattern. Instead, we choose the same
      // (f,p,a) as we know that triggers bit flips and then slowly change each of these parameters to see how it
      // affects the ability to trigger bit flips.
      // For example:
      // ___ freq ____  __ phase __  ______ amplitude _______
      // (f,p,a)      -> (f,p+0,a) -> (f,p,a+1) -> (f,p,a-1) -> ...
      //              -> (f,p+1,a) -> ...
      //              -> (f,p-1,a) -> ...
      // -> (f+1,p,a) -> ...

      Logger::log_info("Systematically testing different combination of (frequency, phase, amplitude).");
      // note: usually, a pattern only causes a bit flip in one row and hence direct_effective_aggs has one element only
      for (AggressorAccessPattern &aap : direct_effective_aggs_vec) {
        size_t cnt = 0;

        const auto orig_frequency = aap.frequency;
        const auto orig_frequency_idx = get_index(allowed_frequencies, orig_frequency/params.get_base_period());
        sort_by_idx_dist(allowed_frequencies, orig_frequency_idx);

        const auto orig_amplitude = aap.amplitude;

        std::vector<int> allowed_phases;
        const auto num_aggressors = aap.aggressors.size();
        for (int i = 0; i <= (int) base_period - (int) num_aggressors; ++i) allowed_phases.push_back(i);

        const auto orig_start_offset = aap.start_offset;
        const auto orig_start_offset_idx = get_index(allowed_phases, orig_start_offset);
        sort_by_idx_dist(allowed_phases, orig_start_offset_idx);

        Logger::log_highlight(format_string("Original parameters (freq, ph, amp) = (%d, %d, %d)",
            orig_frequency/patt.base_period, orig_start_offset, orig_amplitude));

        // == FREQUENCY =======
        for (const auto &freq : allowed_frequencies) {

          // == PHASE =======
          for (const auto &phase : allowed_phases) {

            std::vector<int> allowed_amplitudes;
            for (int i = 1; (i*num_aggressors) <= base_period - phase; ++i) allowed_amplitudes.push_back(i);

            const auto orig_amplitude_idx = get_index(allowed_amplitudes, orig_amplitude);
            sort_by_idx_dist(allowed_amplitudes, orig_amplitude_idx);

            // == AMPLITUDE =======
            for (const auto &amplitude : allowed_amplitudes) {
              cnt++;

              std::vector<AggressorAccessPattern> aggs(indirect_effective_aggs.begin(), indirect_effective_aggs.end());
              // modify effective AggressorAccessPattern
              aap.frequency = freq*base_period;
              aap.start_offset = phase;
              aap.amplitude = amplitude;
              aggs.push_back(aap);

              Logger::log_highlight(format_string("ROUND %d | Parameters (freq, ph, amp) = (%d, %d, %d)",
                  cnt, freq, phase, amplitude));

              // back up the original AggressorAccessPatterns by moving them
              std::vector<AggressorAccessPattern> old_aaps = std::move(patt.agg_access_patterns);

              // fill up the slots in the pattern
              builder.prefill_pattern(pattern_total_acts, aggs);

              // NOTE: We don't include the FuzzingParameterSet that found the HammeringPattern in the JSON yet, so
              //  passing a new FuzzingParameterSet instance 'params' here could actually break things, e.g., if
              //  parameter ranges are too narrow and we cannot fill up the remaining slots
              builder.generate_frequency_based_pattern(params, patt.total_activations, patt.base_period);

              // as we changed the AggressorAccessPattern, the existing Agg ID -> DRAM Address mapping is not valid
              // anymore and we need to generate a new mapping
              // TODO: Maybe we should randomize fpa_probing_num_reps times to be sure that it just doesn't work because
              //  we are hammering at a unfavourable location? Alternatively, we could let the direct effective
              //  AggressorAccessPatterntarget always a target known-to-be vulnerable row so we can be sure that if we
              //  don't see any bit flips, it's not because of a bad location
              mapper.randomize_addresses(params, patt.agg_access_patterns, false);
              auto num_bitflips = ReplayingHammerer::hammer_pattern(mem, params, jitter, patt, mapper,
                  flushing_strategy, fencing_strategy, fpa_probing_num_reps, sync_each_ref, num_sync_aggs, total_acts,
                  false, false, false);
              if (num_bitflips==0) {
                Logger::log_failure("No bit flips found.");
              } else {
                Logger::log_success(format_string(
                    "Found %lu bit flips, on average %2.f per hammering rep (%d). Flipped row(s): %s.",
                    num_bitflips,
                    num_bitflips/(float) fpa_probing_num_reps,
                    fpa_probing_num_reps,
                    mem.get_flipped_rows_text_repr().c_str()));
              }

              // restore original AggressorAccessPatterns
              patt.agg_access_patterns = std::move(old_aaps);

              if (cnt%max_trials_per_aap==0) goto continue_next;
            }
          }
        }
        continue_next:
        Logger::log_info("Threshold for number of analysis runs reached, continuing with next AggressorAccessPattern.");
      }
    }
  }
}

std::vector<HammeringPattern> ReplayingHammerer::get_matching_patterns_from_json(const char *json_filename,
                                                                                 const char *pattern_ids) {
  // extract all HammeringPattern IDs from the given comma-separated string
  std::stringstream ids_str(pattern_ids);
  std::unordered_set<std::string> ids;
  while (ids_str.good()) {
    std::string substr;
    getline(ids_str, substr, ',');
    ids.insert(substr);
  }

  // open the JSON file
  std::ifstream ifs(json_filename);
  if (!ifs.is_open()) {
    Logger::log_error(format_string("Could not open given file (%s).", json_filename));
    exit(1);
  }

  // parse the JSON file and extract HammeringPatterns matching any of the given IDs
  nlohmann::json json_file = nlohmann::json::parse(ifs);
  std::vector<HammeringPattern> patterns;
  for (auto const &json_hammering_patt : json_file) {
    HammeringPattern pattern;
    from_json(json_hammering_patt, pattern);
    // after parsing, check if this pattern's ID matches one of the IDs given to '-replay_patterns'
    // Note: Due to a bug in the implementation, old raw_data.json files may contain multiple HammeringPatterns with the
    // same ID and the exact same pattern but a different mapping. In this case, we load ALL such patterns.
    if (ids.count(pattern.instance_id) > 0) {
      Logger::log_info(format_string("Found in JSON pattern with ID=%s and assoc. mappings:",
          pattern.instance_id.c_str()));
      for (const auto &mp : pattern.address_mappings) {
        Logger::log_data(format_string("%s (min row: %d, max row: %d)",
            mp.get_instance_id().c_str(), mp.min_row, mp.max_row));
      }
      patterns.push_back(pattern);
    }
  }
  return patterns;
}

size_t ReplayingHammerer::hammer_pattern(Memory &memory, FuzzingParameterSet &fuzz_params, CodeJitter &code_jitter,
                                         HammeringPattern &pattern, PatternAddressMapper &mapper,
                                         FLUSHING_STRATEGY flushing_strategy, FENCING_STRATEGY fencing_strategy,
                                         unsigned long num_reps, bool sync_each_ref, int aggressors_for_sync,
                                         int num_activations, bool verbose_sync, bool verbose_memcheck,
                                         bool verbose_params) {
  size_t num_bitflips = 0;

  // load victims for memory check
  mapper.determine_victims(pattern.agg_access_patterns);

  // transform pattern into vector of addresses
  std::vector<volatile char *> hammering_accesses_vec;
  mapper.export_pattern(pattern.aggressors, pattern.base_period, hammering_accesses_vec);

  // create instructions that follow this pattern (i.e., do jitting of code)
  code_jitter.jit_strict(fuzz_params, flushing_strategy, fencing_strategy, hammering_accesses_vec, sync_each_ref,
      aggressors_for_sync, num_activations);

  for (unsigned long num_tries = 0; num_tries < num_reps; num_tries++) {
    // TODO: Analyze using Hynix whether this waiting really makes sense, otherwise remove it
    // wait a specific time while doing some random accesses before starting hammering
    auto wait_until_hammering_us = fuzz_params.get_random_wait_until_start_hammering_microseconds();
    if (verbose_params) {
      FuzzingParameterSet::print_dynamic_parameters2(sync_each_ref, wait_until_hammering_us, aggressors_for_sync);
    }
    if (wait_until_hammering_us > 0) {
      std::vector<volatile char *> random_rows = mapper.get_random_nonaccessed_rows(fuzz_params.get_max_row_no());
      FuzzyHammerer::do_random_accesses(random_rows, wait_until_hammering_us);
    }

    // do hammering
    code_jitter.hammer_pattern(fuzz_params, verbose_sync);

    // check if any bit flips happened
    // it's important that we run in reproducibility mode, otherwise the bitflips vec in the mapping is changed!
    num_bitflips += memory.check_memory(mapper, true, verbose_memcheck);
  }

  code_jitter.cleanup();

  return num_bitflips;
}
