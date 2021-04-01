#include "Utilities/TimeHelper.hpp"
#include "Forges/TraditionalHammerer.hpp"

#include <climits>
#include <Blacksmith.hpp>

void TraditionalHammerer::hammer(std::vector<volatile char *> &aggressors, size_t hammer_rounds) {
  for (size_t i = 0; i < hammer_rounds; i++) {
    for (auto &a : aggressors) {
      *a;
    }
    for (auto &a : aggressors) {
      clflushopt(a);
    }
    mfence();
  }
}

/// Performs hammering on given aggressor rows for HAMMER_ROUNDS times.
void TraditionalHammerer::hammer(std::vector<volatile char *> &aggressors) {
  hammer(aggressors, HAMMER_ROUNDS);
}

/// Performs synchronized hammering on the given aggressor rows.
void TraditionalHammerer::hammer_sync(std::vector<volatile char *> &aggressors, int acts,
                                      volatile char *d1, volatile char *d2) {

  size_t sync_acts = 0;
  size_t sync_rounds = 0;
//  Logger::log_debug(format_string("acts: %d", acts));
//  Logger::log_debug(format_string("aggressors.size(): %lu", aggressors.size()));
  size_t ref_rounds = std::max(1UL, acts/aggressors.size());

  // determines how often we are repeating
  size_t agg_rounds = ref_rounds;
  uint64_t before = 0;
  uint64_t after = 0;

  *d1;
  *d2;

  // synchronize with the beginning of an interval
  Logger::log_debug("after-before: ", false);
  while (true) {
    clflushopt(d1);
    clflushopt(d2);
    mfence();
    before = rdtscp();
    lfence();
    *d1;
    *d2;
    after = rdtscp();
    // check if an ACTIVATE was issued
    if ((after - before) > 1000) {
      break;
    }
  }

  // perform hammering for HAMMER_ROUNDS/ref_rounds times
  for (size_t i = 0; i < 5000000/aggressors.size(); i++) {
    for (size_t j = 0; j < agg_rounds; j++) {
      for (size_t k = 0; k < aggressors.size(); k++) {
        *aggressors[k];
        clflushopt(aggressors[k]);
      }
      mfence();
    }

    // after HAMMER_ROUNDS/ref_rounds times hammering, check for next ACTIVATE
    while (true) {
      mfence();
      lfence();
      before = rdtscp();
      lfence();
      *d1;
      *d2;
      after = rdtscp();
      lfence();
      clflushopt(d1);
      clflushopt(d2);
      sync_acts += 2;
      // stop if an ACTIVATE was issued
      if ((after - before) > 1000) {
        sync_rounds++;
        break;
      }
    }
  }
  Logger::log_debug(format_string("sync_acts/sync_rounds: %lu", sync_acts/sync_rounds));
}

void TraditionalHammerer::n_sided_hammer_experiment(Memory &memory, int acts) {
  // This implement the experiment showing the offset is an important factor when crafting patterns.
  // Randomly chooses a double-sided pair
  // Create a pattern of N ACTIVATEs (determine based on number of ACTs per tREF)
  // Loop over the offset (position of double-sided pair within pattern)
  // Place aggressors at current offset and randomize all other accesses
  // Hammer pattern for acts activations
  // Scan for flipped rows

#ifdef ENABLE_JSON
  nlohmann::json all_results = nlohmann::json::array();
  nlohmann::json current;
#endif

  const auto start_ts = get_timestamp_sec();

  int seed = rand();
  srand(seed);
  const auto num_aggs = 2;
  const auto pattern_length = (size_t) acts;

  const auto MAX_ROW = 2048;
  size_t MAX_AMPLITUDE = 5;
  const auto NUM_LOCATIONS = 5;
  int v = 2;  // distance between aggressors (within a pair)

  for (size_t loc = 0; loc < NUM_LOCATIONS; ++loc) {

    DRAMAddr start_addr = DRAMAddr(rand()%NUM_BANKS, rand()%MAX_ROW, 0);

    for (size_t cur_amplitude = 1; cur_amplitude < MAX_AMPLITUDE; ++cur_amplitude) {

      // start address/row
      for (size_t cur_offset = pattern_length-1; cur_offset > 0; --cur_offset) {

        Logger::log_debug(format_string("Running: cur_offset = %lu, cur_amplitude = %lu, loc = %lu/%lu",
            cur_offset, cur_amplitude, loc + 1, NUM_LOCATIONS));

        std::vector<volatile char *> aggressors;
        std::stringstream ss;

        // fill up the pattern with accesses
        ss << "agg row: ";
        DRAMAddr agg1 = start_addr;
        DRAMAddr agg2 = agg1.add(0, v, 0);
        Logger::log_info(
            format_string("agg1 row %" PRIu64 " (%p) agg2 row %" PRIu64 " (%p)",
                agg1.row, agg1.to_virt(),
                agg2.row, agg2.to_virt()));
        for (size_t pos = 0; pos < pattern_length;) {
          if (pos==cur_offset) {
            // add the aggressor pair
            for (size_t cnt = cur_amplitude; cnt > 0; --cnt) {
              aggressors.push_back((volatile char *) agg1.to_virt());
              ss << agg1.row << " ";
              pos++;
              aggressors.push_back((volatile char *) agg2.to_virt());
              ss << agg2.row << " ";
              pos++;
            }
          } else {
            // fill up the remaining accesses with random rows
            DRAMAddr agg = DRAMAddr(start_addr.bank, rand()%MAX_ROW, 0);
            ss << agg.row << " ";
            aggressors.push_back((volatile char *) agg.to_virt());
            pos++;
          }
        }
        Logger::log_data(ss.str());
//          Logger::log_debug(format_string("#aggs in pattern = %lu", aggressors.size()));

        if (aggressors.size()!=pattern_length) {
          Logger::log_debug("Skipping as given cur_offset + cur_amplitude would lead to a longer pattern.");
          continue;
        }

        // do the hammering
        if (!USE_SYNC) {
          // CONVENTIONAL HAMMERING
          Logger::log_info(format_string("Hammering %d aggressors", num_aggs));
          hammer(aggressors);
        } else if (USE_SYNC) {
          // SYNCHRONIZED HAMMERING
          // uses one dummy that are hammered repeatedly until the refresh is detected
          auto d1 = DRAMAddr(start_addr.bank, rand()%MAX_ROW, 0);
          auto d2 = d1.add(0, 2, 0);
          Logger::log_info(
              format_string("d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)",
                  d1.row, d1.to_virt(),
                  d2.row, d2.to_virt()));
          Logger::log_info(format_string("Hammering sync %d aggressors on bank %d", num_aggs, start_addr.bank));
          hammer_sync(aggressors, acts, (volatile char *) d1.to_virt(), (volatile char *) d2.to_virt());
        }

        // check 20 rows before and after the placed aggressors for flipped bits
        Logger::log_debug("Checking for flipped bits...");
        const auto check_rows_around = 20;
        auto num_bitflips =
            memory.check_memory((volatile char *) agg1.to_virt(),
                (volatile char *) agg1.add(0, 1, 0).to_virt(),
                check_rows_around);
        num_bitflips +=
            memory.check_memory((volatile char *) agg2.to_virt(),
                (volatile char *) agg2.add(0, 1, 0).to_virt(),
                check_rows_around);

#ifdef ENABLE_JSON
        current["cur_offset"] = cur_offset;
        current["cur_amplitude"] = cur_amplitude;
        current["location"] = loc;
        current["num_bitflips"] = num_bitflips;
        current["pattern_length"] = pattern_length;
        current["check_rows_around"] = check_rows_around;

        current["aggressors"] = nlohmann::json::array();
        nlohmann::json agg_1;
        DRAMAddr d((void *) aggressors[cur_offset]);
        agg_1["bank"] = d.bank;
        agg_1["row"] = d.row;
        agg_1["col"] = d.col;
        current["aggressors"].push_back(agg_1);
        nlohmann::json agg_2;
        DRAMAddr d2((void *) aggressors[cur_offset + 1]);
        agg_2["bank"] = d2.bank;
        agg_2["row"] = d2.row;
        agg_2["col"] = d2.col;
        current["aggressors"].push_back(agg_2);

        all_results.push_back(current);
#endif
      }
    }
  }

#ifdef ENABLE_JSON
  // export result into JSON
  std::ofstream json_export("experiment-summary.json");

  nlohmann::json meta;
  meta["start"] = start_ts;
  meta["end"] = get_timestamp_sec();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["dimm_id"] = program_args.dimm_id;
  meta["acts_per_tref"] = acts;
  meta["seed"] = seed;

  nlohmann::json root;
  root["metadata"] = meta;
  root["results"] = all_results;

  json_export << root << std::endl;
  json_export.close();
#endif
}

void TraditionalHammerer::n_sided_hammer_experiment_frequencies(Memory &memory) {
#ifdef ENABLE_JSON
  nlohmann::json root;
  nlohmann::json all_results = nlohmann::json::array();
  nlohmann::json current;
#endif
  const auto start_ts = get_timestamp_sec();

  // choose two aggressors between a row from that we know from previous runs that it is vulnerable
  // (Victor did the same on LPDDR: he did not choose the aggressor rows arbitrarily)
  auto agg_bank = 10;
  auto agg1 = DRAMAddr(agg_bank, 677, 0);
  auto agg2 = DRAMAddr(agg_bank, agg1.row + 2, 0);
#ifdef ENABLE_JSON
  root["aggressors"] = nlohmann::json::array();
  std::vector<DRAMAddr> aggs = {agg1, agg2};
  for (const auto agg: aggs) {
    nlohmann::json agg_1;
    agg_1["bank"] = agg.bank;
    agg_1["row"] = agg.row;
    agg_1["col"] = agg.col;
    root["aggressors"].push_back(agg_1);
  }
#endif

  // randomly choose two dummies (add 1000 to make sure it cannot be the same row as the aggs)
  DRAMAddr dmy1, dmy2;
  dmy1 = DRAMAddr(agg_bank, rand()%2048 + 1000, 0);
  dmy2 = DRAMAddr(agg_bank, dmy1.row + 2, 0);

#ifdef ENABLE_JSON
  root["dummies"] = nlohmann::json::array();
  std::vector<DRAMAddr> dummies = {dmy1, dmy2};
  for (const auto dmy: dummies) {
    nlohmann::json dmy_1;
    dmy_1["bank"] = dmy.bank;
    dmy_1["row"] = dmy.row;
    dmy_1["col"] = dmy.col;
    root["dummies"].push_back(dmy_1);
  }
#endif

  Logger::log_debug(format_string("agg rows: %lu, %lu", agg1.row, agg2.row));
  Logger::log_debug(format_string("dmy rows: %lu, %lu", dmy1.row, dmy2.row));

  const auto MAX_AGG_ROUNDS = 16; // 1...MAX_AGG_ROUNDS
  const auto DMY_ROUNDS = 64;     // 32...DMY_ROUNDS
  std::vector<volatile char *> aggressors;

  // build the pattern by first accessing the two aggressors, followed by the two dummies
  for (size_t agg_rounds = 1; agg_rounds < MAX_AGG_ROUNDS; ++agg_rounds) {

    for (size_t dummy_rounds = 32; dummy_rounds < DMY_ROUNDS; ++dummy_rounds) {
      Logger::log_debug(format_string("Running: agg_rounds = %lu, dummy_rounds = %lu", agg_rounds, dummy_rounds));

      // add aggressors to pattern
      for (size_t ard = 0; ard < agg_rounds; ++ard) {
        aggressors.push_back((volatile char *) agg1.to_virt());
        aggressors.push_back((volatile char *) agg2.to_virt());
      }

      // add dummies to pattern
      for (size_t drd = 0; drd < dummy_rounds; ++drd) {
        aggressors.push_back((volatile char *) dmy1.to_virt());
        aggressors.push_back((volatile char *) dmy2.to_virt());
      }

      // hammer the pattern
      Logger::log_info(format_string("Hammering %d aggs, %d dummies...", agg_rounds*2, dummy_rounds*2));
      const auto hammer_count = 8192*32;
      hammer(aggressors, hammer_count);

      // check rows before and after for flipped bits
      const auto check_rows_around = 5;
      auto sum_bitflips = memory.check_memory((volatile char *) agg1.to_virt(),
          (volatile char *) agg1.add(0, 1, 0).to_virt(),
          check_rows_around);
      sum_bitflips += memory.check_memory((volatile char *) agg2.to_virt(),
          (volatile char *) agg2.add(0, 1, 0).to_virt(),
          check_rows_around);

      // log results into JSON
#ifdef ENABLE_JSON
      current["agg_rounds"] = agg_rounds;
      current["dummy_rounds"] = dummy_rounds;
      current["num_bitflips"] = sum_bitflips;
      current["pattern_length"] = aggressors.size();
      current["check_rows_around"] = check_rows_around;
      all_results.push_back(current);
#endif
    }
  }

  // write JSON to disk
#ifdef ENABLE_JSON
  // export result into JSON
  std::ofstream json_export("experiment-hynix-summary.json");

  nlohmann::json meta;
  meta["start"] = start_ts;
  meta["end"] = get_timestamp_sec();
  meta["memory_config"] = DRAMAddr::get_memcfg_json();
  meta["dimm_id"] = program_args.dimm_id;

  root["metadata"] = meta;
  root["results"] = all_results;

  json_export << root << std::endl;
  json_export.close();
#endif
}

void TraditionalHammerer::n_sided_hammer(Memory &memory, int acts, long runtime_limit) {
  const auto execution_limit = get_timestamp_sec() + runtime_limit;
  while (get_timestamp_sec() < execution_limit) {
    srand(time(nullptr));

    int aggressor_rows_size = (rand()%(MAX_ROWS - 3)) + 3;  // number of aggressor rows
    int v = 2;  // distance between aggressors (within a pair)
    int d = (rand()%16);  // distance of each double-sided aggressor pair

    for (size_t ba = 0; ba < 4; ba++) {
      DRAMAddr cur_next_addr(ba, rand()%4096, 0);

      std::vector<volatile char *> aggressors;
      std::stringstream ss;

      ss << "agg row: ";
      for (int i = 1; i < aggressor_rows_size; i += 2) {
        cur_next_addr.add_inplace(0, d, 0);
        ss << cur_next_addr.row << " ";
        aggressors.push_back((volatile char *) cur_next_addr.to_virt());

        cur_next_addr.add_inplace(0, v, 0);
        ss << cur_next_addr.row << " ";
        aggressors.push_back((volatile char *) cur_next_addr.to_virt());
      }

      if ((aggressor_rows_size%2)!=0) {
        ss << cur_next_addr.row << " ";
        aggressors.push_back((volatile char *) cur_next_addr.to_virt());
      }
      Logger::log_data(ss.str());

      if (!USE_SYNC) {
        // CONVENTIONAL HAMMERING
        Logger::log_info(format_string("Hammering %d aggressors with v=%d d=%d on bank %d",
            aggressor_rows_size, v, d, ba));
        hammer(aggressors);
      } else if (USE_SYNC) {
        // SYNCHRONIZED HAMMERING
        // uses two dummies that are hammered repeatedly until the refresh is detected
        cur_next_addr.add_inplace(0, 100, 0);
        auto d1 = cur_next_addr;
        cur_next_addr.add_inplace(0, v, 0);
        auto d2 = cur_next_addr;
        Logger::log_info(format_string("d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)",
            d1.row, d1.to_virt(), d2.row, d2.to_virt()));
        if (ba==0) {
          Logger::log_info(format_string("sync: ref_rounds %lu, remainder %lu.", acts/aggressors.size(),
              acts - ((acts/aggressors.size())*aggressors.size())));
        }
        Logger::log_info(format_string("Hammering sync %d aggressors on bank %d", aggressor_rows_size, ba));
        hammer_sync(aggressors, acts, (volatile char *) d1.to_virt(), (volatile char *) d2.to_virt());
      }

      // check 100 rows before and after for flipped bits
      memory.check_memory(aggressors[0], aggressors[aggressors.size() - 1], 100);
    }
  }
}
