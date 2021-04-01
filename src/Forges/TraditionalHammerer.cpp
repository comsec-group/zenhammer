#include "Utilities/TimeHelper.hpp"
#include "Forges/TraditionalHammerer.hpp"

#include <climits>
#include <Blacksmith.hpp>

/// Performs hammering on given aggressor rows for HAMMER_ROUNDS times.
void TraditionalHammerer::hammer(std::vector<volatile char *> &aggressors) {
  for (size_t i = 0; i < HAMMER_ROUNDS; i++) {
    for (auto &a : aggressors) {
      *a;
    }
    for (auto &a : aggressors) {
      clflushopt(a);
    }
    mfence();
  }
}

/// Performs synchronized hammering on the given aggressor rows.
void TraditionalHammerer::hammer_sync(std::vector<volatile char *> &aggressors, int acts,
                                      volatile char *d1, volatile char *d2) {
  size_t ref_rounds = std::max(1UL,acts/aggressors.size());

  // determines how often we are repeating
  size_t agg_rounds = ref_rounds;
  uint64_t before = 0;
  uint64_t after = 0;

  *d1;
  *d2;

  // synchronize with the beginning of an interval
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
  for (size_t i = 0; i < HAMMER_ROUNDS/ref_rounds; i++) {
    for (size_t j = 0; j < agg_rounds; j++) {
      for (size_t k = 0; k < aggressors.size() - 2; k++) {
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
      clflushopt(d1);
      *d1;
      clflushopt(d2);
      *d2;
      after = rdtscp();
      lfence();
      // stop if an ACTIVATE was issued
      if ((after - before) > 1000) break;
    }
  }
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

  const auto start_ts = time(nullptr);
  srand(start_ts);
  const auto num_aggs = 2;
  const auto pattern_length = (size_t)acts;

  int v = 2;  // distance between aggressors (within a pair)

  size_t low_row_no;
  void* low_row_vaddr;
  size_t high_row_no;
  void* high_row_vaddr;

  auto update_low_high = [&](DRAMAddr &dramAddr) {
    if (dramAddr.row < low_row_no) {
      low_row_no = dramAddr.row;
      low_row_vaddr = dramAddr.to_virt();
    }
    if (dramAddr.row > high_row_no) {
      high_row_no = dramAddr.row;
      high_row_vaddr = dramAddr.to_virt();
    }
  };

  const auto TARGET_BANK = 0;
  const auto NUM_LOCATIONS = 10;
  const size_t MAX_AMPLITUDE = 5;

  for (size_t cur_location = 1; cur_location <= NUM_LOCATIONS; ++cur_location) {
    // start address/row
    DRAMAddr cur_next_addr(TARGET_BANK, rand()%2048, 0);

    for (size_t cur_amplitude = 1; cur_amplitude < MAX_AMPLITUDE; ++cur_amplitude) {

      for (size_t cur_offset = 75; cur_offset < pattern_length - (num_aggs - 1); ++cur_offset) {

        Logger::log_debug(format_string("Running: cur_offset = %lu, cur_amplitude = %lu, cur_location = %lu/%lu",
            cur_offset, cur_amplitude, cur_location, NUM_LOCATIONS));

        low_row_no = std::numeric_limits<size_t>::max();
        low_row_vaddr = nullptr;
        high_row_no = std::numeric_limits<size_t>::min();
        high_row_vaddr = nullptr;

        std::vector<volatile char *> aggressors;
        std::stringstream ss;

        // fill up the pattern with accesses
        ss << "agg row: ";
        for (size_t pos = 0; pos < pattern_length;) {
          if (pos==cur_offset) {
            // add the aggressor pair
            DRAMAddr agg1 = cur_next_addr;
            DRAMAddr agg2 = agg1.add(0, v, 0);
            ss << agg1.row << " ";
            ss << agg2.row << " ";
            update_low_high(agg1);
            update_low_high(agg2);
            for (size_t cnt = cur_amplitude; cnt > 0; --cnt) {
              aggressors.push_back((volatile char *) agg1.to_virt());
              aggressors.push_back((volatile char *) agg2.to_virt());
              pos += 2;
            }
          } else {
            // fill up the remaining accesses with random rows
            DRAMAddr agg(TARGET_BANK, rand()%1024, 0);
//          update_low_high(agg);
            ss << agg.row << " ";
            aggressors.push_back((volatile char *) agg.to_virt());
            pos++;
          }
        }
        Logger::log_data(ss.str());
      Logger::log_debug(format_string("#aggs in pattern = %lu", aggressors.size()));

        // do the hammering
        if (!USE_SYNC) {
          // CONVENTIONAL HAMMERING
          Logger::log_info(format_string("Hammering %d aggressors on bank %d", num_aggs, TARGET_BANK));
          hammer(aggressors);
        } else if (USE_SYNC) {
          // SYNCHRONIZED HAMMERING
          // uses one dummy that are hammered repeatedly until the refresh is detected
        cur_next_addr.add_inplace(0, 100, 0);
        auto d1 = cur_next_addr;
        cur_next_addr.add_inplace(0, 2, 0);
        auto d2 = cur_next_addr;
          Logger::log_info(
              format_string("d1 row %" PRIu64 " (%p) d2 row %" PRIu64 " (%p)",
                  d1.row, d1.to_virt(),
                  d2.row, d2.to_virt()));

          Logger::log_info(format_string("Hammering sync %d aggressors on bank %d", num_aggs, TARGET_BANK));
          hammer_sync(aggressors, acts, (volatile char *) d1.to_virt(), (volatile char *) d2.to_virt());
        }

        // check 20 rows before and after the placed aggressors for flipped bits
        Logger::log_debug("Checking for flipped bits...");
        const auto check_rows_around = 20;
      auto num_bitflips = memory.check_memory((volatile char*)low_row_vaddr, (volatile char*)high_row_vaddr,
            check_rows_around);
#ifdef ENABLE_JSON
        current["cur_offset"] = cur_offset;
        current["cur_amplitude"] = cur_amplitude;
        current["location"] = cur_location;
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
meta["seed"] = start_ts;

nlohmann::json root;
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
