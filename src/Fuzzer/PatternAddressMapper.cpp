#include <set>
#include "Fuzzer/PatternAddressMapper.hpp"

#include "GlobalDefines.hpp"
#include "Utilities/Uuid.hpp"
#include "Utilities/Range.hpp"

PatternAddressMapper::PatternAddressMapper() : instance_id(uuid::gen_uuid()) { /* NOLINT */
  // standard mersenne_twister_engine seeded with rd()
  std::random_device rd;
  gen = std::mt19937(rd());
}

void PatternAddressMapper::randomize_addresses(FuzzingParameterSet &fuzzing_params,
                                               std::vector<AggressorAccessPattern> &agg_access_patterns) {
  // clear any already existing mapping
  aggressor_to_addr.clear();

  // retrieve and then store randomized values as they should be the same for all added addresses
  const int bank_no = fuzzing_params.get_random_bank_no();
  const bool use_seq_addresses = fuzzing_params.get_random_use_seq_addresses();
  const int start_row = fuzzing_params.get_random_start_row();
  FuzzingParameterSet::print_dynamic_parameters(bank_no, use_seq_addresses, start_row);

  size_t cur_row = start_row;

  // a set of DRAM rows that are already assigned to aggressors
  std::set<int> occupied_rows;

  // we can make use here of the fact that each aggressor (identified by its ID) has a fixed N, that means, is
  // either accessed individually (N=1) or in a group of multiple aggressors (N>1; e.g., N=2 for double sided)
  // => if we already know the address of any aggressor in an aggressor access pattern, we already must know
  // addresses for all of them as we must have accessed all of them together before
  size_t row;
  int assignment_trial_cnt = 0;

  for (auto &acc_pattern : agg_access_patterns) {
    for (size_t i = 0; i < acc_pattern.aggressors.size(); i++) {
      Aggressor &current_agg = acc_pattern.aggressors[i];
      if (aggressor_to_addr.count(current_agg.id) > 0) {
        row = aggressor_to_addr.at(current_agg.id).row;
      } else if (i > 0) {
        // if this aggressor has any partners (N>1), we need to add the appropriate distance and cannot choose randomly
        auto last_addr = aggressor_to_addr.at(acc_pattern.aggressors.at(i - 1).id);
        // update cur_row for its next use (note that here it is: cur_row = last_addr.row)
        cur_row = (last_addr.row + (size_t) fuzzing_params.get_agg_intra_distance())%fuzzing_params.get_max_row_no();
        row = cur_row;
      } else {
        // this is a new aggressor pair - we can choose where to place it
        // if use_seq_addresses is true, we use the last address and add the agg_inter_distance on top -> this is the
        //   row of the next aggressor
        // if use_seq_addresses is false, we just pick any random row no. between [0, 8192]
        cur_row = (cur_row + (size_t) fuzzing_params.get_agg_inter_distance())%fuzzing_params.get_max_row_no();

        retry:
        row = use_seq_addresses ?
              cur_row :
              (Range<int>(cur_row, cur_row + fuzzing_params.get_max_row_no()).get_random_number(gen)
                  %fuzzing_params.get_max_row_no());

        // check that we haven't assigned this address yet to another aggressor ID
        // if use_seq_addresses is True, the only way that the address is already assigned is that we already flipped
        // around the address range once (because of the modulo operator) so that retrying doesn't make sense
        if (!use_seq_addresses && occupied_rows.count(row) > 0) {
          assignment_trial_cnt++;
          if (assignment_trial_cnt < 7) goto retry;
          Logger::log_info(string_format(
              "Assigning unique addresses for Aggressor ID %d didn't succeed. Giving up after 3 trials.",
              current_agg.id));
        }
      }

      assignment_trial_cnt = 0;
      occupied_rows.insert(row);
      aggressor_to_addr.insert({current_agg.id, DRAMAddr(bank_no, row, 0)});
    }
  }

  // set to make sure we add victims only once
  std::set<volatile char *> victim_addresses;
  victim_rows.clear();
  for (auto &acc_pattern : agg_access_patterns) {
    for (auto &agg : acc_pattern.aggressors) {
      auto dram_addr = aggressor_to_addr.at(agg.id);
      for (int i = -5; i <= 5; ++i) {
        auto cur_row_candidate = dram_addr.row + i;
        auto victim_start = DRAMAddr(dram_addr.bank, cur_row_candidate, 0);
        if (victim_addresses.count((volatile char *) victim_start.to_virt())==0) {
          victim_rows.emplace_back((volatile char *) victim_start.to_virt(),
                                   (volatile char *) DRAMAddr(victim_start.bank, victim_start.row + 1, 0).to_virt());
          victim_addresses.insert((volatile char *) victim_start.to_virt());
        }
      }
    }
  }

  Logger::log_info(string_format("Found %d different aggressors (IDs) in pattern.", aggressor_to_addr.size()));
}

void PatternAddressMapper::export_pattern_internal(
    std::vector<Aggressor> &aggressors, size_t base_period,
    std::vector<volatile char *> &addresses,
    std::vector<int> &rows) {

  bool invalid_aggs = false;
  std::stringstream pattern_str;
  for (size_t i = 0; i < aggressors.size(); ++i) {
    // for better visualization: add blank line after each base period
    if (i!=0 && (i%base_period)==0) {
      pattern_str << std::endl;
    }

    // check whether this is a valid aggressor, i.e., the aggressor's ID != -1
    auto agg = aggressors[i];
    if (agg.id==ID_PLACEHOLDER_AGG) {
      pattern_str << FC_RED << "-1" << F_RESET;
      invalid_aggs = true;
      continue;
    }

    // check whether there exists a aggressor ID -> address mapping before trying to access it
    if (aggressor_to_addr.count(agg.id)==0) {
      Logger::log_error(string_format("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      continue;
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
    rows.push_back(aggressor_to_addr.at(agg.id).row);
    pattern_str << aggressor_to_addr.at(agg.id).row << " ";
  }

  // print string representation of pattern
//  Logger::log_info("Pattern filled by random DRAM rows:");
//  Logger::log_data(pattern_str.str());

  if (invalid_aggs) {
    Logger::log_error(
        "Found at least an invalid aggressor in the pattern. These aggressors were NOT added but printed to visualize their position.");
  }

  // writes the agg_id -> DRAMAddr mapping into the log file
  Logger::log_info("Aggressor ID to DRAM address mapping (bank, rank, column):");
  std::stringstream mapping_str;
  mapping_str << "{ ";
  size_t cnt = 0;
  for (const auto &p : aggressor_to_addr) {
    mapping_str << p.first << ": " << p.second.to_string_compact();
    cnt++;
    if (cnt < aggressor_to_addr.size()) mapping_str << ", ";
  }
  mapping_str << " }";
  Logger::log_data(mapping_str.str());
}

void PatternAddressMapper::export_pattern(
    std::vector<Aggressor> &aggressors, size_t base_period, std::vector<volatile char *> &addresses) {
  std::vector<int> dummy_vector;
  export_pattern_internal(aggressors, base_period, addresses, dummy_vector);
}

void PatternAddressMapper::export_pattern(
    std::vector<Aggressor> &aggressors, size_t base_period, std::vector<int> &rows) {
  std::vector<volatile char *> dummy_vector;
  export_pattern_internal(aggressors, base_period, dummy_vector, rows);
}

void PatternAddressMapper::export_pattern(
    std::vector<Aggressor> &aggressors, size_t base_period, int *rows, size_t max_rows) {
  std::vector<int> rows_vector;
  std::vector<volatile char *> dummy_vector;
  export_pattern_internal(aggressors, base_period, dummy_vector, rows_vector);

  if (max_rows < rows_vector.size()) {
    Logger::log_error("Exporting pattern failed! Given plain-C 'rows' array is too small to hold all aggressors.");
  }

  for (size_t i = 0; i < std::min(rows_vector.size(), max_rows); ++i) {
    rows[i] = rows_vector.at(i);
  }
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const PatternAddressMapper &p) {
  j = nlohmann::json{{"id", p.get_instance_id()},
                     {"aggressor_to_addr", p.aggressor_to_addr},
                     {"bit_flips", p.bit_flips},
  };
}

void from_json(const nlohmann::json &j, PatternAddressMapper &p) {
  j.at("id").get_to(p.get_instance_id());
  j.at("aggressor_to_addr").get_to(p.aggressor_to_addr);
  j.at("bit_flips").get_to(p.bit_flips);
}

#endif

const std::string &PatternAddressMapper::get_instance_id() const {
  return instance_id;
}

std::string &PatternAddressMapper::get_instance_id() {
  return instance_id;
}

const std::vector<std::pair<volatile char *, volatile char *>> &PatternAddressMapper::get_victim_rows() const {
  return victim_rows;
}
