#include "Fuzzer/PatternAddressMapper.hpp"

#include <algorithm>
#include <iostream>

#include "GlobalDefines.hpp"
#include "Utilities/Uuid.hpp"
#include "Memory/Memory.hpp"

// static variable initialization
// size_t PatternAddressMapper::bank_counter = 0;
// size_t PatternAddressMapper::bankgroup_counter = 0;
// size_t PatternAddressMapper::sc_counter = 0;
DRAMAddr PatternAddressMapper::pattern_start_row{};

PatternAddressMapper::PatternAddressMapper()
    : cr(CustomRandom()), instance_id(uuid::gen_uuid(cr.gen)) {
  code_jitter = std::make_unique<CodeJitter>();
}

void PatternAddressMapper::randomize_addresses(FuzzingParameterSet &fuzzing_params,
                                               const std::vector<AggressorAccessPattern> &agg_access_patterns,
                                               bool verbose) {



  // clear any already existing mapping
  aggressor_to_addr.clear();

  const bool use_seq_addresses = fuzzing_params.get_random_use_seq_addresses();
  // auto bank_no = PatternAddressMapper::bank_counter;
  // auto bankgroup_no = PatternAddressMapper::bankgroup_counter;
  // auto sc_no = PatternAddressMapper::sc_counter;
  // PatternAddressMapper::bank_counter = (PatternAddressMapper::bank_counter + 1);
  // PatternAddressMapper::bankgroup_counter = (PatternAddressMapper::bankgroup_counter + 1);
  // PatternAddressMapper::sc_counter = (PatternAddressMapper::sc_counter + 1);
  pattern_start_row.increment_all_common();

  const int start_row = fuzzing_params.get_random_start_row();
  // if (verbose) FuzzingParameterSet::print_dynamic_parameters(bank_no, use_seq_addresses, start_row);

  auto cur_row = static_cast<size_t>(start_row);

  // a set of DRAM rows that are already assigned to aggressors
  std::set<size_t> occupied_rows;

  // we can make use here of the fact that each aggressor (identified by its ID) has a fixed N, that means, is
  // either accessed individually (N=1) or in a group of multiple aggressors (N>1; e.g., N=2 for double sided)
  // => if we already know the address of any aggressor in an aggressor access pattern, we already must know
  // addresses for all of them as we must have accessed all of them together before
  size_t row;
  int assignment_trial_cnt = 0;

  size_t total_abstract_aggs = 0;
  for (auto &acc_pattern : agg_access_patterns) total_abstract_aggs += acc_pattern.aggressors.size();
  Logger::log_debug(format_string("[PatternAddressMapper] Target no. of DRAM rows = %d",
      fuzzing_params.get_num_aggressors()));
  Logger::log_debug(format_string("[PatternAddressMapper] Aggressors in AggressorAccessPattern = %d",
      total_abstract_aggs));

  // probability to map aggressor to same row as another aggressor is already mapped to
  const int prob2 = 100 - (
      static_cast<int>(std::min(
          static_cast<double>(fuzzing_params.get_num_aggressors())/
          static_cast<double>(total_abstract_aggs),1.0)*100));
  Logger::log_debug(format_string("[PatternAddressMapper] Probability to map multiple AAPs to same DRAM row = %d", prob2));

  std::random_device device;
  std::mt19937 engine(device()); // Seed the random number engine
  std::vector<int> weights = std::vector<int>({100-prob2, prob2});
  std::discrete_distribution<> dist(weights.begin(), weights.end()); // Create the distribution

  std::stringstream ss_weights;
  for (const auto &w : weights) ss_weights << w << " ";
  Logger::log_debug(format_string("[PatternAddressMapper] weights = %s", ss_weights.str().c_str()));

  for (auto &acc_pattern : agg_access_patterns) {
    for (size_t i = 0; i < acc_pattern.aggressors.size(); i++) {
      const Aggressor &current_agg = acc_pattern.aggressors.at(i);

      // aggressor has existing row mapping OR
      if (aggressor_to_addr.count(current_agg.id) > 0) {
        row = aggressor_to_addr.at(current_agg.id).get_row();
      } else {
        if (i > 0) {  // aggressor is part of a n>1 aggressor tuple
          // we need to add the appropriate distance and cannot choose randomly
          auto last_addr = aggressor_to_addr.at(acc_pattern.aggressors.at(i - 1).id);
          // update cur_row for its next use (note that here it is: cur_row = last_addr.row)
          cur_row = (last_addr.get_row() + (size_t) fuzzing_params.get_agg_intra_distance());
          row = cur_row;
        } else {
          // this is a new aggressor pair - we can choose where to place it
          // if use_seq_addresses is true, we use the last address and add the agg_inter_distance on top -> this is the
          //   row of the next aggressor
          // if use_seq_addresses is false, we just pick any random row no. between [0, 8192]
          cur_row = (cur_row + (size_t) fuzzing_params.get_agg_inter_distance());

         bool map_to_existing_agg = dist(engine);
          if (map_to_existing_agg && !occupied_rows.empty()) {
              auto idx = Range<size_t>(1, occupied_rows.size()).get_random_number(cr.gen)-1;
              auto it = occupied_rows.begin();
              while (idx--) it++;
              row = *it;
          } else {
          retry:
            row = use_seq_addresses ?
                  cur_row :
                  Range<size_t>(cur_row, cur_row + 10).get_random_number(cr.gen);

            // check that we haven't assigned this address yet to another aggressor ID
            // if use_seq_addresses is True, the only way that the address is already assigned is that we already flipped
            // around the address range once (because of the modulo operator) so that retrying doesn't make sense
            if (!use_seq_addresses && occupied_rows.count(row) > 0) {
              assignment_trial_cnt++;
              if (assignment_trial_cnt < 7) goto retry;
              Logger::log_info(format_string(
                  "Assigning unique addresses for Aggressor ID %d didn't succeed. Giving up after 3 trials.",
                  current_agg.id));
            }
          }
        }
      }

      assignment_trial_cnt = 0;
      occupied_rows.insert(row);
      pattern_start_row.set_row(row);
      aggressor_to_addr.insert(std::make_pair(current_agg.id, pattern_start_row));
    }
  }

  // determine victim rows
  determine_victims(agg_access_patterns);

  // this works as sets are always ordered
  min_row = *occupied_rows.begin();
  max_row = *occupied_rows.rbegin();

  if (verbose)
    Logger::log_info(format_string("Found %d different aggressors (IDs) in pattern.", aggressor_to_addr.size()));
}

void PatternAddressMapper::determine_victims(const std::vector<AggressorAccessPattern> &agg_access_patterns) {
  std::unordered_set<uint64_t> victim_vaddrs;

  // check row_blast_radius rows around the aggressors for flipped bits
  const int row_blast_radius = 3;
  // a set to make sure we add victims only once
  victim_rows.clear();
  for (auto &acc_pattern : agg_access_patterns) {
    for (const auto &agg : acc_pattern.aggressors) {
      if (aggressor_to_addr.count(agg.id) == 0) {
        Logger::log_error(format_string("Could not find DRAMAddr mapping for Aggressor %d", agg.id));
        exit(EXIT_FAILURE);
      }

      const auto dram_addr = aggressor_to_addr.at(agg.id);
      for (int delta_nrows = -row_blast_radius; delta_nrows <= row_blast_radius; ++delta_nrows) {
          auto cur_row_candidate = static_cast<int>(dram_addr.get_row()) + delta_nrows;
        // don't add the aggressor itself and ignore any non-existing (negative) row no.
        if (delta_nrows == 0 || cur_row_candidate < 0)
          continue;

        auto vic_start = aggressor_to_addr[agg.id];
        vic_start.set_row((size_t)((int)vic_start.get_row()+delta_nrows));
        
        // ignore this victim if we already added it before
        if (victim_vaddrs.find((uint64_t)vic_start.to_virt()) == victim_vaddrs.end()) {
          victim_rows.push_back(vic_start);
          victim_vaddrs.insert((uint64_t)vic_start.to_virt());
        }
      }
    }
  }
}

void PatternAddressMapper::export_pattern_internal(
    std::vector<Aggressor> &aggressors, int base_period,
    std::vector<volatile char *> &addresses,
    std::vector<int> &rows) {

  bool invalid_aggs = false;
  std::stringstream pattern_str;
  for (size_t i = 0; i < aggressors.size(); ++i) {
    // for better visualization: add linebreak after each base period
    if (i!=0 && (i%base_period)==0) {
      pattern_str << "\n";
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
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      continue;
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
    rows.push_back(static_cast<int>(aggressor_to_addr.at(agg.id).get_row()));
    pattern_str << aggressor_to_addr.at(agg.id).get_row() << " ";
  }

  // print string representation of pattern
//  Logger::log_info("Pattern filled by random DRAM rows:");
//  Logger::log_data(pattern_str.str());

  if (invalid_aggs) {
    Logger::log_error(
        "Found at least an invalid aggressor in the pattern. "
        "These aggressors were NOT added but printed to visualize their position.");
    Logger::log_data(pattern_str.str());
  }
}

void PatternAddressMapper::export_pattern(
    std::vector<Aggressor> &aggressors, int base_period, std::vector<volatile char *> &addresses) {
  std::vector<int> dummy_vector;
  export_pattern_internal(aggressors, base_period, addresses, dummy_vector);
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

std::string PatternAddressMapper::get_mapping_text_repr() {
  // get all keys (this is to not assume that keys always must start by 1) and sort them
  std::vector<int> keys;
  for (auto const &map: aggressor_to_addr) keys.push_back(map.first);
  std::sort(keys.begin(), keys.end());

  // iterate over keys and build text representation
  std::stringstream mapping_str;
  for (const auto &k : keys) {
    mapping_str << std::setw(3) << std::setfill(' ') << std::left << k
                << " -> "
                << std::setw(22) << std::setfill(' ') << std::left
                <<  aggressor_to_addr.at(k).to_string_compact()
                << "   "
                << "\n";
  }

  return mapping_str.str();
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const PatternAddressMapper &p) {
  if (p.code_jitter==nullptr) {
    Logger::log_error("CodeJitter is nullptr! Cannot serialize PatternAddressMapper without causing segfault.");
    return;
  }

  j = nlohmann::json{{"id", p.get_instance_id()},
                    {"aggressor_to_addr", p.aggressor_to_addr},
                     {"bit_flips", p.bit_flips},
                     {"min_row", p.min_row},
                     {"max_row", p.max_row},
                     {"reproducibility_score", p.reproducibility_score},
                     {"code_jitter", *p.code_jitter}
  };
}

void from_json(const nlohmann::json &j, PatternAddressMapper &p) {
  j.at("id").get_to(p.get_instance_id());
 j.at("aggressor_to_addr").get_to(p.aggressor_to_addr);
  j.at("bit_flips").get_to(p.bit_flips);
  j.at("min_row").get_to(p.min_row);
  j.at("max_row").get_to(p.max_row);
  j.at("reproducibility_score").get_to(p.reproducibility_score);
  p.code_jitter = std::make_unique<CodeJitter>();
  j.at("code_jitter").get_to(*p.code_jitter);
}

#endif

const std::string &PatternAddressMapper::get_instance_id() const {
  return instance_id;
}

std::string &PatternAddressMapper::get_instance_id() {
  return instance_id;
}

const std::vector<DRAMAddr> & PatternAddressMapper::get_victim_rows() const {
  return victim_rows;
}

void PatternAddressMapper::shift_mapping(int rows, const std::unordered_set<AggressorAccessPattern> &aggs_to_move) {
  std::set<int> occupied_rows;

  // collect the aggressor ID of the aggressors given in the aggs_to_move set
  std::unordered_set<AGGRESSOR_ID_TYPE> movable_ids;
  for (const auto &agg_pair : aggs_to_move) {
    for (const auto &agg : agg_pair.aggressors) {
      movable_ids.insert(agg.id);
    }
  }

  for (auto &agg_acc_patt : aggressor_to_addr) {
    // if aggs_to_move is empty, we consider it as 'move all aggressors'; otherwise we check whether the current
    // aggressor ID is in aggs_to_move prior shifting the aggressor by the given number of rows (param: rows)
    if (aggs_to_move.empty() || movable_ids.count(agg_acc_patt.first) > 0) {
      agg_acc_patt.second.add_inplace(0, 0, 0, rows, 0);
      occupied_rows.insert(static_cast<int>(agg_acc_patt.second.get_row()));
    }
  }

  // this works as sets are always ordered
  min_row = *occupied_rows.begin();
  max_row = *occupied_rows.rbegin();
}

CodeJitter &PatternAddressMapper::get_code_jitter() const {
  return *code_jitter;
}

PatternAddressMapper::PatternAddressMapper(const PatternAddressMapper &other)
    : victim_rows(other.victim_rows),
      instance_id(other.instance_id),
      min_row(other.min_row),
      max_row(other.max_row),
      aggressor_to_addr(other.aggressor_to_addr),
      bit_flips(other.bit_flips),
      reproducibility_score(other.reproducibility_score) {
  code_jitter = std::make_unique<CodeJitter>();
  code_jitter->total_activations = other.get_code_jitter().total_activations;
  code_jitter->fencing_strategy = other.get_code_jitter().fencing_strategy;
  code_jitter->flushing_strategy = other.get_code_jitter().flushing_strategy;
}

PatternAddressMapper &PatternAddressMapper::operator=(const PatternAddressMapper &other) {
  if (this==&other) return *this;
  victim_rows = other.victim_rows;
  instance_id = other.instance_id;

  code_jitter = std::make_unique<CodeJitter>();
  code_jitter->total_activations = other.get_code_jitter().total_activations;
  code_jitter->fencing_strategy = other.get_code_jitter().fencing_strategy;
  code_jitter->flushing_strategy = other.get_code_jitter().flushing_strategy;

  min_row = other.min_row;
  max_row = other.max_row;

  aggressor_to_addr = other.aggressor_to_addr;
  bit_flips = other.bit_flips;
  reproducibility_score = other.reproducibility_score;

  return *this;
}

[[maybe_unused]] void PatternAddressMapper::compute_mapping_stats(std::vector<AggressorAccessPattern> &agg_access_patterns,
                                                 int &agg_intra_distance, int &agg_inter_distance,
                                                 bool uses_seq_addresses) {
  Logger::log_info("Deriving mapping parameters from AggressorAccessPatterns.");

  if (agg_access_patterns.size() == 0) {
    Logger::log_highlight("Cannot derive mapping params from AggressorAccessPatterns as cannot be found!");
    return;
  }

  // find first AggressorAccessPattern with more than one aggressor, then compute distance in-between aggressors
  agg_intra_distance = 0;
  for (auto &agg_access_pattern : agg_access_patterns) {
    if (agg_access_pattern.aggressors.size() > 1) {
      auto r1 = aggressor_to_addr.at(agg_access_pattern.aggressors.at(1).id).get_row();
      auto r0 = aggressor_to_addr.at(agg_access_pattern.aggressors.at(0).id).get_row();
      agg_intra_distance = static_cast<int>(r1-r0);
      break;
    }
  }

  // if all consecutive AggressorAccessPatterns have the same inter-distance, then they use "sequential addresses"
  uses_seq_addresses = true;
  agg_inter_distance = -1;
  for (auto it = agg_access_patterns.begin(); it+1 != agg_access_patterns.end(); ++it) {
    auto this_size = it->aggressors.size();
    auto this_row = aggressor_to_addr.at(it->aggressors.at(this_size-1).id).get_row();
    auto next_row = aggressor_to_addr.at((it+1)->aggressors.at(0).id).get_row();
    auto distance = static_cast<int>(next_row - this_row);
    if (agg_inter_distance == -1) {
        agg_inter_distance = distance;
    } else if (agg_inter_distance != distance) {
      uses_seq_addresses = false;
      break;
    }
  }

  Logger::log_data(format_string("inter-distance v = %d", agg_inter_distance));
  Logger::log_data(format_string("intra-distance d = %d", agg_intra_distance));
  Logger::log_data(format_string("use_seq_addresses = %s", (uses_seq_addresses ? "true" : "false")));
}

size_t PatternAddressMapper::count_bitflips() const {
  size_t sum = 0;
  for (const auto &bf : bit_flips) sum += bf.size();
  return sum;
}

void PatternAddressMapper::remap_aggressors(DRAMAddr &new_location) {
  // determine the mapping with the smallest row no -- this is the start point where we apply our new location on
  size_t smallest_row_no = std::numeric_limits<size_t>::max();
  for (const auto &[id, addr]: aggressor_to_addr) {
    smallest_row_no = std::min(smallest_row_no, addr.get_row());
  }

  // compute offset between old start row and new start row
  int offset = (int)new_location.get_row() - (int)smallest_row_no;

  // now update each mapping's address
  for (auto &[id, addr]: aggressor_to_addr) {
    // we just overwrite the bank
    addr = DRAMAddr(new_location.get_subchan(),
      new_location.get_rank(),
      new_location.get_bankgroup(),
      new_location.get_bank(), 
      offset,
      new_location.get_column());
    // addr.bank = new_location.bank;
    // addr.bankgroup = new_location.bankgroup;
    // addr.subchan = new_location.subchan;
    // for the row, we need to shift accordingly to preserve the distances between aggressors
    // addr.add_inplace(0, 0, 0, 0, offset, 0);
  }
}
