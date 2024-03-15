#include "Fuzzer/PatternAddressMapper.hpp"

#include <algorithm>

#include "Fuzzer/HammeringPattern.hpp"
#include "GlobalDefines.hpp"
#include "Memory/DRAMConfig.hpp"
#include "Utilities/Uuid.hpp"

// initialize the bank_counter (static var)
int PatternAddressMapper::bank_counter = 0;

PatternAddressMapper::PatternAddressMapper()
    : instance_id(uuid::gen_uuid()) { /* NOLINT */
  code_jitter = std::make_unique<CodeJitter>();

  // standard mersenne_twister_engine seeded with rd()
  std::random_device rd;
  gen = std::mt19937(rd());
}

void PatternAddressMapper::randomize_addresses(FuzzingParameterSet &fuzzing_params,
                                               const std::vector<AggressorAccessPattern> &agg_access_patterns,
                                               bool verbose) {
  // clear any already existing mapping
  aggressor_to_addr.clear();

  // retrieve and then store randomized values as they should be the same for all added addresses
  // (store bank_no as field for get_random_nonaccessed_rows)
  bank_no = PatternAddressMapper::bank_counter;
  PatternAddressMapper::bank_counter = static_cast<int>(
    (PatternAddressMapper::bank_counter + 1) % DRAMConfig::get().banks());
  const bool use_seq_addresses = fuzzing_params.get_random_use_seq_addresses();
  const int start_row = fuzzing_params.get_random_start_row();
  if (verbose) FuzzingParameterSet::print_dynamic_parameters(bank_no, use_seq_addresses, start_row);

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
  Logger::log_info(format_string("[PatternAddressMapper] Target no. of DRAM rows = %d",
      fuzzing_params.get_num_aggressors()));
  Logger::log_info(format_string("[PatternAddressMapper] Aggressors in AggressorAccessPattern = %d",
      total_abstract_aggs));

  // probability to map aggressor to same row as another aggressor is already mapped to
  const int prob2 = 100 - (
      static_cast<int>(
          std::min(static_cast<double>(fuzzing_params.get_num_aggressors())/static_cast<double>(total_abstract_aggs),1.0)*100));
  Logger::log_info(format_string("[PatternAddressMapper] Probability to map multiple AAPs to same DRAM row = %d", prob2));

  std::random_device device;
  std::mt19937 engine(device()); // Seed the random number engine
  std::vector<int> weights = std::vector<int>({100-prob2, prob2});
  std::discrete_distribution<> dist(weights.begin(), weights.end()); // Create the distribution

  Logger::log_info("[PatternAddressMapper] weights =");
  for (const auto &w : weights) {
    Logger::log_data(format_string("%d", w));
  }

//  Logger::log_info("Generating 1k random numbers to see how well distribution works ");
//  size_t cnt_0 = 0;
//  size_t cnt_1 = 0;
//  for (size_t i = 0; i < 1000; ++i) {
//    if (dist(engine) == 0)
//      cnt_0++;
//    else
//      cnt_1++;
//  }
//  Logger::log_info(format_string("cnt_0 = %lu", cnt_0));
//  Logger::log_info(format_string("cnt_1 = %lu", cnt_1));

  for (auto &acc_pattern : agg_access_patterns) {
    for (size_t i = 0; i < acc_pattern.aggressors.size(); i++) {
      const Aggressor &current_agg = acc_pattern.aggressors.at(i);

      // aggressor has existing row mapping OR
      if (aggressor_to_addr.count(current_agg.id) > 0) {
        row = aggressor_to_addr.at(current_agg.id).row;
      } else if (i > 0) {  // aggressor is part of a n>1 aggressor tuple
        // we need to add the appropriate distance and cannot choose randomly
        auto last_addr = aggressor_to_addr.at(acc_pattern.aggressors.at(i - 1).id);
        // update cur_row for its next use (note that here it is: cur_row = last_addr.row)
        cur_row = (last_addr.row + (size_t) fuzzing_params.get_agg_intra_distance())%fuzzing_params.get_max_row_no();
        row = cur_row;
      } else {
        // this is a new aggressor pair - we can choose where to place it
        // if use_seq_addresses is true, we use the last address and add the agg_inter_distance on top -> this is the
        //   row of the next aggressor
        // if use_seq_addresses is false, we just pick any random row number
        cur_row = (cur_row + (size_t) fuzzing_params.get_agg_inter_distance())%fuzzing_params.get_max_row_no();

        bool map_to_existing_agg = dist(engine);
        if (map_to_existing_agg && !occupied_rows.empty()) {
            auto idx = Range<size_t>(1, occupied_rows.size()).get_random_number(gen)-1;
            auto it = occupied_rows.begin();
            while (idx--) it++;
            row = *it;
        } else {
        retry:
          row = use_seq_addresses ?
                cur_row :
                (Range<size_t>(cur_row, cur_row + fuzzing_params.get_max_row_no()).get_random_number(gen)
                    %fuzzing_params.get_max_row_no());

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

      assignment_trial_cnt = 0;
      occupied_rows.insert(row);
      aggressor_to_addr.insert(std::make_pair(current_agg.id, DRAMAddr(static_cast<size_t>(bank_no), row, 0)));
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
  // check ROW_THRESHOLD rows around the aggressors for flipped bits
  const int ROW_THRESHOLD = 5;
  // a set to make sure we add victims only once
  victim_rows.clear();
  for (auto &acc_pattern : agg_access_patterns) {
    for (auto &agg : acc_pattern.aggressors) {

      if (aggressor_to_addr.count(agg.id)==0) {
        Logger::log_error(format_string("Could not find DRAMAddr mapping for Aggressor %d", agg.id));
        exit(EXIT_FAILURE);
      }

      const auto dram_addr = aggressor_to_addr.at(agg.id);

      for (int delta_nrows = -ROW_THRESHOLD; delta_nrows <= ROW_THRESHOLD; ++delta_nrows) {
        auto cur_row_candidate = static_cast<int>(dram_addr.row) + delta_nrows;

        // don't add the aggressor itself and ignore any non-existing (negative) row no.
        if (delta_nrows == 0 || cur_row_candidate < 0)
          continue;

        // ignore this victim if we already added it before
        auto victim_start = DRAMAddr(dram_addr.bank, static_cast<size_t>(cur_row_candidate), 0);
        if (victim_rows.count(static_cast<volatile char *>(victim_start.to_virt())) > 0)
          continue;

        victim_rows.insert(static_cast<volatile char *>(victim_start.to_virt()));
      }
    }
  }
}

std::vector<volatile char*> PatternAddressMapper::export_pattern_with_fence_every_nth_access(const HammeringPattern& pattern, int n) {
  // Insert memory barrier after every N-th access.
  assert(n > 0);

  std::vector<volatile char*> addresses;
  for (size_t i = 0; i < pattern.aggressors.size(); ++i) {
    // Check whether this is a valid aggressor, i.e., the aggressor's ID != -1.
    auto agg = pattern.aggressors[i];
    if (agg.id == ID_PLACEHOLDER_AGG) {
      Logger::log_error("Found at least an invalid aggressor in the pattern.");
      exit(EXIT_FAILURE);
    }

    // Check whether there exists an aggressor ID -> address mapping before trying to access it.
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      exit(EXIT_FAILURE);
    }

    if (i % n == 0) {
      addresses.push_back(nullptr);
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
  }

  return addresses;
}

std::vector<volatile char*> PatternAddressMapper::export_pattern_with_fence_per_base_period(const HammeringPattern& pattern, int fences_per_base_period) {
  // Insert memory barrier after every N-th access.
  assert(fences_per_base_period > 0);

  // Find before which indices (mod base_period) to fence.
  std::vector<size_t> indices_mod;
  size_t tmp = 0;
  for (size_t i = 0; i < (size_t)pattern.base_period; i++) {
    if (i == tmp * pattern.base_period / fences_per_base_period) {
      indices_mod.push_back(i);
      tmp++;
    }
  }
  assert(indices_mod.size() == (size_t)fences_per_base_period);

  Logger::log_info(format_string("Fencing every base_period/%d, which are the following indices (mod base_period):", fences_per_base_period));
  for (auto index : indices_mod) {
    Logger::log_data(format_string("%zu ", index), false);
  }
  Logger::log_data("");

  std::vector<volatile char*> addresses;
  size_t current_index = 0;
  for (size_t i = 0; i < pattern.aggressors.size(); ++i) {
    // Check whether this is a valid aggressor, i.e., the aggressor's ID != -1.
    auto agg = pattern.aggressors[i];
    if (agg.id == ID_PLACEHOLDER_AGG) {
      Logger::log_error("Found at least an invalid aggressor in the pattern.");
      exit(EXIT_FAILURE);
    }

    // Check whether there exists an aggressor ID -> address mapping before trying to access it.
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      exit(EXIT_FAILURE);
    }

    if (i % pattern.base_period == indices_mod[current_index]) {
      addresses.push_back(nullptr);
      current_index = (current_index + 1) % indices_mod.size();
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
  }

  return addresses;
}

std::vector<volatile char*> PatternAddressMapper::export_pattern_with_fence_none(const HammeringPattern& pattern) {
  std::vector<volatile char*> addresses;

  // Ensure pattern always starts with a fence.
  addresses.push_back(nullptr);

  for (auto agg : pattern.aggressors) {
    // Check whether this is a valid aggressor, i.e., the aggressor's ID != -1.
    if (agg.id == ID_PLACEHOLDER_AGG) {
      Logger::log_error("Found at least an invalid aggressor in the pattern.");
      exit(EXIT_FAILURE);
    }

    // Check whether there exists an aggressor ID -> address mapping before trying to access it.
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      exit(EXIT_FAILURE);
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
  }

  return addresses;
}

std::vector<volatile char*> PatternAddressMapper::export_pattern_with_fence_all(const HammeringPattern& pattern) {
  std::vector<volatile char*> addresses;

  // Ensure pattern always starts with a fence.
  addresses.push_back(nullptr);

  for (auto agg : pattern.aggressors) {
    // Check whether this is a valid aggressor, i.e., the aggressor's ID != -1.
    if (agg.id == ID_PLACEHOLDER_AGG) {
      Logger::log_error("Found at least an invalid aggressor in the pattern.");
      exit(EXIT_FAILURE);
    }

    // Check whether there exists an aggressor ID -> address mapping before trying to access it.
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      exit(EXIT_FAILURE);
    }

    // Add fence.
    addresses.push_back(nullptr);

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
  }

  return addresses;
}

std::vector<volatile char*> PatternAddressMapper::export_pattern_with_fence_between_tuples(const HammeringPattern& pattern) {
  // Insert memory barrier each time the pattern switches to a different aggressor tuple.
  // For this, we need to find each time a new tuple is hammered.

  std::vector<volatile char*> addresses;
  const auto& start_indices = pattern.get_tuple_start_indices();
  auto next_start_index = start_indices.begin();
  for (size_t i = 0; i < pattern.aggressors.size(); ++i) {
    // Check whether this is a valid aggressor, i.e., the aggressor's ID != -1.
    auto agg = pattern.aggressors[i];
    if (agg.id == ID_PLACEHOLDER_AGG) {
      Logger::log_error("Found at least an invalid aggressor in the pattern.");
      exit(EXIT_FAILURE);
    }

    // Check whether there exists an aggressor ID -> address mapping before trying to access it.
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      exit(EXIT_FAILURE);
    }

    // Check whether we need to insert a memory barrier (i.e., nullptr) before this aggressor.
    if (next_start_index != start_indices.end() && *next_start_index == i) {
      addresses.push_back(nullptr);
      ++next_start_index;
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
  }

  return addresses;
}

std::vector<volatile char*> PatternAddressMapper::export_pattern_with_fence_between_tuple_iterations(const HammeringPattern& pattern) {
  // Insert memory barrier after each tuple iteration.
  // For this, we need to find each time a new tuple is hammered.
  //
  // EXAMPLE
  // Tuples:   (1,2), (3,4)
  // Pattern:  |1 2|1 2|1 2|3 4|3 4 (and repeat)

  std::vector<volatile char*> addresses;
  const auto& start_indices = pattern.get_tuple_iteration_start_indices();
  auto next_start_index = start_indices.begin();
  for (size_t i = 0; i < pattern.aggressors.size(); ++i) {
    // Check whether this is a valid aggressor, i.e., the aggressor's ID != -1.
    auto agg = pattern.aggressors[i];
    if (agg.id == ID_PLACEHOLDER_AGG) {
      Logger::log_error("Found at least an invalid aggressor in the pattern.");
      exit(EXIT_FAILURE);
    }

    // Check whether there exists an aggressor ID -> address mapping before trying to access it.
    if (aggressor_to_addr.count(agg.id) == 0) {
      Logger::log_error(format_string("Could not find a valid address mapping for aggressor with ID %d.", agg.id));
      exit(EXIT_FAILURE);
    }

    // Check whether we need to insert a memory barrier (i.e., nullptr) before this aggressor.
    if (next_start_index != start_indices.end() && *next_start_index == i) {
      addresses.push_back(nullptr);
      ++next_start_index;
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    addresses.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
  }

  return addresses;
}

static SCHEDULING_POLICY get_default_scheduling_policy_for_uarch() {
  auto uarch = DRAMConfig::get().get_uarch();
  switch (uarch) {
    case Microarchitecture::AMD_ZEN_1_PLUS:
    case Microarchitecture::AMD_ZEN_2:
      return SCHEDULING_POLICY::REPETITON;
    case Microarchitecture::AMD_ZEN_3:
      return SCHEDULING_POLICY::PAIR;
    case Microarchitecture::INTEL_COFFEE_LAKE:
      return SCHEDULING_POLICY::FULL;
    default:
      Logger::log_error(format_string("Error: No default scheduling policy available for microarchitecture %s.", to_string(uarch)));
      exit(EXIT_FAILURE);
  }
}

std::vector<volatile char*> PatternAddressMapper::export_pattern(const HammeringPattern& pattern, SCHEDULING_POLICY scheduling_policy) {
  if (scheduling_policy == SCHEDULING_POLICY::DEFAULT)
    scheduling_policy = get_default_scheduling_policy_for_uarch();

  Logger::log_debug(format_string("Using SCHEDULING_POLICY::%s to export pattern.", to_string(scheduling_policy).c_str()));

  switch (scheduling_policy) {
    case SCHEDULING_POLICY::NONE:
      return export_pattern_with_fence_none(pattern);
    case SCHEDULING_POLICY::FULL:
      return export_pattern_with_fence_all(pattern);
    case SCHEDULING_POLICY::BASE_PERIOD:
      return export_pattern_with_fence_per_base_period(pattern, 1);
    case SCHEDULING_POLICY::HALF_BASE_PERIOD:
      return export_pattern_with_fence_per_base_period(pattern, 2);
    case SCHEDULING_POLICY::PAIR:
      return export_pattern_with_fence_between_tuples(pattern);
    case SCHEDULING_POLICY::REPETITON:
      return export_pattern_with_fence_between_tuple_iterations(pattern);
    default:
      assert(false && "Unreachable.");
  }
}


std::string PatternAddressMapper::get_mapping_text_repr() {
  // get all keys (this is to not assume that keys always must start by 1) and sort them
  std::vector<int> keys;
  for (auto const &map: aggressor_to_addr) keys.push_back(map.first);
  std::sort(keys.begin(), keys.end());

  // iterate over keys and build text representation
  size_t cnt = 0;
  std::stringstream mapping_str;
  for (const auto &k : keys) {
    if (cnt > 0 && cnt%3==0) mapping_str << std::endl;
    mapping_str << std::setw(3) << std::left << k
                << " -> "
                << std::setw(13) << std::left << aggressor_to_addr.at(k).to_string_compact()
                << "   ";
    cnt++;
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
                     {"bank_no", p.bank_no},
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
  j.at("bank_no").get_to(p.bank_no);
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

const std::unordered_set<volatile char *> &PatternAddressMapper::get_victim_rows() const {
  return victim_rows;
}

std::vector<volatile char *> PatternAddressMapper::get_random_nonaccessed_rows(int row_upper_bound) {
  // we don't mind if addresses are added multiple times
  std::vector<volatile char *> addresses;
  for (int i = 0; i < 1024; ++i) {
    auto row_no = Range<int>(max_row, max_row + min_row).get_random_number(gen)%row_upper_bound;
    addresses.push_back(
        static_cast<volatile char*>(DRAMAddr(static_cast<size_t>(bank_no), static_cast<size_t>(row_no), 0).to_virt()));
  }
  return addresses;
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
      agg_acc_patt.second.row += rows;
      occupied_rows.insert(static_cast<int>(agg_acc_patt.second.row));
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
      bank_no(other.bank_no),
      aggressor_to_addr(other.aggressor_to_addr),
      bit_flips(other.bit_flips),
      reproducibility_score(other.reproducibility_score) {
  code_jitter = std::make_unique<CodeJitter>();
  code_jitter->num_aggs_for_sync = other.get_code_jitter().num_aggs_for_sync;
  code_jitter->total_activations = other.get_code_jitter().total_activations;
  code_jitter->fencing_strategy = other.get_code_jitter().fencing_strategy;
  code_jitter->flushing_strategy = other.get_code_jitter().flushing_strategy;
  code_jitter->pattern_sync_each_ref = other.get_code_jitter().pattern_sync_each_ref;
  std::random_device rd;
  gen = std::mt19937(rd());
}

PatternAddressMapper &PatternAddressMapper::operator=(const PatternAddressMapper &other) {
  if (this==&other) return *this;
  victim_rows = other.victim_rows;
  instance_id = other.instance_id;
  gen = other.gen;

  code_jitter = std::make_unique<CodeJitter>();
  code_jitter->num_aggs_for_sync = other.get_code_jitter().num_aggs_for_sync;
  code_jitter->total_activations = other.get_code_jitter().total_activations;
  code_jitter->fencing_strategy = other.get_code_jitter().fencing_strategy;
  code_jitter->flushing_strategy = other.get_code_jitter().flushing_strategy;
  code_jitter->pattern_sync_each_ref = other.get_code_jitter().pattern_sync_each_ref;

  min_row = other.min_row;
  max_row = other.max_row;
  bank_no = other.bank_no;

  aggressor_to_addr = other.aggressor_to_addr;
  bit_flips = other.bit_flips;
  reproducibility_score = other.reproducibility_score;

  return *this;
}

void PatternAddressMapper::compute_mapping_stats(std::vector<AggressorAccessPattern> &agg_access_patterns,
                                                 int &agg_intra_distance, int &agg_inter_distance,
                                                 bool uses_seq_addresses) {
  Logger::log_info("Deriving mapping parameters from AggressorAccessPatterns.");

  // find first AggressorAccessPattern with more than one aggressor, then compute distance in-between aggressors
  agg_intra_distance = 0;
  for (auto &agg_access_pattern : agg_access_patterns) {
    if (agg_access_pattern.aggressors.size() > 1) {
      auto r1 = aggressor_to_addr.at(agg_access_pattern.aggressors.at(1).id).row;
      auto r0 = aggressor_to_addr.at(agg_access_pattern.aggressors.at(0).id).row;
      agg_intra_distance = static_cast<int>(r1-r0);
      break;
    }
  }

  // if all consecutive AggressorAccessPatterns have the same inter-distance, then they use "sequential addresses"
  uses_seq_addresses = true;
  agg_inter_distance = -1;
  for (auto it = agg_access_patterns.begin(); it+1 != agg_access_patterns.end(); ++it) {
    auto this_size = it->aggressors.size();
    auto this_row = aggressor_to_addr.at(it->aggressors.at(this_size-1).id).row;
    auto next_row = aggressor_to_addr.at((it+1)->aggressors.at(0).id).row;
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
    smallest_row_no = std::min(smallest_row_no, addr.row);
  }

  // compute offset between old start row and new start row
  size_t offset = new_location.row - smallest_row_no;

  // now update each mapping's address
  for (auto &[id, addr]: aggressor_to_addr) {
    // we just overwrite the bank
    addr.bank = new_location.bank;
    // for the row, we need to shift accordingly to preserve the distances between aggressors
    addr.row += offset;
  }
}
