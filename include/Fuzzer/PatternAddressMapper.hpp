#ifndef BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
#define BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_

#include <random>
#include <set>
#include <utility>
#include <unordered_set>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Fuzzer/Aggressor.hpp"
#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Fuzzer/BitFlip.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/CodeJitter.hpp"

class PatternAddressMapper {
 private:
  void export_pattern_internal(std::vector<Aggressor> &aggressors,
                               int base_period,
                               std::vector<volatile char *> &addresses,
                               std::vector<int> &rows);

  std::vector<SimpleDramAddress> victim_rows;

  CustomRandom cr;

  // the unique identifier of this pattern-to-address mapping
  std::string instance_id;

  std::vector<size_t> cluster_ids;

  static size_t cluster_ids_idx;


public:
  std::unique_ptr<CodeJitter> code_jitter;

  PatternAddressMapper(Memory &mem);

  // copy constructor
  PatternAddressMapper(const PatternAddressMapper& other);

  // copy assignment operator
  PatternAddressMapper& operator=(const PatternAddressMapper& other);

  // information about the mapping (required for determining rows not belonging to this mapping)
  size_t min_row = 0;
  size_t max_row = 0;

  // a mapping from aggressors included in this pattern to memory addresses (DRAMAddr)
  std::unordered_map<AGGRESSOR_ID_TYPE, SimpleDramAddress> aggressor_to_addr;

  // the bit flips that were detected while running the pattern with this mapping
  std::vector<std::vector<BitFlip>> bit_flips;

  // the reproducibility score of this mapping, e.g.,
  //    1   => 100%: was reproducible in all reproducibility runs executed,
  //    0.4 => 40%: was reproducible in 40% of all reproducibility runs executed
  int reproducibility_score = -1;

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  void randomize_addresses(FuzzingParameterSet &fuzzing_params,
                           const std::vector<AggressorAccessPattern> &agg_access_patterns,
                           bool verbose,
                           Memory &mem);

  void remap_aggressors(SimpleDramAddress &new_location);

  void export_pattern(std::vector<Aggressor> &aggressors, int base_period, std::vector<volatile char *> &addresses);

  [[nodiscard]] const std::string &get_instance_id() const;

  std::string &get_instance_id();

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, int *rows, size_t max_rows);

  [[nodiscard]] const std::vector<SimpleDramAddress> & get_victim_rows() const;

  void determine_victims(const std::vector<AggressorAccessPattern> &agg_access_patterns,
                         Memory &mem);

  std::string get_mapping_text_repr();

  [[nodiscard]] CodeJitter & get_code_jitter() const;

  [[maybe_unused]] void compute_mapping_stats(std::vector<AggressorAccessPattern> &agg_access_patterns, int &agg_intra_distance,
                             int &agg_inter_distance, bool uses_seq_addresses);

  void shift_mapping(int rows, const std::unordered_set<AggressorAccessPattern> &aggs_to_move);

  [[nodiscard]] size_t count_bitflips() const;
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const PatternAddressMapper &p);

void from_json(const nlohmann::json &j, PatternAddressMapper &p);

#endif

#endif //BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
