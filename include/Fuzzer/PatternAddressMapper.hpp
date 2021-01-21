#ifndef BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
#define BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_

#include <random>
#include <set>

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
                               size_t base_period,
                               std::vector<volatile char *> &addresses,
                               std::vector<int> &rows);

  std::vector<std::pair<volatile char *, volatile char *>> victim_rows{};

  // the unique identifier of this pattern-to-address mapping
  std::string instance_id;

  // a randomization engine
  std::mt19937 gen;

 public:
  std::unique_ptr<CodeJitter> code_jitter;

  PatternAddressMapper();

  // copy constructor
  PatternAddressMapper(const PatternAddressMapper& other);

  // copy assignment operator
  PatternAddressMapper& operator=(const PatternAddressMapper& other);

  // information about the mapping (required for determining rows not belonging to this mapping)
  int min_row{};
  int max_row{};
  int bank_no{};

  // a mapping from aggressors included in this pattern to memory addresses (DRAMAddr)
  std::unordered_map<AGGRESSOR_ID_TYPE, DRAMAddr> aggressor_to_addr{};

  // the bit flips that were detected while running the pattern with this mapping
  std::vector<BitFlip> bit_flips{};

  // the reproducibility score of this mapping, e.g.,
  //    1   => 100%: was reproducible in all reproducibility runs executed,
  //    0.4 => 40%: was reproducible in 40% of all reproducibility runs executed
  // (note: is zero initialized, i.e., value is also 0 in case that this pattern does not trigger bit flips at all)
  double reproducibility_score{};

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  void randomize_addresses(FuzzingParameterSet &fuzzing_params,
                           std::vector<AggressorAccessPattern> &agg_access_patterns,
                           bool verbose);

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, std::vector<int> &rows);

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, std::vector<volatile char *> &addresses);

  const std::string &get_instance_id() const;

  std::string &get_instance_id();

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, int *rows, size_t max_rows);

  const std::vector<std::pair<volatile char *, volatile char *>> &get_victim_rows() const;

  std::vector<volatile char *> get_random_nonaccessed_rows(int row_upper_bound);

  void determine_victims(std::vector<AggressorAccessPattern> &agg_access_patterns);

  std::string get_mapping_text_repr();

  void shift_mapping(int rows);

  CodeJitter & get_code_jitter() const;
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const PatternAddressMapper &p);

void from_json(const nlohmann::json &j, PatternAddressMapper &p);

#endif

#endif //BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
