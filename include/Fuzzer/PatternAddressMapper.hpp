#ifndef BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
#define BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_

#include <random>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Fuzzer/Aggressor.hpp"
#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Fuzzer/BitFlip.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"

class PatternAddressMapper {
 private:
  void export_pattern_internal(std::vector<Aggressor> &aggressors,
                               size_t base_period,
                               std::vector<volatile char *> &addresses,
                               std::vector<int> &rows);

  // the lowest address among all aggressors
  volatile char *lowest_address{nullptr};

  // the highest address among all aggressors
  volatile char *highest_address{nullptr};

  // the unique identifier of this pattern-to-address mapping
  std::string instance_id;

  bool arm_mode{false};

 public:
  // a mapping from aggressors included in this pattern to memory addresses (DRAMAddr)
  std::unordered_map<AGGRESSOR_ID_TYPE, DRAMAddr> aggressor_to_addr;

  std::vector<BitFlip> bit_flips;

  // a randomization engine
  std::mt19937_64 gen;

  explicit PatternAddressMapper();

  explicit PatternAddressMapper(bool arm_mode);

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  // TODO: add bool allow_same_address_aggressors=false to control reuse of addresses for aggressors with different IDs
  void randomize_addresses(FuzzingParameterSet &fuzzing_params,
                           std::vector<AggressorAccessPattern> &agg_access_patterns);

  volatile char *get_lowest_address() const;

  volatile char *get_highest_address() const;

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, std::vector<int> &rows);

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, std::vector<volatile char *> &addresses);

  const std::string &get_instance_id() const;

  std::string &get_instance_id();

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, int *rows, size_t max_rows);
};

void to_json(nlohmann::json &j, const PatternAddressMapper &p);

void from_json(const nlohmann::json &j, PatternAddressMapper &p);

#endif //BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
