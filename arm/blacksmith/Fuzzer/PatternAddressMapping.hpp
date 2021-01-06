#ifndef BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
#define BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_

#include <random>

#include "DRAMAddr.hpp"
#include "Fuzzer/Aggressor.hpp"
#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"

class PatternAddressMapping {
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


  // a randomization engine
  std::mt19937 gen;

  explicit PatternAddressMapping();

  explicit PatternAddressMapping(bool arm_mode);

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  // TODO: add bool allow_same_address_aggressors=false to control reuse of addresses for aggressors with different IDs
  void randomize_addresses(FuzzingParameterSet &fuzzing_params,
                           std::vector<AggressorAccessPattern> &agg_access_patterns);

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, std::vector<int> &rows);

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, std::vector<volatile char *> &addresses);

  const std::string &get_instance_id() const;

  std::string &get_instance_id();

  void export_pattern(std::vector<Aggressor> &aggressors, size_t base_period, int *rows, size_t max_rows);
};



#endif //BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_