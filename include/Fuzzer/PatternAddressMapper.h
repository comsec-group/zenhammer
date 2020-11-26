#ifndef BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
#define BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_

#include "Fuzzer/HammeringPattern.hpp"

class PatternAddressMapper {
 public:
  // the unique identifier of this pattern-to-address mapping
  const std::string instance_id;

  // data about the pattern
  HammeringPattern &hammering_pattern;

  // a mapping from aggressors included in this pattern to memory addresses (DRAMAddr)
  std::unordered_map<AGGRESSOR_ID_TYPE, DRAMAddr> aggressor_to_addr;

  // a randomization engine
  std::mt19937 gen;

  // the lowest address of the
  volatile char *lowest_address;

  volatile char *highest_address;

  PatternAddressMapper(HammeringPattern &hp);

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  // TODO: add bool allow_same_address_aggressors=false to control reuse of addresses for aggressors with different IDs
  void randomize_addresses(size_t bank);

  // exports this pattern in a format that can be used by the CodeJitter
  std::vector<volatile char *> export_pattern_for_jitting();

  volatile char *get_lowest_address() const;

  volatile char *get_highest_address() const;
};

#endif //BLACKSMITH_INCLUDE_PATTERNADDRESSMAPPER_H_
