#ifndef HAMMERING_PATTERN
#define HAMMERING_PATTERN

#include <iostream>
#include <random>
#include <unordered_map>
#include <vector>
#include <nlohmann/json.hpp>

#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Utilities/Range.hpp"
#include "Utilities/Uuid.hpp"
#include "PatternAddressMapping.hpp"

class HammeringPattern {
 public:
  std::string instance_id;

  // the base period this hammering pattern was generated for
  size_t base_period{};

  size_t max_period{};

  size_t total_activations{};

  size_t num_refresh_intervals{};

  // the order in which accesses happen
  std::vector<Aggressor> accesses;

  // additional and more structured information about the aggressors involved in this pattern such as whether they are 1-sided or 2-sided
  std::vector<AggressorAccessPattern> agg_access_patterns;

  // from an OOP perspective it would make more sense to have a reference to this HammeringPattern in each of the
  // PatternAddressMapping objects; however, for the JSON export having this vector of mappings for a pattern works
  // better because we need to foreign keys and can easily associate this HammeringPattern to N PatternAddressMappings
  std::vector<PatternAddressMapping> address_mappings;

  HammeringPattern() : instance_id(uuid::gen_uuid()) {};

  explicit HammeringPattern(size_t base_period);

};

void to_json(nlohmann::json &j, const HammeringPattern &p);

void from_json(const nlohmann::json &j, HammeringPattern &p);

#endif /* HAMMERING_PATTERN */
