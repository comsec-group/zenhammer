#ifndef HAMMERING_PATTERN
#define HAMMERING_PATTERN

#include <iostream>
#include <random>
#include <unordered_map>
#include <vector>

#include "Fuzzer/AggressorAccessPattern.hpp"
#include "Utilities/Range.hpp"
#include "Utilities/Uuid.hpp"

class HammeringPattern {
 public:
  const std::string instance_id;

  // the base period this hammering pattern was generated for
  size_t base_period;

  // the order in which accesses happen
  std::vector<Aggressor> accesses;

  // additional and more structured information about the aggressors involved in this pattern such as whether they are 1-sided or 2-sided
  std::vector<AggressorAccessPattern> agg_access_patterns;

  HammeringPattern() : instance_id(uuid::gen_uuid()) {};
};

#endif /* HAMMERING_PATTERN */
