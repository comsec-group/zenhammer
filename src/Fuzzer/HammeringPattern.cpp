#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/HammeringPattern.hpp"

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const HammeringPattern &p) {
  j = nlohmann::json{{"id", p.instance_id},
                     {"base_period", p.base_period},
                     {"max_period", p.max_period},
                     {"total_activations", p.total_activations},
                     {"num_refresh_intervals", p.num_refresh_intervals},
                     {"access_ids", Aggressor::get_agg_ids(p.aggressors)},
                     {"agg_access_patterns", p.agg_access_patterns},
                     {"address_mappings", p.address_mappings}
  };
}

void from_json(const nlohmann::json &j, HammeringPattern &p) {
  j.at("instance_id").get_to(p.instance_id);
  j.at("base_period").get_to(p.base_period);
  j.at("max_period").get_to(p.max_period);
  j.at("total_activations").get_to(p.total_activations);
  j.at("num_refresh_intervals").get_to(p.num_refresh_intervals);

  std::vector<AGGRESSOR_ID_TYPE> agg_ids;
  j.at("accesses_agg_ids").get_to<std::vector<AGGRESSOR_ID_TYPE>>(agg_ids);
  p.aggressors = Aggressor::create_aggressors(agg_ids);

  j.at("agg_access_patterns").get_to<>(p.agg_access_patterns);
  j.at("address_mappings").get_to<>(p.address_mappings);
}

#endif

HammeringPattern::HammeringPattern(size_t base_period)
    : instance_id(uuid::gen_uuid()),
      base_period(base_period),
      max_period(0),
      total_activations(0),
      num_refresh_intervals(0) {}

HammeringPattern::HammeringPattern()
    : instance_id(uuid::gen_uuid()),
      base_period(0),
      max_period(0),
      total_activations(0),
      num_refresh_intervals(0) {}
