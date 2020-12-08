#include <Fuzzer/FuzzingParameterSet.hpp>
#include "Fuzzer/HammeringPattern.hpp"

void to_json(nlohmann::json &j, const HammeringPattern &p) {
  j = nlohmann::json{{"id", p.instance_id},
                     {"base_period", p.base_period},
                     {"max_period", p.max_period},
                     {"total_activations", p.total_activations},
                     {"num_refresh_intervals", p.num_refresh_intervals},
                     {"access_ids", Aggressor::get_agg_ids(p.accesses)},
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
  p.accesses = Aggressor::create_aggressors(agg_ids);

  j.at("agg_access_patterns").get_to<>(p.agg_access_patterns);
  j.at("address_mappings").get_to<>(p.address_mappings);
}

void HammeringPattern::generate_random_addr_mapping(FuzzingParameterSet &fuzzing_params,
                                                     PatternAddressMapping &pattern_address_mapping) {
  pattern_address_mapping.randomize_addresses(fuzzing_params, agg_access_patterns);
}

std::vector<volatile char *> HammeringPattern::get_jittable_accesses_vector(PatternAddressMapping &pattern_address_mapping) {
  return pattern_address_mapping.export_pattern_for_jitting(accesses, base_period);
}
