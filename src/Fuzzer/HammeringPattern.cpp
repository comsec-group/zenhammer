#include "Fuzzer/HammeringPattern.hpp"

void to_json(nlohmann::json &j, const HammeringPattern &p) {
  j = nlohmann::json{{"id", p.instance_id},
                     {"base_period", p.base_period},
                     {"accesses", p.accesses},
                     {"agg_access_patterns", p.agg_access_patterns}
  };
}

void from_json(const nlohmann::json &j, HammeringPattern &p) {
  j.at("instance_id").get_to(p.instance_id);
  j.at("base_period").get_to(p.base_period);
  j.at("accesses").get_to<std::vector<Aggressor>>(p.accesses);
  j.at("agg_access_patterns").get_to<>(p.agg_access_patterns);
}

