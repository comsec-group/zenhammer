#include "Fuzzer/AggressorAccessPattern.hpp"

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const AggressorAccessPattern &p) {
  j = nlohmann::json{{"frequency", p.frequency},
                     {"amplitude", p.amplitude},
                     {"start_offset", p.start_offset},
                     {"aggressors", Aggressor::get_agg_ids(p.aggressors)}
  };
}

void from_json(const nlohmann::json &j, AggressorAccessPattern &p) {
  j.at("frequency").get_to(p.frequency);
  j.at("amplitude").get_to(p.amplitude);
  j.at("start_offset").get_to(p.start_offset);
  std::vector<AGGRESSOR_ID_TYPE> agg_ids;
  j.at("aggressors").get_to(agg_ids);
  p.aggressors = Aggressor::create_aggressors(agg_ids);
}

#endif
