#include "Fuzzer/AggressorAccessPattern.hpp"

void to_json(nlohmann::json &j, const AggressorAccessPattern &p) {
  j = nlohmann::json{{"frequency", p.frequency},
                     {"amplitude", p.amplitude},
                     {"start_offset", p.start_offset},
                     {"offset_aggressor_map", p.offset_aggressor_map}
  };
}

void from_json(const nlohmann::json &j, AggressorAccessPattern &p) {
  j.at("frequency").get_to(p.frequency);
  j.at("amplitude").get_to(p.amplitude);
  j.at("start_offset").get_to(p.start_offset);
  j.at("offset_aggressor_map").get_to(p.offset_aggressor_map);
}
