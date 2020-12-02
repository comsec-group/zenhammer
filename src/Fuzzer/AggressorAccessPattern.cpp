#include "Fuzzer/AggressorAccessPattern.hpp"

void to_json(nlohmann::json &j, const AggressorAccessPattern &p) {
  j = nlohmann::json{{"frequency", p.frequency},
                     {"amplitude", p.amplitude},
                     {"offset_aggressor_map", p.offset_aggressor_map}
                     };
}

void from_json(const nlohmann::json &j, AggressorAccessPattern &p) {
  j.at("frequency").get_to(p.frequency);
  j.at("amplitude").get_to(p.amplitude);
  j.at("offset_aggressor_map").get_to(p.offset_aggressor_map);
}
