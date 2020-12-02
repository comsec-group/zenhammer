#include "Fuzzer/Aggressor.hpp"

std::string Aggressor::to_string() const {
  if (id==ID_PLACEHOLDER_AGG) return "EMPTY";
  std::stringstream ss;
  ss << "agg" << std::setfill('0') << std::setw(2) << id;
  return ss.str();
}

void to_json(nlohmann::json &j, const Aggressor &p) {
  j = nlohmann::json{{"id", p.id}};
}

void from_json(const nlohmann::json &j, Aggressor &p) {
  j.at("id").get_to(p.id);
}
