#ifndef AGGRESSORACCESSPATTERN
#define AGGRESSORACCESSPATTERN

#include <unordered_map>
#include <utility>
#include <nlohmann/json.hpp>

#include "Fuzzer/Aggressor.hpp"

class AggressorAccessPattern {
 public:
  size_t frequency{};

  int amplitude{};

  size_t start_offset{};

  std::unordered_map<int, Aggressor> offset_aggressor_map;

  AggressorAccessPattern() = default;

  AggressorAccessPattern(size_t frequency,
                         int amplitude,
                         std::unordered_map<int, Aggressor> off_aggs,
                         size_t absolute_offset)
      : frequency(frequency),
        amplitude(amplitude),
        start_offset(absolute_offset),
        offset_aggressor_map(std::move(off_aggs)) {
  }
};

void to_json(nlohmann::json &j, const AggressorAccessPattern &p);

void from_json(const nlohmann::json &j, AggressorAccessPattern &p);

#endif /* AGGRESSORACCESSPATTERN */
