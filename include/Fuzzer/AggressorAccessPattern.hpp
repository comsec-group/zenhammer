#ifndef AGGRESSORACCESSPATTERN
#define AGGRESSORACCESSPATTERN

#include <unordered_map>
#include <utility>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Fuzzer/Aggressor.hpp"

class AggressorAccessPattern {
 public:
  size_t frequency{};

  int amplitude{};

  size_t start_offset{};

  std::vector<Aggressor> aggressors;

  AggressorAccessPattern() = default;

  AggressorAccessPattern(size_t frequency,
                         int amplitude,
                         std::vector<Aggressor> aggressors,
                         size_t absolute_offset)
      : frequency(frequency),
        amplitude(amplitude),
        start_offset(absolute_offset),
        aggressors(std::move(aggressors)) {
  }
};

void to_json(nlohmann::json &j, const AggressorAccessPattern &p);

void from_json(const nlohmann::json &j, AggressorAccessPattern &p);

#endif /* AGGRESSORACCESSPATTERN */
