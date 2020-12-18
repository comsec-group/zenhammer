#ifndef AGGRESSORACCESSPATTERN
#define AGGRESSORACCESSPATTERN

#include <unordered_map>

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

#endif /* AGGRESSORACCESSPATTERN */
