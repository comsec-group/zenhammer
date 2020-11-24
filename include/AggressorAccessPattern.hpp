#ifndef AGGRESSORACCESSPATTERN
#define AGGRESSORACCESSPATTERN

#include <unordered_map>

#include "Aggressor.hpp"

class AggressorAccessPattern {
 public:
  size_t frequency;

  int amplitude;

  std::unordered_map<int, Aggressor> offset_aggressor_map;

  AggressorAccessPattern(size_t frequency, int amplitude, std::unordered_map<int, Aggressor> off_aggs)
      : frequency(frequency), amplitude(amplitude), offset_aggressor_map(off_aggs) {
  }
};

#endif /* AGGRESSORACCESSPATTERN */
