#ifndef BLACKSMITH_INCLUDE_UTILITIES_CUSTOMRANDOM_H
#define BLACKSMITH_INCLUDE_UTILITIES_CUSTOMRANDOM_H

#include <cstdint>
#include <random>

#define PSEUDORANDOM (1)

static const uint64_t SEED = 859345892ULL;

class CustomRandom {
public:
  std::mt19937 gen;

  explicit CustomRandom();
};

#endif //BLACKSMITH_INCLUDE_UTILITIES_CUSTOMRANDOM_H
