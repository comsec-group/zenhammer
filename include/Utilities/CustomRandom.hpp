#ifndef ZENHAMMER_INCLUDE_UTILITIES_CUSTOMRANDOM_HPP
#define ZENHAMMER_INCLUDE_UTILITIES_CUSTOMRANDOM_HPP

#include <cstdint>
#include <random>

#define PSEUDORANDOM (1)

static const uint64_t SEED = 859345892ULL;

class CustomRandom {
public:
  std::mt19937 gen;

  explicit CustomRandom();
};

#endif //ZENHAMMER_INCLUDE_UTILITIES_CUSTOMRANDOM_HPP
