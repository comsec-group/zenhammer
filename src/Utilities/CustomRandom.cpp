#include "Utilities/CustomRandom.hpp"

CustomRandom::CustomRandom() {
  gen = std::mt19937((PSEUDORANDOM) ? SEED : std::random_device{}());
}
