#ifndef RANGE
#define RANGE

#include <random>

/// A range is equivalent to the mathematical notation [i,j] where i,j ∈ ℕ.
struct Range {
  int min;
  int max;
  std::uniform_int_distribution<> dist;

  Range() = default;

  Range(int min, int max) : min(min), max(max), dist(std::uniform_int_distribution<>(min, max)) {}

  Range(int min, int max, bool ensure_order) {
    int new_min = min;
    int new_max = max;
    if (ensure_order) {
      if (min >= max) {
        new_min = max;
        new_max = min;
      }
    }
    min = new_min;
    max = new_max;
    dist = std::uniform_int_distribution<>(new_min, new_max);
  }

  int get_random_number(std::mt19937 &gen) {
    return dist(gen);
  }

  int get_random_number(int upper_bound, std::mt19937 &gen) {
    if (max > upper_bound) dist = std::uniform_int_distribution<>(min, upper_bound);
    return dist(gen);
  }
};

#endif /* RANGE */
