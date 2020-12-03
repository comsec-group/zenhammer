#ifndef RANGE
#define RANGE

#include <random>

template<typename T = int>
struct Range {
  T min{0};
  T max{0};
  std::uniform_int_distribution<T> dist;

  Range() = default;

  Range(T min, T max) : min(min), max(max), dist(std::uniform_int_distribution<T>(min, max)) {}

  Range(T min, T max, bool ensure_order) {
    T new_min = min;
    T new_max = max;
    if (ensure_order) {
      if (min >= max) {
        new_min = max;
        new_max = min;
      }
    }
    min = new_min;
    max = new_max;
    dist = std::uniform_int_distribution<T>(new_min, new_max);
  }

  T get_random_number(std::mt19937 &gen) {
    return dist(gen);
  }

  T get_random_number(int upper_bound, std::mt19937 &gen) {
    if (max > upper_bound) dist = std::uniform_int_distribution<>(min, upper_bound);
    return dist(gen);
  }
};
#endif /* RANGE */
