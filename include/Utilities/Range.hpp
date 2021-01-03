#ifndef RANGE
#define RANGE

#include <random>

template<typename T = int>
struct Range {
  T min{0};
  T max{0};
  T step{1};
  std::uniform_int_distribution<T> dist;

  Range() = default;

  Range(T min, T max) : min(min), max(max), dist(std::uniform_int_distribution<T>(min, max)) {

  }

  Range(T min, T max, T step) : min(min), max(max), step(step), dist(std::uniform_int_distribution<T>(min, max)) {

  }

  T get_random_number(std::mt19937 &gen) {
    if (min==max) {
      return min;
    } else if (max < min) {
      std::swap(max, min);
    }
    if (step!=1) {
      return Range<T>(min/step, max/step).get_random_number(gen)*step;
    } else {
      return dist(gen);
    }
  }

  T get_random_number(int upper_bound, std::mt19937_64 &gen) {
    if (max > upper_bound) dist = std::uniform_int_distribution<>(min, upper_bound);
    if (step!=1) {
      return Range<T>(min/step, upper_bound/step).get_random_number(gen)*step;
    } else {
      return dist(gen);
    }
  }
};
#endif /* RANGE */
