#ifndef ZENHAMMER_INCLUDE_UTILITIES_HELPER_HPP_
#define ZENHAMMER_INCLUDE_UTILITIES_HELPER_HPP_

#include <chrono>
#include <vector>
#include <string>

struct statistics {
  uint64_t min;
  uint64_t max;
  uint64_t avg;
  uint64_t median;
  uint64_t std;
  uint64_t most_frequent;
  std::string to_string();
};

template <typename T>
T median(std::vector<T> &v);

int64_t get_timestamp_sec();

int64_t get_timestamp_us();

double calc_std(std::vector<uint64_t> &values, double mean, size_t num_numbers);

void calculate_statistics(std::vector<uint64_t> &vec, statistics &stats);

#endif //ZENHAMMER_INCLUDE_UTILITIES_HELPER_HPP_
