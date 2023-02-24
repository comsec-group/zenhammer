#ifndef BLACKSMITH_INCLUDE_UTILITIES_LPHEER_HPP_
#define BLACKSMITH_INCLUDE_UTILITIES_LPHEER_HPP_

#include <chrono>

inline int64_t get_timestamp_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

inline int64_t get_timestamp_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}

template <typename T>
T median(std::vector<T> &v) {
  if (v.empty()) {
    return 0.0;
  }
  auto n = v.size() / 2;
  nth_element(v.begin(), v.begin()+n, v.end());
  auto med = v[n];
  // even set size
  if (!(v.size() & 1)) {
    auto max_it = max_element(v.begin(), v.begin()+n);
    med = (*max_it + med) / 2.0;
  }
  return static_cast<T>(med);
}

double compute_std(std::vector<uint64_t> &values, double mean, size_t num_numbers) {
  double var = 0;
  for (const auto &num : values) {
    if (static_cast<double>(num) < mean)
      continue;
    var += std::pow(static_cast<double>(num) - mean, 2);
  }
  auto val = std::sqrt(var / static_cast<double>(num_numbers));
  return val;
}

struct statistics {
  uint64_t min;
  uint64_t max;
  uint64_t avg;
  uint64_t median;
  uint64_t std;
  uint64_t most_frequent;
  std::string to_string() {
    return format_string("min=%d, max=%d, mf=%d, avg=%d, med=%d, std=%d",
                         min, max, most_frequent, avg, median, std);

  }
};

void calculate_statistics(std::vector<uint64_t> &vec, statistics &stats) {
  stats.min = *std::min_element(vec.begin(), vec.end());
  stats.max = *std::max_element(vec.begin(), vec.end());
  auto avg = static_cast<double>(std::accumulate(vec.begin(), vec.end(), 0UL)/static_cast<double>(vec.size()));
  stats.avg = static_cast<uint64_t>(avg);
  stats.std = static_cast<uint64_t>(compute_std(vec, static_cast<double>(stats.avg), vec.size()));
  stats.median = median<uint64_t>(vec);

  size_t max_cnt = 0;
  size_t mf_val;
  std::unordered_map<uint64_t,uint64_t> val2cnt;
  for (const auto &v : vec) {
    val2cnt[v]++;
    if (val2cnt[v] > max_cnt) {
      max_cnt = val2cnt[v];
      mf_val = v;
    }
  }
  stats.most_frequent = mf_val;
}


#endif //BLACKSMITH_INCLUDE_UTILITIES_HELPER_HPP_
