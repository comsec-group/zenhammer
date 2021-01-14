#ifndef BLACKSMITH_INCLUDE_UTILITIES_TIMEHELPER_HPP_
#define BLACKSMITH_INCLUDE_UTILITIES_TIMEHELPER_HPP_

#include <chrono>

inline long get_timestamp_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
};

inline unsigned long long get_timestamp_us() {
  return std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
};

#endif //BLACKSMITH_INCLUDE_UTILITIES_TIMEHELPER_HPP_
