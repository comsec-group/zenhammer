#ifndef BLACKSMITH_INCLUDE_LOGGER_HPP_
#define BLACKSMITH_INCLUDE_LOGGER_HPP_

#include <string>
#include <fstream>
#include <memory>

template<typename ... Args>
std::string string_format(const std::string &format, Args ... args) {
  int size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
  if (size <= 0) { throw std::runtime_error("Error during formatting."); }
  std::unique_ptr<char[]> buf(new char[size]);
  snprintf(buf.get(), size, format.c_str(), args ...);
  return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}

class Logger {
 private:
  Logger();

  // a reference to the file output stream associated to the logfile
  std::ofstream logfile;

  // the logger instance (a singleton)
  static Logger instance;

 public:
  static void initialize();

  static void close();

  static void log_info(const std::string &message, bool newline = true);

  static void log_highlight(const std::string &message, bool newline = true);

  static void log_error(const std::string &message, bool newline = true);

  static void log_data(const std::string &message, bool newline = true);

  static void log_bitflip(volatile char *flipped_address,
                          uint64_t row_no,
                          size_t page_offset,
                          unsigned char actual_value,
                          unsigned char expected_value,
                          unsigned long timestamp,
                          bool newline = true);

  static void log_debug(const std::string &message, bool newline = true);
};

#endif //BLACKSMITH_INCLUDE_LOGGER_HPP_
