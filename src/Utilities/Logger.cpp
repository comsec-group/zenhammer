#include "Utilities/Logger.hpp"

#include <iostream>
#include <GlobalDefines.hpp>

// initialize the singleton instance
Logger Logger::instance; /* NOLINT */

Logger::Logger() = default;

void Logger::initialize() {
  instance.logfile = std::ofstream();

  std::string logfile_filename = "stdout.log";
  std::cout << "Writing into logfile \e[1m" << logfile_filename << "\e[0m." << std::endl;
  instance.logfile.open(logfile_filename, std::ios::out);
}

void Logger::close() {
  instance.logfile.close();
}

void Logger::log_info(const std::string &message, bool newline) {
  instance.logfile << FCYAN "[+] " << message;
  instance.logfile << NONE;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_error(const std::string &message, bool newline) {
  instance.logfile << FRED "[-] " << message;
  instance.logfile << NONE;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_data(const std::string &message, bool newline) {
  instance.logfile << message;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_bitflip(volatile char *flipped_address,
                         uint64_t row_no,
                         size_t page_offset,
                         unsigned char actual_value,
                         unsigned char expected_value,
                         unsigned long timestamp,
                         bool newline) {

  instance.logfile << FGREEN "[!] "
                   << string_format("Flip at %p, row %lu, page offset: %lu, from %x to %x detected at t=%lu.",
                                    flipped_address,
                                    row_no,
                                    page_offset,
                                    actual_value,
                                    expected_value,
                                    timestamp);
  instance.logfile << NONE;
  if (newline) instance.logfile << std::endl;
}
