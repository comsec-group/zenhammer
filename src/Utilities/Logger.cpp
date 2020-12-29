#include "Utilities/Logger.hpp"

#include <iostream>
#include <GlobalDefines.hpp>

// initialize the singleton instance
Logger Logger::instance; /* NOLINT */

Logger::Logger() = default;

void Logger::initialize() {
  instance.logfile = std::ofstream();

  std::string logfile_filename = "stdout.log";
  std::cout << "Writing stdout/stderr into logfile \e[1m" << logfile_filename << "\e[0m." << std::endl;
  instance.logfile.open(logfile_filename, std::ios::out | std::ios::trunc);
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
                   << "[!] Flip " << flipped_address << ", "
                   << "row " << row_no << ", "
                   << "page offset: " << page_offset << ", "
                   << "from " << expected_value << " to " << actual_value << ", "
                   << "detected at t=" << timestamp << std::endl;
  instance.logfile << NONE;
  if (newline) instance.logfile << std::endl;
}
