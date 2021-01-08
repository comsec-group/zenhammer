#include "Utilities/Logger.hpp"

#include <iostream>
#include <GlobalDefines.hpp>

// initialize the singleton instance
Logger Logger::instance; /* NOLINT */

Logger::Logger() = default;

void Logger::initialize() {
  instance.logfile = std::ofstream();

  std::string logfile_filename = "stdout.log";
  std::cout << "Writing into logfile " FF_BOLD << logfile_filename << F_RESET << std::endl;
  // we need to open the log file in append mode because the run_benchmark script writes values into it
  instance.logfile.open(logfile_filename, std::ios::out | std::ios::app);
}

void Logger::close() {
  instance.logfile.close();
}

void Logger::log_info(const std::string &message, bool newline) {
  instance.logfile << FC_CYAN "[+] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_info2(const std::string &message, bool newline) {
  instance.logfile << FC_MAGENTA << FF_BOLD << "[+] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_error(const std::string &message, bool newline) {
  instance.logfile << FC_RED "[-] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_data(const std::string &message, bool newline) {
  instance.logfile << message;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_debug(const std::string &message, bool newline) {
  instance.logfile << FC_YELLOW "[DEBUG] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}

void Logger::log_bitflip(volatile char *flipped_address,
                         uint64_t row_no,
                         size_t page_offset,
                         unsigned char actual_value,
                         unsigned char expected_value,
                         unsigned long timestamp,
                         bool newline) {
  instance.logfile << FC_GREEN
                   << "[!] Flip " << std::hex << (void *) flipped_address << ", "
                   << std::dec << "row " << row_no << ", "
                   << "page offset: " << page_offset << ", "
                   << std::hex << "from " << (int) expected_value << " to " << (int) actual_value << ", "
                   << std::dec << "detected at t=" << timestamp << ".";
  instance.logfile << F_RESET;
  if (newline) instance.logfile << std::endl;
}
