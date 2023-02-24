#include "Utilities/Logger.hpp"

#include <iostream>
#include <GlobalDefines.hpp>
#include <filesystem>

// initialize the singleton instance
Logger Logger::instance; /* NOLINT */

Logger::Logger() = default;

void Logger::initialize() {
  instance.logfile = std::ofstream();

  std::string logfile_filename = "stdout.log";
  std::cout << "Writing into logfile " FF_BOLD << logfile_filename << F_RESET << std::endl;
  // we need to open the log file in append mode because the run_benchmark script writes values into it
  instance.logfile.open(logfile_filename, std::ios::out | std::ios::app);
  instance.timestamp_start = (unsigned long) time(nullptr);
}

void Logger::close() {
  instance.logfile << std::endl;
  instance.logfile.close();
}

void Logger::log_info(const std::string &message, bool newline) {
  instance.logfile << FC_CYAN "[+] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile
#if (DEBUG==1)
    << std::endl;
#else
    << "\n";
#endif
}

void Logger::log_highlight(const std::string &message, bool newline) {
  instance.logfile << FC_MAGENTA << FF_BOLD << "[+] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile << "\n";
}

void Logger::log_error(const std::string &message, bool newline) {
  instance.logfile << FC_RED "[-] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile
#if (DEBUG==1)
  << std::endl;
#else
  << "\n";
#endif
}

void Logger::log_data(const std::string &message, bool newline) {
  instance.logfile << message;
  if (newline) instance.logfile
#if (DEBUG==1)
  << std::endl;
#else
  << "\n";
#endif
}

void Logger::log_analysis_stage(const std::string &message, bool newline) {
  std::stringstream ss;
  ss << FC_CYAN_BRIGHT "████  " << message << "  ";
  // this makes sure that all log analysis stage messages have the same length
  auto remaining_chars = 80-message.length();
  while (remaining_chars--) ss << "█";
  instance.logfile << ss.str();
  instance.logfile << F_RESET;
  if (newline) instance.logfile
#if (DEBUG==1)
  << std::endl;
#else
  << "\n";
#endif
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "UnusedParameter"
void Logger::log_debug(const std::string &message, bool newline,
                       const std::experimental::source_location location) {
#if (DEBUG==1)
  std::filesystem::path p(location.file_name());
  instance.logfile << FC_YELLOW << "[DEBUG|"
    << std::string(p.stem()) << std::string(p.extension()) << ":"
    << location.line() << "#"
    << location.function_name() << "] " << message;
  instance.logfile << F_RESET;
  if (newline)
    instance.logfile << std::endl;
#else
  // this is just to ignore complaints of the compiler about unused params
  std::ignore = message;
  std::ignore = newline;
#endif
}
#pragma clang diagnostic pop

void Logger::log_debug_data(const std::string &message, bool newline) {
#if (DEBUG==1)
  instance.logfile << FC_YELLOW << message << F_RESET;
  if (newline) instance.logfile << std::endl;
#else
  // this is just to ignore complaints of the compiler about unused params
  std::ignore = message;
  std::ignore = newline;
#endif
}

std::string Logger::format_timestamp(unsigned long ts) {
  auto minutes = ts/60;
  auto hours = minutes/60;
  std::stringstream ss;
  ss << int(hours) << " hours "
     << int(minutes%60) << " minutes "
     << int(ts%60) << " seconds";
  return ss.str();
}

void Logger::log_timestamp() {
  std::stringstream ss;
  auto current_time = (unsigned long) time(nullptr);
  ss << "Time elapsed: "
     << format_timestamp(current_time - instance.timestamp_start)
     << ".";
  log_info(ss.str());
}

void Logger::log_bitflip(volatile char *flipped_address, uint64_t row_no, unsigned char actual_value,
                         unsigned char expected_value, unsigned long timestamp, bool newline) {
  instance.logfile << FC_GREEN
                   << "[!] Flip " << std::hex << (void *) flipped_address << ", "
                   << std::dec << "row " << row_no << ", "
                   << "page offset: " << (uint64_t)flipped_address%(uint64_t)getpagesize() << ", "
                   << "byte offset: " << (uint64_t)flipped_address%(uint64_t)8 << ", "
                   << std::hex << "from " << (int) expected_value << " to " << (int) actual_value << ", "
                   << std::dec << "detected after " << format_timestamp(timestamp - instance.timestamp_start) << ".";
  instance.logfile << F_RESET;
  if (newline) instance.logfile
#if (DEBUG==1)
  << std::endl;
#else
  << "\n";
#endif
  Logger::log_info("Terminating process as this is a bit flip.");
  exit(EXIT_SUCCESS);
}

void Logger::log_success(const std::string &message, bool newline) {
  instance.logfile << FC_GREEN << "[!] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile
#if (DEBUG==1)
  << std::endl;
#else
  << "\n";
#endif
}

void Logger::log_failure(const std::string &message, bool newline) {
  instance.logfile << FC_RED_BRIGHT << "[-] " << message;
  instance.logfile << F_RESET;
  if (newline) instance.logfile
#if (DEBUG==1)
  << std::endl;
#else
  << "\n";
#endif
}

void Logger::log_metadata(const char *commit_hash, unsigned long run_time_limit_seconds) {
  Logger::log_info("General information about this fuzzing run:");

  char name[1024] = "";
  gethostname(name, sizeof name);

  std::stringstream ss;
  ss << "Start timestamp:: " << instance.timestamp_start << "\n"
     << "Hostname: " << name << "\n"
     << "Commit SHA: " << commit_hash << "\n"
     << "Run time limit: " << run_time_limit_seconds << " (" << format_timestamp(run_time_limit_seconds) << ")";
  Logger::log_data(ss.str());

  log_global_defines();
}

void Logger::log_global_defines() {
  Logger::log_info("Printing run configuration (GlobalDefines.hpp):");
  std::stringstream ss;
  ss << "DRAMA_ROUNDS: " << DRAMA_RNDS << "\n"
     << "HAMMER_ROUNDS: " << (1000000) << "\n"
     << "THRESH: " << BK_CONF_THRESH << "\n"
     << "NUM_BANKS: " << NUM_BANKS << "\n"
     << "NUM_BANKGROUPS: " << NUM_BANKGROUPS << "\n"
     << "NUM_BANKS_PER_BG: " << NUM_BANKS_PER_BG << "\n"
     << "NUM_BANKS: " << NUM_BANKS << "\n"
     << "MEM_SIZE: " << MEM_SIZE << "\n"
     << "PAGE_SIZE: " << getpagesize() << "\n";
  Logger::log_data(ss.str());
}
