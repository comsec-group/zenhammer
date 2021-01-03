#ifndef GLOBAL_DEFINES
#define GLOBAL_DEFINES

#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <sstream>

#include "Utilities/Logger.hpp"

uint64_t static inline KB(uint64_t value) {
  return ((value) << 10ULL);
}

uint64_t static inline MB(uint64_t value) {
  return ((value) << 20ULL);
}

uint64_t static inline GB(uint64_t value) {
  return ((value) << 30ULL);
}

[[gnu::unused]] static inline uint64_t BIT_SET(uint64_t value) {
  return (1ULL << (value));
}

// font colors
#define FC_RED "\e[0;31m"
#define FC_GREEN "\e[0;32m"
#define FC_YELLOW "\e[0;33m"
#define FC_BLUE "\e[0;34m"
#define FC_CYAN "\e[0;36m"
// font faces
#define FF_BOLD "\e[1m"
#define F_RESET "\e[0m" // reset to default font face/color

// ########################################################
// ################### CONFIG PARAMETERS ##################
// ########################################################

// number of rounds to measure cache hit/miss latency
#define DRAMA_ROUNDS 1000

// size in bytes of a cacheline
#define CACHELINE_SIZE 64

// number of rounds to hammer
#define HAMMER_ROUNDS 1000000

// threshold to distinguish between cache miss (t > THRESH) and cache hit (t < THRESH)
#define THRESH 430

// number of conflicting addresses to be determined for each bank
#define NUM_TARGETS 10

// maximum number of aggressor rows
#define MAX_ROWS 30

// number of banks in the system
#define NUM_BANKS 16

// number of active DIMMs in the system
#define DIMM 1

// number of active channels in the system
#define CHANNEL 1

// number of bytes to be allocated
#define MEM_SIZE (GB(1))

// #########################################################
// ################ PROGRAM FLOW PARAMETERS ################
// #########################################################

/// do synchronized hammering
#define USE_SYNC 1

// generate frequency-based patterns using fuzzing
#define USE_FREQUENCY_BASED_FUZZING 1

[[gnu::unused]] static void print_global_defines() {
  Logger::log_info("Printing run configuration (GlobalDefines.hpp):");
  std::stringstream ss;
  ss << "DRAMA_ROUNDS: " << DRAMA_ROUNDS << std::endl
    << "CACHELINE_SIZE: " << CACHELINE_SIZE << std::endl
    << "HAMMER_ROUNDS: " << HAMMER_ROUNDS << std::endl
    << "THRESH: " << THRESH << std::endl
    << "NUM_TARGETS: " << NUM_TARGETS << std::endl
    << "MAX_ROWS: " << MAX_ROWS << std::endl
    << "NUM_BANKS: " << NUM_BANKS << std::endl
    << "DIMM: " << DIMM << std::endl
    << "CHANNEL: " << CHANNEL << std::endl
    << "MEM_SIZE: " << MEM_SIZE << std::endl
    << "PAGE_SIZE: " << getpagesize() << std::endl
    << "USE_SYNC: " << (USE_SYNC ? "true" : "false") << std::endl
    << "USE_FREQUENCY_BASED_FUZZING: " << (USE_FREQUENCY_BASED_FUZZING ? "true" : "false");
  Logger::log_data(ss.str());
}

#endif /* GLOBAL_DEFINES */
