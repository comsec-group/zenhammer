#ifndef GLOBAL_DEFINES
#define GLOBAL_DEFINES

#include <cstdio>
#include <cstdint>
#include <unistd.h>

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
#define FRED "\e[0;31m"
#define FGREEN "\e[0;32m"
#define FYELLOW "\e[0;33m"
#define FBLUE "\e[0;34m"
#define FCYAN "\e[0;36m"
#define NONE "\e[0m" // end coloring, revert to default color

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
  printf("------ Run Configuration ------\n");  // TODO: update this
  printf("DRAMA_ROUNDS: %d\n", DRAMA_ROUNDS);
  printf("CACHELINE_SIZE: %d\n", CACHELINE_SIZE);
  printf("HAMMER_ROUNDS: %d\n", HAMMER_ROUNDS);
  printf("THRESH: %d\n", THRESH);
  printf("NUM_TARGETS: %d\n", NUM_TARGETS);
  printf("MAX_ROWS: %d\n", MAX_ROWS);
  printf("NUM_BANKS: %d\n", NUM_BANKS);
  printf("DIMM: %d\n", DIMM);
  printf("CHANNEL: %d\n", CHANNEL);
  printf("MEM_SIZE: %lu\n", MEM_SIZE);
  printf("PAGE_SIZE: %d\n", getpagesize());
  printf("USE_SYNC: %s\n", USE_SYNC ? "true" : "false");
  printf("USE_FREQUENCY_BASED_FUZZING: %s\n", USE_FREQUENCY_BASED_FUZZING ? "true" : "false");
}

#endif /* GLOBAL_DEFINES */
