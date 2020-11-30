#ifndef GLOBAL_DEFINES
#define GLOBAL_DEFINES

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

// TODO: possible to replace by PAGE_SIZE from <sys/user.h>?
// the size of a page in bytes
#define PAGE_SIZE 4096

// #########################################################
// ################ PROGRAM FLOW PARAMETERS ################
// #########################################################

/// do synchronized hammering
#define USE_SYNC 1

// generate frequency-based patterns using fuzzing
#define USE_FREQUENCY_BASED_FUZZING 1

#endif /* GLOBAL_DEFINES */
