#ifndef GLOBAL_DEFINES
#define GLOBAL_DEFINES

#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <sstream>

#include "Utilities/Logger.hpp"

uint64_t static inline MB(uint64_t value) { return ((value) << 20ULL); }

uint64_t static inline GB(uint64_t value) { return ((value) << 30ULL); }

[[gnu::unused]] static inline uint64_t BIT_SET(uint64_t value) { return (1ULL << (value)); }

// ################### CONFIG PARAMETERS ##################

// number of rounds to measure cache hit/miss latency
#define DRAMA_RNDS (1000)

// threshold to distinguish between bank conflict (t > BK_CONF_THRESH)
// and a regular access without any bank conflict (t < BK_CONF_THRESH)
//#define BK_CONF_THRESH (495)  // worked best on DIMM 6
#define BK_CONF_THRESH (430)  // worked best on DIMM 18

// number of bytes to be allocated
#define MEM_SIZE (GB(1))

#define NUM_BANKGROUPS (8)

#define NUM_BANKS_PER_BG (4)

// number of total banks in the system, calculated as #bankgroups x #banks
#define NUM_BANKS (NUM_BANKGROUPS*NUM_BANKS_PER_BG)

#endif /* GLOBAL_DEFINES */
