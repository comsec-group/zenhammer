#ifndef GLOBAL_DEFINES
#define GLOBAL_DEFINES

/// the starting address of the allocated memory area
#define ADDR 0x2000000000

/// the number of rounds to be used to measure cache hit/miss latency
#define DRAMA_ROUNDS 1000

/// size in bytes of a cacheline
#define CACHELINE_SIZE 64

/// the number of rounds to hammer
#define HAMMER_ROUNDS 1000000

/// threshold to distinguish between cache miss (t > THRESH) and cache hit (t < THRESH)
#define THRESH 430

#define NUM_TARGETS 10

/// the maximum number of aggressor rows
#define MAX_ROWS 30

/// the number of banks in the system
#define NUM_BANKS 16

/// the number of bytes to be allocated
#define MEM_SIZE (GB(1))

/// allocate a super page
#define USE_SUPERPAGE 1

/// do synchronized hammering
#define USE_SYNC 1

/// whether to generate random patterns using fuzzing
#define USE_FUZZING 1

#endif /* GLOBAL_DEFINES */