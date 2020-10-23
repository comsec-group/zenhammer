#ifndef UTILS
#define UTILS

#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define BIT_SET(x) (1ULL << (x))
#define BIT_VAL(b, val) (((val) >> (b)) & 1)
#define KB(x) ((x) << 10ULL)
#define MB(x) ((x) << 20ULL)
#define GB(x) ((x) << 30ULL)
#define CL_SHIFT 6
#define CL_SIZE 64  // cacheline size
#define PAGE_SIZE 4096
#define ROW_SIZE (8 << 10)

#define ALIGN_TO(X, Y) \
  ((X) & (~((1LL << (Y)) - 1LL)))           // Mask out the lower Y bits
#define LS_BITMASK(X) ((1LL << (X)) - 1LL)  // Mask only the lower X bits

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1e9 + (ts)->tv_nsec)

//----------------------------------------------------------
//                      Static functions

static inline __attribute__((always_inline)) void clflush(volatile void *p) {
  asm volatile("clflush (%0)\n" ::"r"(p) : "memory");
}

static inline __attribute__((always_inline)) void clflushopt(volatile void *p) {
#ifdef DDR3
  asm volatile("clflush (%0)\n" ::"r"(p) : "memory");
#else
  asm volatile("clflushopt (%0)\n" ::"r"(p) : "memory");
#
#endif
}

static inline __attribute__((always_inline)) void cpuid() {
  asm volatile("cpuid" ::: "rax", "rbx", "rcx", "rdx");
}

static inline __attribute__((always_inline)) void mfence() {
  asm volatile("mfence" ::: "memory");
}

static inline __attribute__((always_inline)) void sfence() {
  asm volatile("sfence" ::: "memory");
}

static inline __attribute__((always_inline)) void lfence() {
  asm volatile("lfence" ::: "memory");
}

static inline __attribute__((always_inline)) uint64_t rdtscp(void) {
  uint64_t lo, hi;
  asm volatile("rdtscp\n" : "=a"(lo), "=d"(hi)::"%rcx");
  return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
  uint64_t lo, hi;
  asm volatile("rdtsc\n" : "=a"(lo), "=d"(hi)::"%rcx");
  return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t realtime_now() {
  struct timespec now_ts;
  clock_gettime(CLOCK_MONOTONIC, &now_ts);
  return TIMESPEC_NSEC(&now_ts);
}

#endif /* UTILS */
