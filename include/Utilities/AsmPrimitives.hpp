#ifndef UTILS
#define UTILS

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>
#include <unordered_map>

#include "GlobalDefines.hpp"

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

[[gnu::unused]] static inline __attribute__((always_inline)) void clflush(volatile void *p) {
  asm volatile("clflush (%0)\n"::"r"(p)
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void clflushopt(volatile void *p) {
#ifdef DDR3
  asm volatile("clflush (%0)\n" ::"r"(p)
               : "memory");
#else
  asm volatile("clflushopt (%0)\n"::"r"(p)
  : "memory");
#

#endif
}

[[gnu::unused]] static inline __attribute__((always_inline)) void cpuid() {
  asm volatile("cpuid"::
  : "rax", "rbx", "rcx", "rdx");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void mfence() {
  asm volatile("mfence"::
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void sfence() {
  asm volatile("sfence"::
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) void lfence() {
  asm volatile("lfence"::
  : "memory");
}

[[gnu::unused]] static inline __attribute__((always_inline)) uint64_t rdtscp() {
  uint64_t lo, hi;
  asm volatile("rdtscp\n"
  : "=a"(lo), "=d"(hi)::"%rcx");
  return (hi << 32UL) | lo;
}

[[gnu::unused]] static inline __attribute__((always_inline)) uint64_t rdtsc() {
  uint64_t lo, hi;
  asm volatile("rdtsc\n"
  : "=a"(lo), "=d"(hi)::"%rcx");
  return (hi << 32UL) | lo;
}

[[gnu::unused]] static inline __attribute__((always_inline)) uint64_t realtime_now() {
  struct timespec now_ts{};
  clock_gettime(CLOCK_MONOTONIC, &now_ts);
  return ((now_ts).tv_sec*1e9 + (now_ts).tv_nsec);
}

#endif /* UTILS */