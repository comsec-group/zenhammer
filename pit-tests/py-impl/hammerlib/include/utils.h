#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>


// taken from https://github.com/cloudflare/cloudflare-blog/tree/master/2018-11-memory-refresh

#define TIMESPEC_NSEC(ts) ((ts)->tv_sec * 1000000000ULL + (ts)->tv_nsec)
static inline __attribute__((always_inline)) uint64_t realtime_now() {
	struct timespec now_ts;
	clock_gettime(CLOCK_MONOTONIC, &now_ts);
	return TIMESPEC_NSEC(&now_ts);
}

static inline __attribute__((always_inline)) uint64_t rdtscp(void) {
	uint64_t lo, hi;
	asm volatile("rdtscp\n" : "=a" (lo), "=d" (hi) :: "rcx");
	return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) uint64_t rdtsc(void) {
	uint64_t lo, hi;
	asm volatile("rdtsc\n" : "=a" (lo), "=d" (hi) :: "rcx");
	return (hi << 32) | lo;
}

static inline __attribute__((always_inline)) void lfence() {
	asm volatile ("lfence\n");
}

static inline __attribute__((always_inline)) void sfence() {
	asm volatile ("sfence\n");
}
static inline __attribute__((always_inline)) void mfence() {
	asm volatile ("mfence\n");
}

static inline __attribute__((always_inline)) void clflush(void* p) {
	asm volatile("clflush (%0)\n"::"r"(p));
}	

static inline __attribute__((always_inline)) void clflushopt(void* p) {
	asm volatile("clflushopt (%0)\n"::"r"(p));
}	

static inline __attribute__((always_inline)) size_t rand64() {
	size_t res = ((size_t) rand() << 32) | rand();
	return res; 
}

uint64_t median(uint64_t* vals, size_t size); 

unsigned char* rand_addr(unsigned char* base, size_t len); 
