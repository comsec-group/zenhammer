#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

static inline __attribute__((always_inline)) uint64_t rdtscp(void) {
	uint64_t lo, hi;
	asm volatile("rdtscp\n" : "=a" (lo), "=d" (hi) :: "rcx");
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

static inline __attribute__((always_inline)) size_t rand64() {
	size_t res = ((size_t) rand() << 32) | rand();
	return res; 
}

uint64_t median(uint64_t* vals, size_t size); 

size_t time_access(unsigned char* a1, unsigned char* a2, size_t rounds); 

unsigned char* rand_addr(unsigned char* base, size_t len); 
