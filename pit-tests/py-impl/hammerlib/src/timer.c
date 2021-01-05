#include "globals.h"
#include "utils.h"
#include "mapper.h"
#include "timer.h"
#include <string.h>
#include <sched.h>
#include <unistd.h>



// taken from https://github.com/cloudflare/cloudflare-blog/tree/master/2018-11-memory-refresh
// some minor modifications to fit our code
//

#define DELTAS_SZ 32768*4
static delta_t deltas[DELTAS_SZ];

delta_t* profile_refresh(unsigned char* addr) {

	clflush(addr);

	/* [4] Spin the CPU to allow frequency scaling to settle down. */
	uint64_t base, rt0, rt1, cl0, cl1;
	rt0 = realtime_now();
	cl0 = rdtsc();
	int i;
	for (i=0; 1; i++) {
		rt1 = realtime_now();
		if (rt1 - rt0 > 1000000000){
			break;
		}
	}
	cl1 = rdtsc();
//	fprintf(stderr, "[ ] Fun fact. clock_gettime() takes roughly %.1fns and %.1f cycles\n", 1000000000.0 / i, (cl1-cl0)*1.0 / i);

	/* [5] Do the work! */
	base = realtime_now();
	rt0 = base;


//	fprintf(stderr, "[*] Measuring MOV + CLFLUSH. Running %d iterations.\n", DELTAS_SZ);
	for (i = 0; i < DELTAS_SZ; i++) {
		// Perform memory load. Any will do/
		*(volatile int *) addr;
		clflush(addr);
		mfence();
		rt1 = realtime_now();
		uint64_t td = rt1 - rt0;
		rt0 = rt1;
		deltas[i].t = rt1 - base;
		deltas[i].d = td;
	}
	return deltas;
}



size_t time_access(unsigned char* a1, unsigned char* a2, size_t rounds) {
	size_t* times = (size_t*) malloc(sizeof(size_t)*rounds);
	for (size_t k = 0; k < rounds; k++) {

		mfence();
		size_t t0 = rdtscp();
		*(volatile char*) a1;
		*(volatile char*) a2;
		times[k] = rdtscp() - t0;
		lfence();	
		clflush(a1);
		clflush(a2);
	}
	size_t res = median(times, rounds);
	free(times);
	return res; 

}


#ifdef MEDIAN
#define rounds 1000

size_t time_patt(unsigned char** patt, size_t len) {
	size_t* times = (size_t*) malloc(sizeof(size_t)*rounds);
	
	for (size_t k = 0; k < 15; k++) {
		sfence();
		for (size_t l = 0; l < len; l++) {
			*(volatile char*) patt[l];
		}
		for (size_t l = 0; l < len; l++) {
			clflushopt(patt[l]);
		}
	}

	for (size_t k = 0; k < rounds; k++) {
		sfence();
		size_t t0 = rdtscp();
		for (size_t l = 0; l < len; l++) {
			*(volatile char*) patt[l];
		}
		times[k] = rdtscp() - t0;
		for (size_t l = 0; l < len; l++) {
			clflushopt(patt[l]);
		}
	}
	size_t res = median(times, rounds);
	free(times);
	return res; 

}

#else

// this version is not syncing with the various refreshes. it simply generates a pattern with a given freq
// and hopes for the best
size_t  time_patt(unsigned char** patt, size_t len) {



#define TIME_ROUNDS 1000

	usleep(64); // sleep for a couple of tREFIs 
	sched_yield();
		for (size_t j = 0; j < len; j++) {
			 (volatile char*) patt[j];
		}
	
	
	
	size_t t0 = rdtscp();
	for (size_t r = 0; r < TIME_ROUNDS; ++r) {
		for (size_t j = 0; j < len; j++) {
//			asm volatile("cmovnz (%0), %%rdx \n"::"r"(curr_addr));
			*(volatile char*) patt[j];
			clflushopt(patt[j]);


		}
	}
	return (rdtscp() - t0)/TIME_ROUNDS;
}	

#endif
