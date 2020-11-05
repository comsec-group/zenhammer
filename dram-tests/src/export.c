#include "sched.h"

#include "utils.h"
#include "export.h"
#include "globals.h"



void export_times(unsigned char* buff) {
	unsigned char* base;
	unsigned char* probe;
	
	size_t rounds = ITERS;
	for (size_t i = 0; i < SAMPLES; i++) {
		base = (unsigned char*)((size_t) rand_addr(buff, BUFF_LEN) & ~63ULL);
		probe = (unsigned char*)((size_t) rand_addr(buff, BUFF_LEN) & ~63ULL);
		sched_yield();
		size_t dt = time_access(base, probe, rounds);
		fprintf(stdout, "%p,%p,%ld\n", base, probe, dt);
		//fprintf(stdout,"%ld\n", dt);
	}
}
