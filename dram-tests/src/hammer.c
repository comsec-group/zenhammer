#include "globals.h"
#include "utils.h"

#include "math.h"

#define THRESH 400
size_t refresh_sync(unsigned char* buff) {
	size_t rounds = ITERS;	
	unsigned char* a1 = rand_addr(buff, BUFF_LEN);
	//size_t* times = (size_t*) malloc(sizeof(size_t)*rounds);
	size_t count  = 0;	

	for (size_t k = 0; k < rounds; k++) {
		sfence();
		*(volatile char*) a1;
		clflush(a1);
	}

	for (size_t k = 0; k < rounds; k++) {
		sfence();
		size_t t0 = rdtscp();
		*(volatile char*) a1;
		size_t dt = rdtscp() - t0;
		clflush(a1);
		count++;
		if (dt > THRESH) 
			return count;
	}
}
