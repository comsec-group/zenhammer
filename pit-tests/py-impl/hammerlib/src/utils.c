#include "utils.h"


int gt(const void * a, const void * b) {
   return ( *(int*)a - *(int*)b );
}


uint64_t median(uint64_t* vals, size_t size) {
	qsort(vals, size, sizeof(uint64_t), gt);
	return ((size%2)==0) ? vals[size/2] : (vals[(size_t)size/2]+vals[((size_t)size/2+1)])/2;
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


size_t time_patt(unsigned char** patt, size_t len, size_t rounds) {
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


unsigned char* rand_addr(unsigned char* base, size_t len) {
	return (unsigned char*)((size_t)base + (rand64() % len));
}
