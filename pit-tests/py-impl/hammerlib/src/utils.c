#include "utils.h"


int gt(const void * a, const void * b) {
   return ( *(int*)a - *(int*)b );
}


uint64_t median(uint64_t* vals, size_t size) {
	qsort(vals, size, sizeof(uint64_t), gt);
	return ((size%2)==0) ? vals[size/2] : (vals[(size_t)size/2]+vals[((size_t)size/2+1)])/2;
}

unsigned char* rand_addr(unsigned char* base, size_t len) {
	return (unsigned char*)((size_t)base + (rand64() % len));
}
