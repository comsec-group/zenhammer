#include "functions.h"
#include "globals.h"
#include "utils.h"
#include "sched.h"

#ifdef TIME_THRESH

#define MAX_BITS 6 
#define MSB 30 
#define LS_BITMASK(x) (((1ULL)<<(x))-1)
#define CL_SHIFT 6
#define ERROR_RATE 0.02


typedef struct {
	void* a1;
	void* a2;
} tuple_t; 

uint64_t next_bit_permutation(uint64_t v) {
        uint64_t t = v | (v - 1);
        return (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctzl(v) + 1));
}

// return len of results 
int find_tuples(tuple_t* results, unsigned char* buff) {
	unsigned char* probe;
	unsigned char* base;

	size_t rounds = ITERS;
	size_t res_cnt = 0;
	for (size_t i = 0; i < SAMPLES; i++) {

		base = (unsigned char*)((size_t)rand_addr(buff, BUFF_LEN) );
		probe = (unsigned char*)((size_t)rand_addr(buff, BUFF_LEN) );
		sched_yield();
		size_t dt = time_access(base, probe, rounds);
		if (dt > TIME_THRESH) {
			tuple_t tp = {base, probe};
			results[res_cnt] = tp;
			res_cnt += 1;
		}
	}


	return res_cnt;
}


int find_functions(tuple_t* results, size_t len) {

	for (size_t b=0; b <= MAX_BITS; b++) {
		uint64_t fn_mask = ((1L<<(b))-1);
		uint64_t last_mask = (fn_mask<<(MSB-b));
		fn_mask <<= CL_SHIFT;
	        fprintf(stderr, "[ LOG ] - #Bits: %ld \t 0x%010lx 0x%010lx\n", b, fn_mask, last_mask);
		while (fn_mask != last_mask) {
			size_t wrng_cnt = 0;
			if (fn_mask & LS_BITMASK(6)){
				fn_mask = next_bit_permutation(fn_mask);
				continue;
			}
			for (size_t i = 0; i < len; i++) {
				uint64_t res_base = __builtin_parityl((size_t)results[i].a1 & fn_mask);
				uint64_t res_probe = __builtin_parityl((size_t)results[i].a2 & fn_mask);
				if (res_base != res_probe) {
					if(++wrng_cnt >= len*ERROR_RATE) {
						goto next_mask;	
					}
				}
			}

			fprintf(stdout, "0x%lx\n", fn_mask);
next_mask:
			fn_mask = next_bit_permutation(fn_mask);
		}

	}
}



void export_functions(unsigned char* buff) {
	tuple_t* tuples = malloc(sizeof(tuple_t)*SAMPLES); 
	size_t res_cnt = find_tuples(tuples, buff);
	fprintf(stderr, "res_cnt: %ld/%ld\n", res_cnt, SAMPLES);
	find_functions(tuples, res_cnt);

//	for (size_t k = 0; k < res_cnt; k++) {
//		fprintf(stderr, "%p, %p\n", tuples[k].a1, tuples[k].a2);
//	}
	}
#endif 
