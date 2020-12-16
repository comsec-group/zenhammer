#include "globals.h"
#include "utils.h"
#include "mapper.h"
#include "hammer.h"
#include <string.h>

#include <math.h>
#include <sched.h>
#include <unistd.h>

#define THRESH 900 
#define PATT_LEN 160 
#define ADDR_CNT 3




static inline __attribute((always_inline)) size_t check_rand64(void* ptr)
{
	size_t* ptr64 = (size_t*) ptr;
        return (*ptr64 ^ __builtin_ia32_crc32di(SEED, (size_t)ptr64));
}

FlipList scan(void* base, void* end) {
	FlipList f_list;
	memset((void*)&f_list, 0x00, sizeof(f_list));
	size_t* ptr64 = base;
	size_t chunk_size = (size_t) (end - base); 

	for (size_t i = 0; i < chunk_size/sizeof(*ptr64); i += 1) {
		//ptr64 = (size_t*) ((size_t) ptr64 + sizeof(*ptr64));
		size_t flip = check_rand64(&ptr64[i]);
		if (flip) {
#ifdef VERBOSE
			printf("[%p] - FLIP: %lx\n", &ptr64[i], flip);	
#endif
			f_list.flips[f_list.cnt++]  = (Flip) {&ptr64[i], flip, ptr64[i]};
			ptr64[i] ^= flip;
		}	
	}	
	return f_list;
}


static void __attribute__((always_inline)) inline refresh_sync(char* addr) {
	while(1) {
		size_t t0 = rdtscp();
		*(volatile char*)addr;
		size_t dt = rdtscp() - t0;
		clflushopt(addr);
		if (dt > THRESH) 
			break;
	}
}


// this version is not syncing with the various refreshes. it simply generates a pattern with a given freq
// and hopes for the best
void hammer_func(unsigned char* sync_addr, unsigned char** patt, size_t len, size_t rounds, size_t acts_ref) {
// ROUNDS 25000
// NUM_REFS ~8
// MAX_ACT ~170	
	
//	printf("sync: %p\n", sync_addr);
//	printf("patt: ");
//	for (size_t x = 0; x < 10; x++) {
//	
//		printf("%p, ", patt[x]);	
//	}
//	printf("\n");
//	return;
	// bring the pattern into the cache 
		for (size_t j = 0; j < len; j++) {
			 (volatile char*) patt[j];
		}
	
	usleep(64); // sleep for a couple of tREFIs 
	//sched_yield(); // to avoid preemption during hammering
	
	// sync_addr is an address mapping to a different back to avoid intereference
	// REF is for all banks so this doesn't matter
	refresh_sync(sync_addr);
	// hammer the different addresses
	// patt can be seen as a matrix where each row contains the activates to be done in that specific refresh interval 
	// patt[num_refs][max_act_per_ref]	
	for (size_t r = 0; r < rounds; ++r) {
		for (size_t j = 0; j < len;) {
			// no need to serialize. 
			// If you access to different addresses they get serialized authomatically (checked with PMU L2/L3 misses)
			//
			char* curr_addr = patt[j];
			asm volatile("cmovnz (%0), %%rdx \n"::"r"(curr_addr));
//			*(volatile char*) patt[j];
			clflushopt(curr_addr);
			if (++j % acts_ref == 0) {

				refresh_sync((char*)curr_addr);	
			} 
			

		}
//
//			// Once done hammering keep on touching the last address
//			// this address is used to detect the refresh and it gets served from the row buffer
//			// so no need to worry about modifying the state of the sampler since you never reach
//			// the row decoder logic
//			while(1) {
//				size_t t0 = rdtscp();
//				*(volatile char*)patt[j*max_act+max_act-1];
//				size_t dt = rdtscp() - t0;
//				clflushopt(patt[j*max_act+max_act-1]);
//				if (dt > THRESH) 
//					break;
//			}
	}
}	
