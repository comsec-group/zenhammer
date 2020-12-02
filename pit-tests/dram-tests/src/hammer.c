#include "globals.h"
#include "utils.h"
#include "mapper.h"
#include "helper.h"

#include "math.h"
#include "sched.h"

#define THRESH 900 
#define PATT_LEN 160 
#define ADDR_CNT 3
#define SEED 0x7bc661612e71168cULL

static inline __attribute((always_inline)) void fill_rand64(void* ptr)
{
	size_t* ptr64 = (size_t*) ptr;
        *ptr64 = __builtin_ia32_crc32di(SEED, (size_t) ptr64);
}


static inline __attribute((always_inline)) size_t check_rand64(void* ptr)
{
	size_t* ptr64 = (size_t*) ptr;
        return (*ptr64 ^ __builtin_ia32_crc32di(SEED, (size_t)ptr64));
}

void check_chunk(void* base, size_t len) {
	size_t* ptr64 = base;
	for (size_t i = 0; i < len; i += sizeof(*ptr64)) {
		ptr64 = (size_t*) ((size_t) ptr64 + sizeof(*ptr64));
		size_t flip = check_rand64(ptr64);
		if (flip) {
			printf("[%p] - FLIP: %lx\n", ptr64, flip);	
			*ptr64 ^= flip;
		}	
	}	
}

void fill_chunk(void* base, size_t len) {
	size_t* ptr64 = base;
	for (size_t i = 0; i < len; i += sizeof(*ptr64)) {
		ptr64 = (size_t*) ((size_t) ptr64 + sizeof(*ptr64));
		fill_rand64(ptr64);
	}	
}	

void gen_patt(void* buff, void* pattern, size_t off, size_t bk) {
	unsigned char** patt = (unsigned char**) pattern;
	DRAMAddr dAggr[4];
	DRAMAddr dDummy[10];
	
	dAggr[0] = to_dram(buff);
	dAggr[0].row += off;
	dAggr[0].bank = bk;
	dAggr[1] = dAggr[0];
	dAggr[1].row += 2;
	dAggr[2] = dAggr[1];
	dAggr[2].row += 4;
	dAggr[3] = dAggr[2];
	dAggr[3].row += 2;
	size_t patt_off = 0;

	size_t dummy_num = 4;
	// pick dummies
	for (size_t i = 0; i < dummy_num; i++) {
		dDummy[i] = dAggr[0];
		dDummy[i].row = dDummy[i].row + 2 + rand() % 128;
	}

#ifdef DUMMIES
	// gen pattern
	for (size_t i = 0; i < PATT_LEN; i++) {
		patt[i] = to_phys(dAggr[i%4]);

	}
#endif
#define AGGR_ACT 6 
#define DUMMY_ACT 1 

	size_t kk =0;
	while (kk < PATT_LEN) {

		for (size_t i = 0;i < DUMMY_ACT; i++) {
			//patt[kk++] = to_phys(dDummy[i % dummy_num]);
			patt[kk++] = to_phys(dAggr[2]);
			if (kk > PATT_LEN)
				goto done;
		}
		for (size_t i = 0; i < AGGR_ACT; i++) {
			patt[kk++] = to_phys(dAggr[i % 2]);
			if (kk > PATT_LEN)
				goto done;
		}

	}
done:
return ;
#ifdef DEBUG
	for (size_t i = 0; i < PATT_LEN; i++) {
		DRAMAddr d = to_dram(patt[i]);
		fprintf(stderr,"[%ld] - {bk: %ld, row:%ld}\n", i, d.bank, d.row);
	}
#endif 
	
}


size_t refresh_sync(unsigned char* buff) {
	size_t rounds = 10000;	
	DRAMAddr dPatt[ADDR_CNT];
	unsigned char* aPatt[500];
	aPatt[0] = rand_addr(buff, BUFF_LEN);
	dPatt[0] = to_dram(aPatt[0]);
	for (size_t k = 1; k < ADDR_CNT; k++) {
		size_t col = ((k * 167) + 13) & 0x7f;
		dPatt[k] = dPatt[k-1];
		dPatt[k].row += 1;
		//dPatt[k].col = col*64;
		//printf("{bk: %ld, row:%ld, col:%ld}\n", dPatt[k].bank, dPatt[k].row, dPatt[k].col);
	}

	for (size_t i = 0; i < PATT_LEN; i+=ADDR_CNT) {
		size_t col = ((i * 167) + 13) & 0x7f;
		for (size_t k =0; k < ADDR_CNT; k++) {
			aPatt[i+k] = to_phys(dPatt[k]);
			DRAMAddr v = to_dram(aPatt[i+k]);
			fprintf(stderr, "[%ld] - {bk: %ld, row:%ld, col:%ld} = %p\n",i+k, v.bank, v.row, v.col, aPatt[i+k]);
			//printf("%p\n", patt[i+k]);
		}

		//              d0.row += 1;
		//              d1.row += 1;
	}	
	
	size_t count  = 0;	
	size_t* counts = malloc(sizeof(size_t) * rounds);



			sched_yield();
			for (size_t rr = 0; rr < 10;rr++) { 
				for (size_t l = 0; l<PATT_LEN; l++) {
					*(volatile char*)aPatt[l];
					clflushopt(aPatt[l]);
				}
				for (size_t n = 0; n < 100; n++) {
					NOP
				}
			}

			for (size_t k = 0; k < rounds; k++) {
			for (size_t l = 0; l<PATT_LEN; l++) {
				*(volatile char*)aPatt[l];
				clflushopt(aPatt[l]);
			}

			//for (size_t n = 0; n < 100; n++) {
			//	NOP
			//}

		//	size_t t0 = rdtscp();
		//	*(volatile char*)aPatt[0];
		//	size_t dt = rdtscp() - t0;
		//	clflushopt(aPatt[0]);
		//	counts[k] = (dt > 1000) ? 1 : 0;
			count = 0;
			NOP10
			NOP10
			NOP10
			while(1) {
			size_t t0 = rdtscp();
			*(volatile char*)aPatt[0];
			*(volatile char*)aPatt[1];
			size_t dt = rdtscp() - t0;
			clflushopt(aPatt[0]);
			clflushopt(aPatt[2]);
			count += 2 ;
			if (dt > THRESH) 
				break;
			}
			counts[k] = count;
		}

		for (size_t k = 0; k < rounds; k++) {
			printf("%ld\n", counts[k]);
		}
}

	
void hammer_it(unsigned char** patt, size_t patt_len) {
	
	size_t rounds = 25000;
	// warm up rounds to sync
//	for(size_t rr = 0; rr < 40; rr++) {
//		for (size_t l = 0; l<patt_len; l++) {
//			*(volatile char*)patt[l];
//			lfence();
//			clflushopt(patt[l]);
//			mfence();
//		}
//		NOP100
//	}
	DRAMAddr temp;
	unsigned char* temps_v[3];
	temp = to_dram(patt[0]);
	temp.row -= 1;

//
	for (size_t i = 0; i < 3; i++) {
		temp.row += 1;
		temps_v[i] = to_phys(temp);
	}

	for (size_t vv = 0; vv < 100; vv++) {
		for (size_t i = 0; i < 3; i++) {
			*(volatile char*)temps_v[i];
			clflushopt(temps_v[i]);

		}
	
	}
	for (size_t k = 0; k < rounds; k++) {
		for (size_t l = 0; l<patt_len; l++) {
			*(volatile char*)patt[l];
			clflushopt(patt[l]);
		}
//		NOP10
//		NOP10
//		NOP10
//		NOP10
//		NOP10

		while(1) {
			size_t t0 = rdtscp();
			*(volatile char*)patt[0];
			*(volatile char*)patt[1];
			size_t dt = rdtscp() - t0;
			clflushopt(patt[0]);
			clflushopt(patt[1]);
			if (dt > THRESH) 
				break;
		}
	}

}	

void hammer(void* b) {
	
	unsigned char* patt[500];
	size_t patt_len = PATT_LEN;
	b = b + MB(2);
	fill_chunk(b, MB(200));
	for (size_t off = 0; off < 20; off++) {
	for (size_t bk = 0; bk < 32; bk++) {
		fprintf(stderr, "{bk: %ld, row: %ld}\n", bk, off);
		gen_patt(b, patt, off, bk);
		hammer_it(patt, patt_len);
		check_chunk(b, MB(200));
	}
	}
	
	

}
