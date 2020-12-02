#include "globals.h"
#include "mapper.h"
#include "math.h"
#include "helper.h"
#include "counters.h"
#include "utils.h"

#define THRESH 400
size_t consec(unsigned char* buff) {
	size_t rounds = ITERS;	
	//size_t* times = (size_t*) malloc(sizeof(size_t)*rounds);
	size_t count  = 0;	

#define ADDR_CNT 1 
#define PATT_LEN 64 

	DRAMAddr dAddr[ADDR_CNT];
	unsigned char* a1; 
	//a1 = rand_addr(buff, MB(2));
	a1 = buff;
	dAddr[0] = to_dram(a1);
	dAddr[0].col = 0;
	for (size_t k = 1; k < ADDR_CNT; k++) {
		size_t col = ((k * 167) + 13) & 0x7f;
		dAddr[k] = dAddr[k-1];
		//dAddr[k].row += 1;
		//dAddr[k].col = col*64;
		dAddr[k].col += 256;
		//printf("{bk: %ld, row:%ld, col:%ld}\n", dAddr[k].bank, dAddr[k].row, dAddr[k].col);
	}
	
	unsigned char* patt[500];
	for (size_t i = 0; i < PATT_LEN; i+=ADDR_CNT) {
		size_t col = ((i * 167) + 13) & 0x7f;
		for (size_t k =0; k < ADDR_CNT; k++) {
			patt[i+k] = to_phys(dAddr[k]);
//			dAddr[k].row += 1;
		//	dAddr[k].col = col*64;
			DRAMAddr v = to_dram(patt[i+k]);
		fprintf(stderr, "[%ld] - {bk: %ld, row:%ld, col:%ld} = %p\n",i+k, v.bank, v.row, v.col, patt[i+k]);
			//printf("%p\n", patt[i+k]);
		}

//		d0.row += 1;
//		d1.row += 1;
	}
//	for (size_t i =0; i < PATT_LEN-1; i++) {
//		*(unsigned char**) patt[i] = patt[i+1];
//		printf("%p\n", *(unsigned char**)patt[i] );
//	}

	uint64_t sum = 0;
	size_t results[ITERS];
#ifdef PMU

	for(int i=0; i<sizeof(pmus)/sizeof(pmu_t); i++)
	{
		uint64_t count_diff = 0;
		enable_pmu();

		sum = 0;
		start_pmu(0, //cnt_idx
				pmus[i].event_id,
				pmus[i].umask,
				pmus[i].cmask,
				pmus[i].inv,
				pmus[i].edge,
				1, //usr
				0, //os,
				0, //any_thread,
				0, //in_tx,
				0  //in_txcp
			 );
#endif	
		 a1 = patt[0];
		char* a2 = patt[1];
		for(int j=0; j<ITERS; j++)
		{

			size_t start, end;
			start = 0;
			end = 0;	
			for (size_t k = 0; k < 15; k++) {
				sfence();
				for (size_t l = 0; l < PATT_LEN; l++) {
					*(volatile char*) patt[l];
					clflushopt(patt[l]);
				}
				// for (size_t i = 0; i < PATT_LEN; i++) {
				// 	*(volatile char*) a1;
				// 	*(volatile char*) a2;
				// 	clflush(a1);
				// 	clflush(a2);
				// }
			}
#ifdef PMU		
			lfence();
			mfence();
			rdpmc(0, start);	
#elif TIME
			size_t t0 = rdtscp();
#endif

			char** x = (void*) patt[0];
				for (size_t l = 0; l < PATT_LEN; l++) {
			//		x = *(volatile char**)x;

					*(volatile char*) patt[l];
					clflushopt((void*)((size_t)patt[l]));
					rdtscp();
					//mfence();
					//lfence();
				}

//				for (size_t l = 0; l < PATT_LEN; l++) {
//					*(volatile char*) patt[l];
//					//clflushopt(patt[l]);
//				}
			sfence();
#ifdef PMU
			rdpmc(0, end);	
			results[j] = (end-start);
#elif TIME
			size_t	dt = rdtscp() - t0;
			results[j] = dt;
#endif

//				for (size_t l = 0; l < PATT_LEN; l++) {
//					clflushopt(patt[l]);
//				}
		}

		size_t res = median(results, ITERS);
#ifdef PMU
		stop_pmu();
		disable_pmu();
		printf("%-40s%ld\n", pmus[i].name, res);
	}
#elif TIME
	printf("dt: %ld - access: %ld\n", res, res/PATT_LEN);
#endif
}
