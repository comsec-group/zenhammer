#include "globals.h"
#include "utils.h"
#include "mapper.h"
#include "math.h"

#define THRESH 400

size_t consec(unsigned char* buff) {
	size_t rounds = ITERS;	
	//size_t* times = (size_t*) malloc(sizeof(size_t)*rounds);
	size_t count  = 0;	

#define	ADDR_CNT 2 
#define PATT_LEN 16 

	DRAMAddr dAddr[ADDR_CNT];
	unsigned char* a1; 
	a1 = rand_addr(buff, MB(2));
	dAddr[0] = to_dram(a1);
	dAddr[0].col = 0;
	for (size_t k = 1; k < ADDR_CNT; k++) {
		dAddr[k] = dAddr[k-1];
		dAddr[k].row += 1;
	//	dAddr[k].col += 128;
		//printf("{bk: %ld, row:%ld, col:%ld}\n", dAddr[k].bank, dAddr[k].row, dAddr[k].col);
	}
	

	
	unsigned char* patt[500];
	for (size_t i = 0; i < PATT_LEN; i+=ADDR_CNT) {
		size_t col = ((i * 167) + 13) & 0x7f;
		for (size_t k =0; k < ADDR_CNT; k++) {
			patt[i+k] = to_phys(dAddr[k]);
			dAddr[k].col += 128;
		//	dAddr[k].row += 1;
		fprintf(stderr, "[%ld] - {bk: %ld, row:%ld, col:%ld}\n",i+k, dAddr[k].bank, dAddr[k].row, dAddr[k].col);
			//printf("%p\n", patt[i+k]);
		}

//		d0.row += 1;
//		d1.row += 1;
	}
	for (size_t r = 0; r < 50; r++) {
	size_t t = time_patt(patt, PATT_LEN, 500);	
	fprintf(stdout, "%ld, %ld\n", t, t/PATT_LEN);
	}	
}
