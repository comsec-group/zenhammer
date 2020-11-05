#ifndef MAPPER_H
#define MAPPER_H

#include "stdlib.h"

#define    BK_SHIFT 	25
#define    ROW_SHIFT 	0	
#define    COL_SHIFT 	12	

//#define    BK_SHIFT 	0	
//#define    COL_SHIFT 	5	
//#define    ROW_SHIFT 	(13+5)
#define    BK_MASK	(0b11111 << BK_SHIFT) 
#define    ROW_MASK	(0b111111111111 << ROW_SHIFT) 
#define    COL_MASK	(0b1111111111111 << COL_SHIFT) 
#define    FN_BITS 	30
#define	   MSB_MASK	0xfffffc0000000

typedef struct {
	size_t msb;
	size_t bank;
	size_t row;
	size_t col;
} DRAMAddr;

typedef size_t physaddr_t;


physaddr_t to_phys(DRAMAddr d); 

DRAMAddr to_dram(physaddr_t p);



#endif 
