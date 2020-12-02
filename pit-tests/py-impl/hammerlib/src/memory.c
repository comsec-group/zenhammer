#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>

#include "globals.h"
#include "utils.h"
#define ADDR 0x200000000UL
#define HUGE_FILE "/mnt/huge/buff"


void* buffer;
int huge_fd;



int mem_mmap(void) {
	
	int huge_fd;	
	srand(time(NULL));
	if((huge_fd = open(HUGE_FILE, O_CREAT|O_RDWR)) == -1) {
            perror("[ERROR] - Unable to open hugetlbfs");
            exit(1);
        }

	buffer = (unsigned char*) mmap((void*) ADDR, BUFF_LEN, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE|MAP_HUGETLB|(30<<MAP_HUGE_SHIFT), huge_fd, 0 );
	if (buffer == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		exit(1);
	}
	
	return 0;	
	
 }


int mem_munmap(void) {

	munmap(buffer, BUFF_LEN);
	close(huge_fd);
	return 0;
}

static inline __attribute((always_inline)) void fill_rand64(void* ptr)
{
	size_t* ptr64 = (size_t*) ptr;
        *ptr64 = __builtin_ia32_crc32di(SEED, (size_t) ptr64);
}


int fill_memory(void) {
	uint64_t* buff64 = buffer;
	for (size_t i = 0; i < BUFF_LEN / sizeof(size_t); i++) {
		fill_rand64(&buff64[i]);
	}
	return 0;
}

