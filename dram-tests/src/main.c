#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sched.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "globals.h"
#include "utils.h"
#include "export.h"
#include "functions.h"
#include "hammer.h"

#define HUGE_FILE "/mnt/huge/buff"







int main(void) {
	
	unsigned char* buff;
	int huge_fd;	
	srand(time(NULL));
	if((huge_fd = open(HUGE_FILE, O_CREAT|O_RDWR)) == -1) {
            perror("[ERROR] - Unable to open hugetlbfs");
            exit(1);
        }

	buff = (unsigned char*) mmap(NULL, BUFF_LEN, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE|MAP_HUGETLB|(30<<MAP_HUGE_SHIFT), huge_fd, 0 );
	if (buff == MAP_FAILED) {
		fprintf(stderr, "mmap failed\n");
		exit(1);
	}

#ifdef EXPORT_TIMES
	export_times(buff);
#elif EXPORT_FUNCTIONS
	export_functions(buff);
#elif SYNC
	fprintf(stdout, "rnds: %ld\n", refresh_sync(buff));

#endif


	munmap(buff, BUFF_LEN);
	close(huge_fd);
	return 0;
	
 }
