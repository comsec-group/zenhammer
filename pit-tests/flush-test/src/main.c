#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
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
#include "helper.h"
#include "mapper.h"
#include "sys/mman.h"
#define ITER 100

#define HUGE_FILE "/mnt/lab1/buff"
size_t consec(void* buff);

static jmp_buf buf;

static void unblock_signal(int signum __attribute__((__unused__))) {
  sigset_t sigs;
  sigemptyset(&sigs);
  sigaddset(&sigs, signum);
  sigprocmask(SIG_UNBLOCK, &sigs, NULL);
}

static void sig_handler(int signum) {
  (void)signum;
  unblock_signal(SIGILL);
  longjmp(buf, 1);
}

int main()
{
	if (signal(SIGILL, sig_handler) == SIG_ERR)
	{
		printf("ERROR\n");
		return 1;
	}

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
	consec(buff);
	return 0;    
}
