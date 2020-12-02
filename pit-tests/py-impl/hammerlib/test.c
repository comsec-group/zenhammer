#include "stdio.h"
#include "stdint.h"
#include "stdlib.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "mapper.h"
#include "memory.h"
#include "init.h"

int main() {	

	init();
	DRAMAddr d = {0, 12, 0};
	void* val = to_addr(d);
	printf("val: %p\n", val);
}

