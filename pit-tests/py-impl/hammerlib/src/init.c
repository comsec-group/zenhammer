#include "memory.h"
#include "init.h"

int init() {
	int res = mem_mmap();
	if (res == 0) {
		fill_memory();
	}
	return res;
}
