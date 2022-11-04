#include "Utilities/Pagemap.hpp"

#include <cstdio>
#include <unistd.h>

#define PAGEMAP_LENGTH 8

uint64_t pagemap::vaddr2paddr(uint64_t vaddr) {
  /* Credits to Balakumaran Kannan.
   * URL: https://eastrivervillage.com/Virtual-memory-to-Physical-memory/
   */
    size_t pid;
    size_t paddr = 0;
    size_t offset;

    int page_size;
    int page_shift = -1;

    char filename[1024] = {0};

    page_size = getpagesize();

    pid = getpid();
    sprintf(filename, "/proc/%ld/pagemap", pid);
#ifdef DEBUG
    printf("getting page number of virtual address 0x%lx of process %ld\n",vaddr, pid);
    printf("opening pagemap %s\n", filename);
#endif

    FILE *pagemap = fopen(filename, "rb");
    if (!pagemap) {
      perror("can't open file. ");
      goto err;
    }

    offset = (vaddr / page_size) * PAGEMAP_LENGTH;
#ifdef DEBUG
    printf("moving to %ld\n", offset);
#endif
    if (fseek(pagemap, (long)offset, SEEK_SET) != 0) {
      perror("fseek failed. ");
      goto err;
    }

    if (fread(&paddr, 1, (PAGEMAP_LENGTH-1), pagemap) < (PAGEMAP_LENGTH-1)) {
      perror("fread fails. ");
      goto err;
    }

    paddr = paddr & 0x7fffffffffffff;
#ifdef DEBUG
    printf("physical frame address is 0x%lx\n", paddr);
#endif
    offset = vaddr % page_size;

    /* PAGE_SIZE = 1U << PAGE_SHIFT */
    while (!((1UL << ++page_shift) & page_size));

    paddr = (size_t)((size_t)paddr << page_shift) + offset;
#ifdef DEBUG
    printf("physical address is 0x%lx\n", paddr);
#endif
    err:
    fclose(pagemap);

    return paddr;
}
