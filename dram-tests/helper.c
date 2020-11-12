#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <getopt.h>
#include <errno.h>
#include <asm/msr.h>
#include <sched.h>
#include <cpuid.h>
#include "helper.h"

int get_cpu()
{
    return sched_getcpu();    
}

/* Read the MSR "reg" on cpu "cpu" */
uint64_t rdmsr(uint32_t reg, int cpu)
{
	static int fd = -1;
    char msr_file_name[128];
	uint64_t data;

    sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);

	if (fd < 0)
    {
		fd = open(msr_file_name, O_RDONLY);
		if (fd < 0)
        {
            printf( "rdmsr: can't open %s\n", msr_file_name);
	        exit(1);
		}
	}

	if ( pread(fd, &data, sizeof(data), reg) != sizeof(data) )
    {
        printf( "rdmsr: cannot read %s/0x%08x\n", msr_file_name, reg);
        exit(2);
	}

	return data;
}

/* Write the MSR "reg" on cpu "cpu" with value "regval" */
void wrmsr(uint32_t reg, int cpu, uint64_t regval)
{
    static int fd = -1;
    char msr_file_name[128];

    sprintf(msr_file_name, "/dev/cpu/%d/msr", cpu);

    if (fd < 0)
    {
        fd = open(msr_file_name, O_WRONLY);
        if (fd < 0)
        {
            printf( "wrmsr: can't open %s\n", msr_file_name);
            exit(3);
        }
    }

    if (pwrite(fd, &regval, sizeof(regval), reg) != sizeof(regval))
    {
        printf( "wrmsr: cannot write 0x%016lx to %s/0x%08x\n", regval, msr_file_name, reg);
        exit(4);
    }

    return;
}

/* Enable the the PMU counters */
void enable_pmu()
{
    /* Verify how many counters are available by CPUID.0AH:EAX[15:8] */
    wrmsr(PERF_GLOBAL_CTRL, get_cpu(), 0x1); 
}

/* Disable the all counters */
void disable_pmu()
{
    wrmsr(PERF_GLOBAL_CTRL, get_cpu(), 0x0); 
}

/* Start a pmu counter with the specified attributes */
void start_pmu( uint64_t event_id,
                uint64_t umask,
                uint64_t cmask,
                uint64_t inv,
                uint64_t edge,
                uint64_t usr,
                uint64_t os,
                uint64_t any_thread,
                uint64_t in_tx,
                uint64_t in_txcp)
{    
    wrmsr( PERF_EVTSEL_BASE+0,  //Only using counter 0
           get_cpu(),
           PMU_EVENT(   event_id,
                        umask,
                        cmask,
                        inv,
                        edge,
                        usr,
                        os,
                        any_thread,
                        in_tx,
                        in_txcp
                    )
           ); 
}

/* Stop PMU counter */
void stop_pmu()
{
    wrmsr( PERF_EVTSEL_BASE+0,  //Only using counter 0
           get_cpu(),
           0
           ); 
}

size_t virt_to_phys(size_t virtual_address) {
    static int pagemap = -1;
    if (pagemap == -1) {
        pagemap = open("/proc/self/pagemap", O_RDONLY);
        if (pagemap < 0) {
            exit(9);
        }
    }
    uint64_t value;
    int got = pread(pagemap, &value, 8, (virtual_address / 0x1000) * 8);
    if (got != 8) {
        exit(10);
        return 0;
    }
    uint64_t page_frame_number = value & ((1ULL << 54) - 1);
    if (page_frame_number == 0) {
        return 0;
    }

    close(pagemap);

    return page_frame_number * 0x1000 + virtual_address % 0x1000;
}

size_t get_phys_mem()
{
    FILE *fp;
    size_t out;

    fp = fopen("/proc/direct_physical_map", "r");    
    if (fp == NULL) {
        printf("Can't open /proc/direct_physical_map\n");
        exit(12);
    }

    fscanf(fp, "0x%zx\n", &out);
    fclose(fp);

    return out;
}

void flush_with_kernel(size_t addr)
{
    static int fd = -1;

    if (fd == -1)
    {
        fd = open("/proc/flush", O_WRONLY);
        if (fd == -1)
        {
            printf("Error! Cannot open /proc/flush!\n");
            exit(13);
        }
    }

    write(fd, &addr, sizeof(size_t));

    return;
}

void tlbflush(size_t addr)
{
    static int fd = -1;

    if (fd == -1)
    {
        fd = open("/proc/tlbflush", O_WRONLY);
        if (fd == -1)
        {
            printf("Error! Cannot open /proc/tlbflush!\n");
            exit(13);
        }
    }

    write(fd, &addr, sizeof(size_t));

    return;
}

uint32_t get_dram_reads(void)
{
    static int fd = -1;
    uint32_t out;

    if (fd == -1)
    {
        fd = open("/proc/dram_reads", O_RDONLY);
        if (fd == -1)
        {
            printf("Error! Cannot open /proc/dram_reads!\n");
            exit(14);
        }
    }

    read(fd, &out, sizeof(uint32_t));

    return out;
}

/* Warning! This code only works from Skylake on */
void enable_cbox()
{
    /* EN = 1 */
    wrmsr(UNC_PERF_GLOBAL_CTR, get_cpu(), 0x20000000);

    /* Reset counter */
    wrmsr(UNC_CBO_0_PERFCTR0, get_cpu(), 0x0);
}

void disable_cbox()
{
    /* EN = 1 */
    wrmsr(UNC_PERF_GLOBAL_CTR, get_cpu(), 0x0);
}

void start_cbox(uint64_t event_id, uint64_t umask)
{
    wrmsr(UNC_CBO_0_PERFEVTSEL0, get_cpu(), CBOX_EVENT(event_id, umask));
}

void stop_cbox()
{
    wrmsr(UNC_CBO_0_PERFEVTSEL0, get_cpu(), 0);
}

uint64_t get_cbox()
{
    return rdmsr(UNC_CBO_0_PERFCTR0, get_cpu());
}
