#ifndef _SPECHAMMER_HELPER_
#define _SPECHAMMER_HELPER_

#include <stdint.h>

/* List of MSR registers */
#define PERF_GLOBAL_CTRL        0x38FU      /* IA32_PERF_GLOBAL_CTRL */
#define PERF_EVTSEL_BASE        0x186U      /* IA32_PERFVTSEL0 */

/* List of CBOX registers */
#define UNC_PERF_GLOBAL_CTR     0xe01
#define UNC_CBO_0_PERFEVTSEL0   0x700
#define UNC_CBO_0_PERFCTR0      0x706


/*
 * NUM:         event number
 * MASK:        event mask
 * USR:         count while in user space
 * OS:          count while in ring 0
 * ANYTHREAD:   if 1, count across all core's threads. If 0 only by the core that set this
 * EN:          always set enable          
 * CMASK:       event filter (specific on the choosen counter)
 * IN_TX:       counts only if inside a transaction (regardless abort/commit)
 * IN_TXCP:     remove event counted in an aborted transaction
 *
 * A common usage of setting IN_TXCP=1 is to capture the number of events that were discarded due to a transac-
 * tional abort. With IA32_PMC2 configured to count in such a manner, then when a transactional region aborts, the
 * value for that counter is restored to the value it had prior to the aborted transactional region. As a result,
 * any updates performed to the counter during the aborted transactional region are discarded.
 * 
 * On the other hand, setting IN_TX=1 can be used to drill down on the performance characteristics of transactional
 * code regions. When a PMCx is configured with the corresponding IA32_PERFEVTSELx.IN_TX=1, only eventing
 * conditions that occur inside transactional code regions are propagated to the event logic and reflected in the
 * counter result. Eventing conditions specified by IA32_PERFEVTSELx but occurring outside a transactional region
 * are discarded.
 */
#define PMU_EVENT(EVENT_ID, UMASK, CMASK, INV, EDGE, USR, OS, ANYTHREAD, IN_TX, IN_TXCP) \
                  ( (EVENT_ID<<0) | (UMASK<<8) | (USR<<16) | (OS<<17) | (ANYTHREAD<<21) | \
                    (1<<22) | (CMASK<<24) | (IN_TX<<32) | (IN_TXCP<<33) | (INV)<<23 | (EDGE)<<18)

#define CBOX_EVENT(EVENT_ID, UMASK) ( (EVENT_ID<<0) | (UMASK<<8) |  (1<<22) )

#define rdpmc_lh(counter, low, high) __asm__ __volatile__("lfence\nrdpmc\nlfence\n" : "=a" (low), "=d" (high) : "c" (counter))
#define rdpmc_l(counter, low)        __asm__ __volatile__("lfence\nrdpmc\nlfence\n" : "=a" (low) : "c" (counter))
#define rdpmc(counter, low)          __asm__ __volatile__("rdpmc\n" : "=a" (low) : "c" (counter))


/*==================*/
/*=== PROTOTYPES ===*/
/*==================*/
int      get_cpu();
uint64_t rdmsr(uint32_t reg, int cpu);
void     wrmsr(uint32_t reg, int cpu, uint64_t regval);

void     enable_pmu();
void     disable_pmu();
void     start_pmu( uint64_t event_id,
                    uint64_t umask,
                    uint64_t cmask,
                    uint64_t inv,
                    uint64_t edge,
                    uint64_t usr,
                    uint64_t os,
                    uint64_t any_thread,
                    uint64_t in_tx,
                    uint64_t in_txcp);
void     stop_pmu();

size_t   virt_to_phys(size_t virtual_address);
size_t   get_phys_mem();
void     flush_with_kernel(size_t addr);
void     tlbflush(size_t addr);
uint32_t get_dram_reads(void);

void enable_cbox();
void disable_cbox();
void start_cbox(uint64_t event_id, uint64_t umask);
void stop_cbox();
uint64_t get_cbox();

static void enable_lbr(void) {
	asm volatile("xor %%edx, %%edx;"
		     "xor %%eax, %%eax;"
		     "inc %%eax;"
		     "mov $0x1d9, %%ecx;"
		     "wrmsr;"
		     : : );

	//	printk(KERN_INFO "LBR Enabled\n");
}

static void disable_lbr(void) {
	asm volatile("xor %%edx, %%edx;"
		     "xor %%eax, %%eax;"
		     "mov $0x1d9, %%ecx;"
		     "wrmsr;"
		     : : );

	//	printk(KERN_INFO "LBR Disabled\n");
}

static void filter_lbr(void) {
	asm volatile("xor %%edx, %%edx;"
		     "xor %%eax, %%eax;"
		     //"mov $0x13a, %%eax;" // capture ring == 0
		      "mov $0x139, %%eax;" // capture ring > 0
		     //		     "mov $0x1fa, %%eax;"
		     "mov $0x1c8, %%ecx;"
		     "wrmsr;"
		     : : );
}

static void print_lbr(void) {
	int ax1f, dx1f, ax1t, dx1t, msr_from_counter, msr_to_counter;
	int ax1i, dx1i, msr_lbr_info;

	// fprintf(stderr, "BSHADOW: 0x%p\n", isgx_ioctl_branch);

    // NOTE: These MSR indices are for Skylake. Not so sure about other generations (e.g., Kaby lake)
	for (msr_from_counter = 1664,msr_to_counter = 1728,msr_lbr_info=3520;
	     msr_from_counter < 1696; msr_from_counter++, msr_to_counter++, msr_lbr_info++) {
		asm volatile("mov %6, %%ecx;"
			     "rdmsr;"
			     "mov %%eax, %0;"
			     "mov %%edx, %1;"
			     "mov %7, %%ecx;"
			     "rdmsr;"
			     "mov %%eax, %2;"
			     "mov %%edx, %3;"
			     "mov %8, %%ecx;"
			     "rdmsr;"
			     "mov %%eax, %4;"
			     "mov %%edx, %5;"
			     : "=g" (ax1f), "=g" (dx1f), "=g" (ax1t), "=g" (dx1t), "=g" (ax1i), "=g" (dx1i)
			     : "g" (msr_from_counter), "g" (msr_to_counter), "g" (msr_lbr_info)
			     : "%eax", "%ecx", "%edx"
			     );

		if (ax1f) {
			fprintf(stderr, "BSHADOW: from: %8x%8x to: %8x%8x, %8x, %8x\n",
			        dx1f, ax1f, dx1t, ax1t, dx1i, ax1i);
		}
	}
}
#endif

