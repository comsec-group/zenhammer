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

#define NOP5      asm volatile("nop\nnop\nnop\nnop\nnop\n");
#define NOP10     NOP5 NOP5
#define NOP100    NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10 NOP10
#define NOP1K     NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100 NOP100
#define NOP10K    NOP1K NOP1K NOP1K NOP1K NOP1K NOP1K NOP1K NOP1K NOP1K NOP1K
#define NOP20K    NOP10K NOP10K
#define NOP50K    NOP10K NOP10K NOP10K NOP10K NOP10K
#define NOP100K   NOP10K NOP10K NOP10K NOP10K NOP10K NOP10K NOP10K NOP10K NOP10K NOP10K
#define NOP1M     NOP100K NOP100K NOP100K NOP100K NOP100K NOP100K NOP100K NOP100K NOP100K NOP100K


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

#define rdpmc(counter, low)  __asm__ __volatile__("lfence\nrdpmc\nlfence\n" : "=a" (low) : "c" (counter) : "rdx")
#define rdpmc_lh(counter, low, high) __asm__ __volatile__("lfence\nrdpmc\nlfence\n" : "=a" (low), "=d" (high) : "c" (counter))

#define PAGE_BIT_PRESENT 0 /* is present */
#define PAGE_BIT_RW    1 /* writeable */
#define PAGE_BIT_USER    2 /* userspace addressable */
#define PAGE_BIT_PWT   3 /* page write through */
#define PAGE_BIT_PCD   4 /* page cache disabled */
#define PAGE_BIT_ACCESSED  5 /* was accessed (raised by CPU) */
#define PAGE_BIT_DIRTY   6 /* was written to (raised by CPU) */
#define PAGE_BIT_PSE   7 /* 4 MB (or 2MB) page */
#define PAGE_BIT_GLOBAL  8 /* Global TLB entry PPro+ */
#define PAGE_BIT_NX    63  /* No execute: only valid after cpuid check */

#define PAGE_PRESENT(x)     (x & (1ULL<<PAGE_BIT_PRESENT))
#define PAGE_RW(x)          (x & (1ULL<<PAGE_BIT_RW))
#define PAGE_USER(x)        (x & (1ULL<<PAGE_BIT_USER))
#define PAGE_PWT(x)         (x & (1ULL<<PAGE_BIT_PWT))
#define PAGE_PCD(x)         (x & (1ULL<<PAGE_BIT_PCD))
#define PAGE_ACCESSED(x)    (x & (1ULL<<PAGE_BIT_ACCESSED))
#define PAGE_DIRTY(x)       (x & (1ULL<<PAGE_BIT_DIRTY))
#define PAGE_PSE(x)         (x & (1ULL<<PAGE_BIT_PSE))
#define PAGE_GLOBAL(x)      (x & (1ULL<<PAGE_BIT_GLOBAL))
#define PAGE_NX(x)          (x & (1ULL<<PAGE_BIT_NX))


/*==================*/
/*=== PROTOTYPES ===*/
/*==================*/
int      get_cpu();
uint64_t rdmsr(uint32_t reg, int cpu);
void     wrmsr(uint32_t reg, int cpu, uint64_t regval);

void     enable_pmu();
void     disable_pmu();
void     start_pmu( uint64_t cnt_idx,
                    uint64_t event_id,
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
void set_cpu(int core_idx);
pthread_t create_thread(int core_idx, void *(*target_loop) (void *), void *arg);

uint64_t get_pte(void *vaddr);
void set_pte(void *vaddr, uint64_t pte);
void print_pte(void *addr);

#endif

