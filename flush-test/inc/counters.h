#ifndef _COUNTERS_H_
#define _COUNTERS_H_

#include <stdint.h>

typedef struct pmu_t {
    uint64_t    event_id;
    uint64_t    umask;
    uint64_t    cmask;
    uint64_t    inv;
    uint64_t    edge;
    char        name[256];
    char        desc[2048];
} pmu_t;

const pmu_t pmus[] = {


    {
              .event_id = 0x3,
              .umask    = 0x2,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "LD_BLOCKS.STORE_FORWARD",
              .desc     = "Loads blocked by overlapping with store buffer that cannot be forwarded",
    },

    {
              .event_id = 0x3,
              .umask    = 0x8,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "LD_BLOCKS.NO_SR",
              .desc     = "The number of times that split load operations are temporarily blocked because all resources for handling the split accesses are in use",
    },

    {
              .event_id = 0x7,
              .umask    = 0x1,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "LD_BLOCKS_PARTIAL.ADDRESS_ALIAS",
              .desc     = "False dependencies in MOB due to partial compare on address",
    },

    {
              .event_id = 0x8,
              .umask    = 0x1,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK",
              .desc     = "Load misses in all TLB levels that cause a page walk of any page size",
    },


    {
              .event_id = 0x24,
              .umask    = 0x21,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.DEMAND_DATA_RD_MISS",
              .desc     = "Demand Data Read requests that missed L2, no rejects",
    },

    {
              .event_id = 0x24,
              .umask    = 0x22,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.RFO_MISS",
              .desc     = "RFO requests that missed L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0x24,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.CODE_RD_MISS",
              .desc     = "L2 cache misses when fetching instructions",
    },

    {
              .event_id = 0x24,
              .umask    = 0x27,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.ALL_DEMAND_MISS",
              .desc     = "Demand requests that missed L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0x38,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.PF_MISS",
              .desc     = "Requests from the L1/L2/L3 hardware prefetchers or load software prefetches that miss L2 cache",
    },

    {
              .event_id = 0x24,
              .umask    = 0x3f,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.MISS",
              .desc     = "All requests that missed L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0x41,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.DEMAND_DATA_RD_HIT",
              .desc     = "Demand Data Read requests that hit L2 cache",
    },

    {
              .event_id = 0x24,
              .umask    = 0x42,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.RFO_HIT",
              .desc     = "RFO requests that hit L2 cache",
    },

    {
              .event_id = 0x24,
              .umask    = 0x44,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.CODE_RD_HIT",
              .desc     = "L2 cache hits when fetching instructions",
    },

    {
              .event_id = 0x24,
              .umask    = 0xd8,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.PF_HIT",
              .desc     = "Prefetches that hit L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0xe1,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.ALL_DEMAND_DATA_RD",
              .desc     = "All demand data read requests to L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0xe2,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.ALL_RFO",
              .desc     = "All L RFO requests to L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0xe4,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.ALL_CODE_RD",
              .desc     = "All L2 code requests",
    },

    {
              .event_id = 0x24,
              .umask    = 0xe7,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.ALL_DEMAND_REFERENCES",
              .desc     = "All demand requests to L2",
    },

    {
              .event_id = 0x24,
              .umask    = 0xf8,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.ALL_PF",
              .desc     = "All requests from the L1/L2/L3 hardware prefetchers or load software prefetches",
    },

    {
              .event_id = 0x24,
              .umask    = 0xef,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "L2_RQSTS.REFERENCES",
              .desc     = "All requests to L2",
    },

    {
              .event_id = 0x2e,
              .umask    = 0x4f,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "LLC_REFERENCES",
              .desc     = "                       ",
    },

    {
              .event_id = 0x2e,
              .umask    = 0x41,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "LLC_MISS",
              .desc     = "                             ",
    },


    {
              .event_id = 0xa1,
              .umask    = 0x1,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_0",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 0",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x2,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_1",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 1",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x4,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_2",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 2",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x8,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_3",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 3",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x10,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_4",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 4",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x20,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_5",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 5",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x40,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_6",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 6",
    },

    {
              .event_id = 0xa1,
              .umask    = 0x80,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_DISPATCHED_PORT.PORT_7",
              .desc     = "Counts the number of cycles in which a uop is dispatched to port 7",
    },

    {
              .event_id = 0xa2,
              .umask    = 0x1,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "RESOURCE_STALLS.ANY",
              .desc     = "Resource-related stall cycles",
    },

    {
              .event_id = 0xa2,
              .umask    = 0x8,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "RESOURCE_STALLS.SB",
              .desc     = "Cycles stalled due to no store buffers available (not including draining form sync)",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x1,
              .cmask    = 0x1,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.CYCLES_L2_MISS",
              .desc     = "Cycles while L2 cache miss demand load is outstanding",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x2,
              .cmask    = 0x2,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.CYCLES_L3_MISS",
              .desc     = "Cycles while L3 cache miss demand load is outstanding",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x4,
              .cmask    = 0x4,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.STALLS_TOTAL",
              .desc     = "Total execution stalls",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x5,
              .cmask    = 0x5,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.STALLS_L2_MISS",
              .desc     = "Execution stalls while L2 cache miss demand load is outstanding",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x6,
              .cmask    = 0x6,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.STALLS_L3_MISS",
              .desc     = "Execution stalls while L3 cache miss demand load is outstanding",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x8,
              .cmask    = 0x8,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.CYCLES_L1D_MISS",
              .desc     = "Cycles while L1 data cache miss demand load is outstanding",
    },

    {
              .event_id = 0xa3,
              .umask    = 0xc,
              .cmask    = 0xc,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.STALLS_L1D_MISS",
              .desc     = "Execution stalls while L1 data cache miss demand load is outstanding",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x10,
              .cmask    = 0x10,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.CYCLES_MEM_ANY",
              .desc     = "Cycles while memory subsystem has an outstanding load",
    },

    {
              .event_id = 0xa3,
              .umask    = 0x14,
              .cmask    = 0x14,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "CYCLE_ACTIVITY.STALLS_MEM_ANY",
              .desc     = "Execution stalls while memory subsystem has an outstanding load",
    },


    {
              .event_id = 0xc2,
              .umask    = 0x2,
              .cmask    = 0x0,
              .inv      = 0x0,
              .edge     = 0x0,
              .name     = "UOPS_RETIRED.RETIRE_SLOTS",
              .desc     = "Retirement slots used",
    },

};
#endif
