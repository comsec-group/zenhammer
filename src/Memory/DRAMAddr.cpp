#include "Memory/DRAMAddr.hpp"
#include "Utilities/Pagemap.hpp"
#include "GlobalDefines.hpp"

#include <limits.h>
#include <iostream>

// initialize static variable
std::map<size_t, MemConfiguration> DRAMAddr::Configs;

void DRAMAddr::initialize(volatile char *start_address, size_t num_ranks, size_t num_bankgroups, size_t num_banks) {
  DRAMAddr::load_mem_config((CHANS(1) | DIMMS(1) | RANKS(num_ranks) | BANKGROUPS(num_bankgroups) | BANKS(num_banks)));
  DRAMAddr::set_base_msb((void *) start_address);
}

void DRAMAddr::set_base_msb(void *buff) {
  base_msb = (uint64_t) buff & (~((uint64_t) (1ULL << 30UL) - 1UL));  // get higher order bits above the super page
  // base_msb = (size_t)((size_t)buff & (UINT_MAX^((1ULL << 30UL)-1UL)));
}

void DRAMAddr::load_mem_config(mem_config_t cfg) {
  DRAMAddr::initialize_configs();
  if (Configs.find(cfg) == Configs.end()) {
    Logger::log_error("Could not find suitable memory configuration! Exiting.");
    exit(EXIT_FAILURE);
  }
  MemConfig = Configs[cfg];
}

DRAMAddr::DRAMAddr() = default;

DRAMAddr::DRAMAddr(size_t sc, size_t rk, size_t bg, size_t bk, size_t r, size_t c) 
  : subchan(sc % (MemConfig.SC_MASK+1)), 
    rank(rk % (MemConfig.RK_MASK+1)), 
    bankgroup(bg % (MemConfig.BG_MASK+1)), 
    bank(bk % (MemConfig.BK_MASK+1)), 
    row(r % (MemConfig.ROW_MASK+1)), 
    col(c % (MemConfig.COL_MASK+1)) {
}

DRAMAddr::DRAMAddr(size_t bk, size_t r, size_t c)
  : DRAMAddr(
      rand() % (MemConfig.SC_MASK+1), 
      rand() % (MemConfig.RK_MASK+1),
      rand() % (MemConfig.BG_MASK+1), 
      bk % (MemConfig.BK_MASK+1), 
      r % (MemConfig.ROW_MASK+1), 
      c % (MemConfig.COL_MASK+1)) {
}

DRAMAddr::DRAMAddr(size_t sc, size_t bk, size_t r, size_t c)
    : DRAMAddr(
        sc % (MemConfig.SC_MASK+1), 
        rand() % (MemConfig.RK_MASK+1),
        rand() % (MemConfig.BG_MASK+1),
        bk % (MemConfig.BK_MASK+1), 
        r % (MemConfig.ROW_MASK+1), 
        c % (MemConfig.COL_MASK+1)) {
}

DRAMAddr::DRAMAddr(void *vaddr) {
  auto p = (uint64_t) vaddr;
  size_t res = 0;
  for (unsigned long i : MemConfig.DRAM_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(p & i);
  }
  subchan = (res >> MemConfig.SC_SHIFT) & MemConfig.SC_MASK;
  bankgroup = (res >> MemConfig.BG_SHIFT) & MemConfig.BG_MASK;
  bank = (res >> MemConfig.BK_SHIFT) & MemConfig.BK_MASK;
  row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
  col = (res >> MemConfig.COL_SHIFT) & MemConfig.COL_MASK;
}

size_t DRAMAddr::get_subchan() const {
  return this->subchan % (MemConfig.SC_MASK+1);
}

size_t DRAMAddr::get_rank() const {
  return this->rank % (MemConfig.RK_MASK+1);
}

size_t DRAMAddr::get_bankgroup() const {
  return this->bankgroup % (MemConfig.BG_MASK+1);
}

size_t DRAMAddr::get_bank() const {
  return this->bank % (MemConfig.BK_MASK+1);
}

size_t DRAMAddr::get_row() const {
  return this->row % (MemConfig.ROW_MASK+1);
}

size_t DRAMAddr::get_column() const {
  return this->col % (MemConfig.COL_MASK+1);
}

void *DRAMAddr::to_virt() {
  size_t l = (this->get_subchan() << MemConfig.SC_SHIFT)
    | (this->get_rank() << MemConfig.RK_SHIFT)
    | (this->get_bankgroup() << MemConfig.BG_SHIFT)
    | (this->get_bank() << MemConfig.BK_SHIFT)
    | (this->get_row() << MemConfig.ROW_SHIFT)
    | (this->get_column() << MemConfig.COL_SHIFT);

  size_t res = 0;
  for (size_t i : MemConfig.ADDR_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(l & i);
  }

  auto virt = (base_msb | res);
  // std::cout << this->to_string() << " => " << std::hex << "0x" << (uint64_t)virt << std::endl;

  assert(((uint64_t) virt < base_msb+HUGEPAGE_SZ) && ((uint64_t) virt >= base_msb));

  return (void *) virt;
}

void *DRAMAddr::to_phys() {
  return (void*)pagemap::vaddr2paddr((uint64_t)this->to_virt());
}

std::string DRAMAddr::to_string() {
  char buff[1024];
  sprintf(buff, "DRAMAddr(sc: %zu, rk %zu, bg: %zu, b: %zu, r: %zu, c: %zu)",
          this->subchan, this->rank, this->bankgroup, this->bank, this->row, this->col);
  return {buff};
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%ld,%ld,%ld,%ld,%ld,%ld)",
          this->subchan, this->rank,  this->bankgroup, this->bank, this->row, this->col);
  return {buff};
}

DRAMAddr DRAMAddr::add(size_t sc_increment, size_t rank_increment, size_t bankgroup_increment, 
  size_t bank_increment, size_t row_increment, size_t column_increment) const {
  return {this->subchan + sc_increment,
          this->rank + rank_increment,
          this->bankgroup + bankgroup_increment,
          this->bank + bank_increment,
          this->row + row_increment,
          this->col + column_increment};
}

void DRAMAddr::add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment) {
  this->bank = (this->bank+bank_increment) % (MemConfig.BK_MASK+1);
  this->row = (this->row+row_increment) % (MemConfig.ROW_MASK+1);
  this->col = (this->col+column_increment) % (MemConfig.COL_MASK+1);
}

void DRAMAddr::add_inplace(size_t sc_increment, size_t bg_increment, size_t bank_increment, size_t row_increment, size_t column_increment) {
  this->subchan= (this->subchan+sc_increment) % (MemConfig.SC_MASK+1);
  this->bankgroup= (this->bankgroup+bg_increment) % (MemConfig.BG_MASK+1);
  this->bank = (this->bank+bank_increment) % (MemConfig.BK_MASK+1);
  this->row = (this->row+row_increment) % (MemConfig.ROW_MASK+1);
  this->col = (this->col+column_increment) % (MemConfig.COL_MASK+1);
}

void DRAMAddr::set_row(size_t row_no) {
  this->row = row_no % (MemConfig.ROW_MASK+1);
}

void DRAMAddr::increment_all_common() {
  this->bank = (this->bank+1) % (MemConfig.BK_MASK+1);
  if (this->bank == 0) {
    this->bankgroup = (this->bankgroup+1) % (MemConfig.BG_MASK+1);
    if (this->bankgroup == 0) {
      this->rank = (this->rank+1) % (MemConfig.RK_MASK+1);
      if ((MemConfig.RK_MASK > 0 && this->rank == 0) 
        || (MemConfig.RK_MASK == 0 && this->bankgroup == 0)) {
        this->subchan = (this->subchan+1) % (MemConfig.SC_MASK+1);
      }
    }
  }
}

// Define the static DRAM configs
MemConfiguration DRAMAddr::MemConfig;
size_t DRAMAddr::base_msb;

void DRAMAddr::initialize_configs() {
   struct MemConfiguration cfg_zen4_1ch_1d_1rk_8bg_4bk = {
      .IDENTIFIER = (unsigned long)((CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(8UL) | BANKS(4UL))),
      .SC_SHIFT = 28,
      .SC_MASK = (0b1),
      .RK_SHIFT = 0,
      .RK_MASK = (0b0),
      .BG_SHIFT = 24,
      .BG_MASK = (0b111),
      .BK_SHIFT = 22,
      .BK_MASK = (0b11),
      .ROW_SHIFT = 12,
      .ROW_MASK = (0b1111111111),
      .COL_SHIFT = 2,
      .COL_MASK = (0b1111111111),
      // maps physical addr -> DRAM addr (subch | bankgroup | bank | row | col)
      .DRAM_MTX = {
        0b1111111111000000000001000000,  /*  subch_b0 = addr b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b6 */
        0b1000010000000001000000000000,  /*  rank_b0 = addr b27 b22 b12 */
        0b0100001000000000001000000000,  /*  bg_b2 = addr b26 b21 b9 */
        0b0010000100000000000100000000,  /*  bg_b1 = addr b25 b20 b8 */
        0b0001000010000000100000000000,  /*  bg_b0 = addr b24 b19 b11 */
        0b0000100001000000010000000000,  /*  bk_b1 = addr b23 b18 b10 */
        0b1000000000000000000000000000,  /*  bk_b0 = addr b27 */
        0b0100000000000000000000000000,  /*  row_b9 = addr b26 */
        0b0010000000000000000000000000,  /*  row_b8 = addr b25 */
        0b0001000000000000000000000000,  /*  row_b7 = addr b24 */
        0b0000100000000000000000000000,  /*  row_b6 = addr b23 */
        0b0000010000000000000000000000,  /*  row_b5 = addr b22 */
        0b0000001000000000000000000000,  /*  row_b4 = addr b21 */
        0b0000000100000000000000000000,  /*  row_b3 = addr b20 */
        0b0000000010000000000000000000,  /*  row_b2 = addr b19 */
        0b0000000001000000000000000000,  /*  row_b1 = addr b18 */
        0b0000000000100000000000000000,  /*  row_b0 = addr b17 */
        0b0000000000010000000000000000,  /*  col_b9 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b8 = addr b15 */
        0b0000000000000100000000000000,  /*  col_b7 = addr b14 */
        0b0000000000000010000000000000,  /*  col_b6 = addr b13 */
        0b0000000000000000000010000000,  /*  col_b5 = addr b7 */
        0b0000000000000000000000100000,  /*  col_b4 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b3 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b2 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b1 = addr b2 */
        0b0000000000000000000000000001,  /*  col_b0 = addr b0 */
        0b0000000000000000000000000010,  /* augmented row = addr b1 */
      },
      // maps DRAM addr (subch | bankgroup | bank | row | col) -> physical addr
      .ADDR_MTX = {
        0b0000001000000000000000000000,  /*  addr b27 = subch_b0 bg_b2 row_b9  */
        0b0000000100000000000000000000,  /*  addr b26 = subch_b0 bg_b1 row_b8  */
        0b0000000010000000000000000000,  /*  addr b25 = subch_b0 bg_b0 row_b7  */
        0b0000000001000000000000000000,  /*  addr b24 = subch_b0 bk_b1 row_b6  */
        0b0000000000100000000000000000,  /*  addr b23 = subch_b0 bk_b0 row_b5  */
        0b0000000000010000000000000000,  /*  addr b22 = subch_b0 bg_b2 row_b4  */
        0b0000000000001000000000000000,  /*  addr b21 = subch_b0 bg_b1 row_b3  */
        0b0000000000000100000000000000,  /*  addr b20 = subch_b0 bg_b0 row_b2  */
        0b0000000000000010000000000000,  /*  addr b19 = subch_b0 bk_b1 row_b1  */
        0b0000000000000001000000000000,  /*  addr b18 = subch_b0 bk_b0 row_b0  */
        0b0000000000000000100000000000,  /*  addr b17 = col_b9  */
        0b0000000000000000010000000000,  /*  addr b16 = col_b8  */
        0b0000000000000000001000000000,  /*  addr b15 = col_b7  */
        0b0000000000000000000100000000,  /*  addr b14 = col_b6  */
        0b0000000000000000000010000000,  /*  addr b13 = col_b5  */
        0b0100001000010000000000000000,  /*  addr b12 = bg_b2  */
        0b0000100001000010000000000000,  /*  addr b11 = bk_b1  */
        0b0000010000100001000000000000,  /*  addr b10 = bk_b0  */
        0b0010000100001000000000000000,  /*  addr b9 = bg_b1  */
        0b0001000010000100000000000000,  /*  addr b8 = bg_b0  */
        0b0000000000000000000001000000,  /*  addr b7 = col_b4  */
        0b1000001111111111000000000000,  /*  addr b6 = subch_b0  */
        0b0000000000000000000000100000,  /*  addr b5 = col_b3  */
        0b0000000000000000000000010000,  /*  addr b4 = col_b2  */
        0b0000000000000000000000001000,  /*  addr b3 = col_b1  */
        0b0000000000000000000000000100,  /*  addr b2 = col_b0  */
        0b0000000000000000000000000001,  /*  addr b1 =  */
        0b0000000000000000000000000010,  /*  addr b0 =  */
      }
   };

   struct MemConfiguration cfg_zen4_1ch_1d_1rk_4bg_4bk = {
      .IDENTIFIER = (unsigned long)((CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(4UL) | BANKS(4UL))),
      .SC_SHIFT = 28,
      .SC_MASK = (0b1),
      .RK_SHIFT = 0,
      .RK_MASK = (0b0),
      .BG_SHIFT = 25,
      .BG_MASK = (0b11),
      .BK_SHIFT = 23,
      .BK_MASK = (0b11),
      .ROW_SHIFT = 12,
      .ROW_MASK = (0b11111111111),
      .COL_SHIFT = 2,
      .COL_MASK = (0b1111111111),
      // maps physical addr -> DRAM addr (subch | bankgroup | bank | row | col)
      .DRAM_MTX = {
        0b1111111111100000000001000000,  /*  subch_b0 = addr b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 b6 */
        0b1000100010000000000100000000,  /*  rank_b0 = addr b27 b23 b19 b8 */
        0b0001000100000000001000000000,  /*  bg_b1 = addr b24 b20 b9 */
        0b0010001000100000010000000000,  /*  bg_b0 = addr b25 b21 b17 b10 */
        0b0100010001000000100000000000,  /*  bk_b1 = addr b26 b22 b18 b11 */
        0b1000000000000000000000000000,  /*  bk_b0 = addr b27 */
        0b0100000000000000000000000000,  /*  row_b10 = addr b26 */
        0b0010000000000000000000000000,  /*  row_b9 = addr b25 */
        0b0001000000000000000000000000,  /*  row_b8 = addr b24 */
        0b0000100000000000000000000000,  /*  row_b7 = addr b23 */
        0b0000010000000000000000000000,  /*  row_b6 = addr b22 */
        0b0000001000000000000000000000,  /*  row_b5 = addr b21 */
        0b0000000100000000000000000000,  /*  row_b4 = addr b20 */
        0b0000000010000000000000000000,  /*  row_b3 = addr b19 */
        0b0000000001000000000000000000,  /*  row_b2 = addr b18 */
        0b0000000000100000000000000000,  /*  row_b1 = addr b17 */
        0b0000000000010000000000000000,  /*  row_b0 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b9 = addr b15 */
        0b0000000000000100000000000000,  /*  col_b8 = addr b14 */
        0b0000000000000010000000000000,  /*  col_b7 = addr b13 */
        0b0000000000000001000000000000,  /*  col_b6 = addr b12 */
        0b0000000000000000000010000000,  /*  col_b5 = addr b7 */
        0b0000000000000000000000100000,  /*  col_b4 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b3 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b2 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b1 = addr b2 */
        0b0000000000000000000000000001,  /*  col_b0 = addr b0 */
        0b0000000000000000000000000010,  /* augmented row = addr b1 */
      },
      // maps DRAM addr (subch | bankgroup | bank | row | col) -> physical addr
      .ADDR_MTX = {
        0b0000010000000000000000000000,  /*  addr b27 = subch_b0 bg_b1 row_b10  */
        0b0000001000000000000000000000,  /*  addr b26 = subch_b0 bk_b0 row_b9  */
        0b0000000100000000000000000000,  /*  addr b25 = subch_b0 bk_b1 row_b8  */
        0b0000000010000000000000000000,  /*  addr b24 = subch_b0 bg_b0 row_b7  */
        0b0000000001000000000000000000,  /*  addr b23 = subch_b0 bg_b1 row_b6  */
        0b0000000000100000000000000000,  /*  addr b22 = subch_b0 bk_b0 row_b5  */
        0b0000000000010000000000000000,  /*  addr b21 = subch_b0 bk_b1 row_b4  */
        0b0000000000001000000000000000,  /*  addr b20 = subch_b0 bg_b0 row_b3  */
        0b0000000000000100000000000000,  /*  addr b19 = subch_b0 bg_b1 row_b2  */
        0b0000000000000010000000000000,  /*  addr b18 = subch_b0 bk_b0 row_b1  */
        0b0000000000000001000000000000,  /*  addr b17 = subch_b0 bk_b1 row_b0  */
        0b0000000000000000100000000000,  /*  addr b16 = col_b9  */
        0b0000000000000000010000000000,  /*  addr b15 = col_b8  */
        0b0000000000000000001000000000,  /*  addr b14 = col_b7  */
        0b0000000000000000000100000000,  /*  addr b13 = col_b6  */
        0b0000000000000000000010000000,  /*  addr b12 = col_b5  */
        0b0000101000100010000000000000,  /*  addr b11 = bk_b0  */
        0b0001000100010001000000000000,  /*  addr b10 = bk_b1  */
        0b0010000010001000000000000000,  /*  addr b9 = bg_b0  */
        0b0100010001000100000000000000,  /*  addr b8 = bg_b1  */
        0b0000000000000000000001000000,  /*  addr b7 = col_b4  */
        0b1000011111111111000000000000,  /*  addr b6 = subch_b0  */
        0b0000000000000000000000100000,  /*  addr b5 = col_b3  */
        0b0000000000000000000000010000,  /*  addr b4 = col_b2  */
        0b0000000000000000000000001000,  /*  addr b3 = col_b1  */
        0b0000000000000000000000000100,  /*  addr b2 = col_b0  */
        0b0000000000000000000000000001,  /*  addr b1 =  */
        0b0000000000000000000000000010,  /*  addr b0 =  */
      }
   };

      struct MemConfiguration cfg_zen4_1ch_1d_2rk_8bg_4bk = {
      .IDENTIFIER = (unsigned long)((CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKGROUPS(8UL) | BANKS(4UL))),
      .SC_SHIFT = 27,
      .SC_MASK = (0b1),
      .RK_SHIFT = 26,
      .RK_MASK = (0b1),
      .BG_SHIFT = 23,
      .BG_MASK = (0b111),
      .BK_SHIFT = 21,
      .BK_MASK = (0b11),
      .ROW_SHIFT = 12,
      .ROW_MASK = (0b111111111),
      .COL_SHIFT = 2,
      .COL_MASK = (0b1111111111),

      // maps physical addr -> DRAM addr (subch | rank | bankgroup | bank | row | col)
      .DRAM_MTX = {
        0b1111111110000000000001000000,  /*  subch_b0 = addr b27 b26 b25 b24 b23 b22 b21 b20 b19 b6 */
        0b0000000000000100000000000000,  /*  rank_b0 = addr b14 */
        0b0100001000000000000100000000,  /*  bg_b2 = addr b26 b21 b8 */
        0b1000010000000000001000000000,  /*  bg_b1 = addr b27 b22 b9 */
        0b0000100000000001000000000000,  /*  bg_b0 = addr b23 b12 */
        0b0001000010000000010000000000,  /*  bk_b1 = addr b24 b19 b10 */
        0b0010000100000000100000000000,  /*  bk_b0 = addr b25 b20 b11 */
        0b1000000000000000000000000000,  /*  row_b8 = addr b27 */
        0b0100000000000000000000000000,  /*  row_b7 = addr b26 */
        0b0010000000000000000000000000,  /*  row_b6 = addr b25 */
        0b0001000000000000000000000000,  /*  row_b5 = addr b24 */
        0b0000100000000000000000000000,  /*  row_b4 = addr b23 */
        0b0000010000000000000000000000,  /*  row_b3 = addr b22 */
        0b0000001000000000000000000000,  /*  row_b2 = addr b21 */
        0b0000000100000000000000000000,  /*  row_b1 = addr b20 */
        0b0000000010000000000000000000,  /*  row_b0 = addr b19 */
        0b0000000001000000000000000000,  /*  col_b9 = addr b18 */
        0b0000000000100000000000000000,  /*  col_b8 = addr b17 */
        0b0000000000010000000000000000,  /*  col_b7 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b6 = addr b15 */
        0b0000000000000010000000000000,  /*  col_b5 = addr b13 */
        0b0000000000000000000010000000,  /*  col_b4 = addr b7 */
        0b0000000000000000000000100000,  /*  col_b3 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b2 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b1 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b0 = addr b2 */
        0b0000000000000000000000000001,  /* augmented row = addr b0 */
        0b0000000000000000000000000010,  /* augmented row = addr b1 */
      },

      // maps DRAM addr (subch | rank | bankgroup | bank | row | col) -> physical addr
      .ADDR_MTX = {
        0b0000000100000000000000000000,  /*  addr b27 = subch_b0 bg_b1 row_b8  */
        0b0000000010000000000000000000,  /*  addr b26 = subch_b0 bg_b2 row_b7  */
        0b0000000001000000000000000000,  /*  addr b25 = subch_b0 bk_b0 row_b6  */
        0b0000000000100000000000000000,  /*  addr b24 = subch_b0 bk_b1 row_b5  */
        0b0000000000010000000000000000,  /*  addr b23 = subch_b0 bg_b0 row_b4  */
        0b0000000000001000000000000000,  /*  addr b22 = subch_b0 bg_b1 row_b3  */
        0b0000000000000100000000000000,  /*  addr b21 = subch_b0 bg_b2 row_b2  */
        0b0000000000000010000000000000,  /*  addr b20 = subch_b0 bk_b0 row_b1  */
        0b0000000000000001000000000000,  /*  addr b19 = subch_b0 bk_b1 row_b0  */
        0b0000000000000000100000000000,  /*  addr b18 = col_b9  */
        0b0000000000000000010000000000,  /*  addr b17 = col_b8  */
        0b0000000000000000001000000000,  /*  addr b16 = col_b7  */
        0b0000000000000000000100000000,  /*  addr b15 = col_b6  */
        0b0100000000000000000000000000,  /*  addr b14 = rank_b0  */
        0b0000000000000000000010000000,  /*  addr b13 = col_b5  */
        0b0000100000010000000000000000,  /*  addr b12 = bg_b0  */
        0b0000001001000010000000000000,  /*  addr b11 = bk_b0  */
        0b0000010000100001000000000000,  /*  addr b10 = bk_b1  */
        0b0001000100001000000000000000,  /*  addr b9 = bg_b1  */
        0b0010000010000100000000000000,  /*  addr b8 = bg_b2  */
        0b0000000000000000000001000000,  /*  addr b7 = col_b4  */
        0b1000000111111111000000000000,  /*  addr b6 = subch_b0  */
        0b0000000000000000000000100000,  /*  addr b5 = col_b3  */
        0b0000000000000000000000010000,  /*  addr b4 = col_b2  */
        0b0000000000000000000000001000,  /*  addr b3 = col_b1  */
        0b0000000000000000000000000100,  /*  addr b2 = col_b0  */
        0b0000000000000000000000000001,  /*  addr b1 =  */
        0b0000000000000000000000000010,  /*  addr b0 =  */
      }
   };

   DRAMAddr::Configs = {
      { (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(8UL) | BANKS(4UL)), cfg_zen4_1ch_1d_1rk_8bg_4bk },
      { (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(4UL) | BANKS(4UL)) , cfg_zen4_1ch_1d_1rk_4bg_4bk },
      { (CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKGROUPS(8UL) | BANKS(4UL)) , cfg_zen4_1ch_1d_2rk_8bg_4bk }
   };
}

#ifdef ENABLE_JSON
void to_json(nlohmann::json &j, const DRAMAddr &p) {
  j = {
      {"subchannel", p.get_subchan()},
      {"rank", p.get_rank()},
      {"bankgroup", p.get_bankgroup()},
      {"bank", p.get_bank()},
      {"row", p.get_row()},
      {"col", p.get_column()}
  };
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("subchannel").get_to(p.subchan);
  j.at("rank").get_to(p.rank);
  j.at("bankgroup").get_to(p.bankgroup);
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
}

nlohmann::json DRAMAddr::get_memcfg_json() {
  return nlohmann::json{
        {"channels", CHANS_INV(MemConfig.IDENTIFIER)}, 
        {"dimms", DIMMS_INV(MemConfig.IDENTIFIER)}, 
        {"ranks", RANKS_INV(MemConfig.IDENTIFIER)}, 
        {"bankgroups", BANKGROUPS_INV(MemConfig.IDENTIFIER)}, 
        {"banks", BANKS_INV(MemConfig.IDENTIFIER)}};
}
#endif
