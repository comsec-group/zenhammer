#include "Memory/DRAMAddr.hpp"
#include "Utilities/Pagemap.hpp"
#include "GlobalDefines.hpp"

// initialize static variable
std::map<size_t, MemConfiguration> DRAMAddr::Configs;
std::unordered_map<size_t, std::pair<size_t, size_t>> DRAMAddr::bankIdx2bgbk;

void DRAMAddr::initialize(volatile char *start_address) {
  DRAMAddr::load_mem_config((CHANS(1) | DIMMS(1) | RANKS(1) | BANKGROUPS(8) | BANKS(4)));
  DRAMAddr::set_base_msb((void *) start_address);

  // FIXME: this assumes a 8 bg, 4 bk/bg configuration; we also need to support a 4/4 configuration
  DRAMAddr::bankIdx2bgbk = {
      {0, std::make_pair(0,0)},
      {1, std::make_pair(1,0)},
      {2, std::make_pair(2,0)},
      {3, std::make_pair(3,0)},
      {4, std::make_pair(4,0)},
      {5, std::make_pair(5,0)},
      {6, std::make_pair(6,0)},
      {7, std::make_pair(7,0)},
      {8, std::make_pair(0,1)},
      {9, std::make_pair(1,1)},
      {10, std::make_pair(2,1)},
      {11, std::make_pair(3,1)},
      {12, std::make_pair(4,1)},
      {13, std::make_pair(5,1)},
      {14, std::make_pair(6,1)},
      {15, std::make_pair(7,1)},
      {16, std::make_pair(0,2)},
      {17, std::make_pair(1,2)},
      {18, std::make_pair(2,2)},
      {19, std::make_pair(3,2)},
      {20, std::make_pair(4,2)},
      {21, std::make_pair(5,2)},
      {22, std::make_pair(6,2)},
      {23, std::make_pair(7,2)},
      {24, std::make_pair(0,3)},
      {25, std::make_pair(1,3)},
      {26, std::make_pair(2,3)},
      {27, std::make_pair(3,3)},
      {28, std::make_pair(4,3)},
      {29, std::make_pair(5,3)},
      {30, std::make_pair(6,3)},
      {31, std::make_pair(7,3)}
  };
}

void DRAMAddr::set_base_msb(void *buff) {
  base_msb = (size_t) buff & (~((size_t) (1ULL << 30UL) - 1UL));  // get higher order bits above the super page
}

void DRAMAddr::load_mem_config(mem_config_t cfg) {
  DRAMAddr::initialize_configs();
  MemConfig = Configs[cfg];
}

DRAMAddr::DRAMAddr() = default;

DRAMAddr::DRAMAddr(size_t bk, size_t r, size_t c)
  // use any of the two subchannels
  : DRAMAddr(0, bankIdx2bgbk.at(bk).first, bankIdx2bgbk.at(bk).second, r, c) {
}

DRAMAddr::DRAMAddr(size_t sc, size_t bg, size_t bk, size_t r, size_t c) {
  subchan = sc;
  bankgroup = bg;
  bank = bk;
//  row = r;
  set_row(r);
  col = c;
}

DRAMAddr::DRAMAddr(size_t sc, size_t bk, size_t r, size_t c)
    : DRAMAddr(sc, bankIdx2bgbk.at(bk).first, bankIdx2bgbk.at(bk).second, r, c) {
}

DRAMAddr::DRAMAddr(void *vaddr) {
//  uint64_t p = pagemap::vaddr2paddr((uint64_t)vaddr);
  auto p = (uint64_t) vaddr;
  size_t res = 0;
  for (unsigned long i : MemConfig.DRAM_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(p & i);
  }
  subchan = (res >> MemConfig.SC_SHIFT) & MemConfig.SC_MASK;
  bankgroup = (res >> MemConfig.BG_SHIFT) & MemConfig.BG_MASK;
  bank = (res >> MemConfig.BK_SHIFT) & MemConfig.BK_MASK;
//  row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
  set_row((res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK);
  col = (res >> MemConfig.COL_SHIFT) & MemConfig.COL_MASK;
}

size_t DRAMAddr::linearize() const {
  return (this->subchan << MemConfig.SC_SHIFT)
      | (this->bankgroup << MemConfig.BG_SHIFT)
      | (this->bank << MemConfig.BK_SHIFT)
      | (this->row << MemConfig.ROW_SHIFT)
      | (this->col << MemConfig.COL_SHIFT);
}

void *DRAMAddr::to_virt() {
  return const_cast<const DRAMAddr *>(this)->to_virt();
}

void *DRAMAddr::to_virt() const {
  size_t res = 0;
  size_t l = this->linearize();
  for (unsigned long i : MemConfig.ADDR_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(l & i);
  }
  void *v_addr = (void *) (base_msb | res);
  // FIXME: we ensure bit 25 is always 1, this is a hack because we do not know exactly how the row mask works in the
  //  higher bits (it seems like it's not just a linear function there)
  v_addr = (void*)((uint64_t)v_addr | (1ULL<<24));
  return v_addr;
}

void *DRAMAddr::to_phys() {
  return const_cast<const DRAMAddr *>(this)->to_phys();
}

void *DRAMAddr::to_phys() const {
  return (void*)pagemap::vaddr2paddr((uint64_t)this->to_virt());
}

std::string DRAMAddr::to_string() {
  char buff[1024];
  sprintf(buff, "DRAMAddr(sc: %zu, bg: %zu, b: %zu, r: %zu, c: %zu) = %p",
          this->subchan, this->bankgroup, this->bank, this->row, this->col, this->to_phys());
  return {buff};
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%ld,%ld,%ld,%ld,%ld)",
          this->subchan, this->bankgroup, this->bank, this->row, this->col);
  return {buff};
}

DRAMAddr DRAMAddr::add(size_t bank_increment, size_t row_increment, size_t column_increment) const {
  return add(0,
             std::floor(bank_increment/NUM_BANKS_PER_BG),
             bank_increment%NUM_BANKS_PER_BG,
             row_increment,
             column_increment);
}

DRAMAddr DRAMAddr::add(size_t sc_increment, size_t bankgroup_increment, size_t bank_increment, size_t row_increment,
                       size_t column_increment) const {
  return {subchan + sc_increment,
          bankgroup + bankgroup_increment,
          bank + bank_increment,
          row + row_increment,
          col + column_increment
  };
}

void DRAMAddr::add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment) {
  bankgroup += std::floor(bank_increment/NUM_BANKS_PER_BG);
  bank += (bank_increment%NUM_BANKS_PER_BG);
//  row += row_increment;
  set_row(row+row_increment);
  col += column_increment;
}

void DRAMAddr::add_inplace(size_t sc_increment, size_t bg_increment, size_t bk_increment, size_t row_increment,
                           size_t col_increment) {
  subchan += sc_increment;
  bankgroup += bg_increment;
  bank += bk_increment;
//  row += row_increment;
  set_row(row+row_increment);
  col += col_increment;
}

// Define the static DRAM configs
MemConfiguration DRAMAddr::MemConfig;
size_t DRAMAddr::base_msb;

void DRAMAddr::initialize_configs() {
  // we need to distinguish between bg and bk because it might be that (8bg, 2bk) will likely use a different addressing
  // function that (4 bg, 4 bk)
  struct MemConfiguration single_rank = {
      .IDENTIFIER = (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(8UL) | BANKS(4UL)),
      .SC_SHIFT  = 29,
      .SC_MASK   = (0b1),
      .BG_SHIFT  = 26,
      .BG_MASK   = (0b111),
      .BK_SHIFT  = 24,
      .BK_MASK   = (0b11),
      .ROW_SHIFT = 0,
//      .ROW_MASK  = (0b1111111111111111),
      .ROW_MASK  = (0b111111111111),
      .COL_SHIFT = 16,
      .COL_MASK  = (0b11111111),
      /* maps a virtual addr -> DRAM addr: subchannel (1b) | bankgroup (3b) | bank (2b) | col (8b) | row (16b) */
      .DRAM_MTX = {
          0b000000000011000011001000000000,  // 0x0000c3200, subchannel     =  addr b9, b12, b13, b18, b19
          0b010001000100001000000000000000,  // 0x111108000, bank group b2  =  addr b15, b20, b24, b28, (b32)
          0b001000100001000100000000000000,  // 0x088844000, bank group b1  =  addr b14, b18, b23, b27, (b31)
          0b000000000010000001000100000000,  // 0x000081100, bank group b0  =  addr b8, b12, b19
          0b100010001000010000000000000000,  // 0x222210000, bank b1        =  addr b16, b21, b25, b29, (b33)
          0b000100010000100000000000000000,  // 0x044420000, bank b0        =  addr b17, b22, b26, b30
          0b000000000000000000000000000000,  // col b7   =  undefined
          0b000000000000000000000000000000,  // col b6   =  undefined
          0b000000000000000000000000000000,  // col b5   =  undefined
          0b000000000000000000000000000000,  // col b4   =  undefined
          0b000000000000000000000000000000,  // col b3   =  undefined
          0b000000000000000000000000000000,  // col b2   =  undefined
          0b000000000000000000000000000000,  // col b1   =  undefined
          0b000000000000000000000000000000,  // col b0   =  undefined
          0b000000000000000000000000000000,  // row b15  =  addr b33
          0b000000000000000000000000000000,  // row b14  =  addr b32
          0b000000000000000000000000000000,  // row b13  =  addr b31
          0b000000000000000000000000000000,  // row b12  =  addr b30
          0b100000000000000000000000000000,  // row b11  =  addr b29
          0b010000000000000000000000000000,  // row b10  =  addr b28
          0b001000000000000000000000000000,  // row b9   =  addr b27
          0b000100000000000000000000000000,  // row b8   =  addr b26
          0b000010000000000000000000000000,  // row b7   =  addr b25
          0b000001000000000000000000000000,  // row b6   =  addr b24
          0b000000100000000000000000000000,  // row b5   =  addr b23
          0b000000010000000000000000000000,  // row b4   =  addr b22
          0b000000001000000000000000000000,  // row b3   =  addr b21
          0b000000000100000000000000000000,  // row b2   =  addr b20
          0b000000000010000000000000000000,  // row b1   =  addr b19
          0b000000000001000000000000000000,  // row b0   =  addr b18
      },
      /* maps a DRAM addr [subchannel (1b) | bankgroup (3b) | bank (2b) | col (8b) | row (16b)] to a virtual address */
      .ADDR_MTX = {
          0b000010000000000000100000000000,  // addr b29 =  row b11 + bk b1
          0b010000000000000000010000000000,  // addr b28 =  row b10 + bg b2
          0b001000000000000000001000000000,  // addr b27 =  row b9 + bg b1
          0b000001000000000000000100000000,  // addr b26 =  row b8 + bk b0
          0b000010000000000000000010000000,  // addr b25 =  row b7 + bk b1
          0b010000000000000000000001000000,  // addr b24 =  row b6 + bg b2
          0b001000000000000000000000100000,  // addr b23 =  row b5 + bg b1
          0b000001000000000000000000010000,  // addr b22 =  row b4 + bk b0
          0b000010000000000000000000001000,  // addr b21 =  row b3 + bk b1
          0b010000000000000000000000000100,  // addr b20 =  row b2 + bg b2
          0b100100000000000000000000000010,  // addr b19 =  row b1 + bg b0 + sc b0
          0b101000000000000000000000000001,  // addr b18 =  row b0 + bg b1 + sc b0
          0b000001000000000000000000000000,  // addr b17 =  bk b0
          0b000010000000000000000000000000,  // addr b16 =  bk b1
          0b010000000000000000000000000000,  // addr b15 =  bg b2
          0b001000000000000000000000000000,  // addr b14 =  bg b1
          0b100000000000000000000000000000,  // addr b13 =  sc b0
          0b100100000000000000000000000000,  // addr b12 =  bg b0 + sc b0
          0b000000000000000000000000000000,  // addr b11 =  UNUSED
          0b000000000000000000000000000000,  // addr b10 =  UNUSED
          0b100000000000000000000000000000,  // addr b9  =  sc b0
          0b000100000000000000000000000000,  // addr b8  =  bg b0
          0b000000000000000000000000000000,  // addr b7  =  col b0 (undefined)
          0b000000000000000000000000000000,  // addr b6  =  col b1 (undefined)
          0b000000000000000000000000000000,  // addr b5  =  col b2 (undefined)
          0b000000000000000000000000000000,  // addr b4  =  col b3 (undefined)
          0b000000000000000000000000000000,  // addr b3  =  col b4 (undefined)
          0b000000000000000000000000000000,  // addr b2  =  col b5 (undefined)
          0b000000000000000000000000000000,  // addr b1  =  col b6 (undefined)
          0b000000000000000000000000000000,  // addr b0  =  col b7 (undefined)
      }
  };
//  struct MemConfiguration single_rank = {
//      .IDENTIFIER = (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(8UL) | BANKS(4UL)),
//      .SC_SHIFT  = 29,
//      .SC_MASK   = (0b1),
//      .BG_SHIFT  = 26,
//      .BG_MASK   = (0b111),
//      .BK_SHIFT  = 24,
//      .BK_MASK   = (0b11),
//      .ROW_SHIFT = 0,
//      .ROW_MASK  = (01111111111111111),
//      .COL_SHIFT = 16,
//      .COL_MASK  = (0b11111111),
//      /* maps a virtual addr -> DRAM addr: subchannel (1b) | bankgroup (3b) | bank (2b) | col (8b) | row (16b) */
//      .DRAM_MTX = {
//          0b0000000000000011000011001000000000,  // 0x0000c3200, subchannel     =  addr b9, b12, b13, b18, b19
//          0b0100010001000100001000000000000000,  // 0x111108000, bank group b2  =  addr b15, b20, b24, b28, b32
//          0b0010001000100001000100000000000000,  // 0x088844000, bank group b1  =  addr b14, b18, b23, b27, b31
//          0b0000000000000010000001000100000000,  // 0x000081100, bank group b0  =  addr b8, b12, b19
//          0b1000100010001000010000000000000000,  // 0x222210000, bank b1        =  addr b16, b21, b25, b29, b33
//          0b0001000100010000100000000000000000,  // 0x044420000, bank b0        =  addr b17, b22, b26, b30
//          0b0000000000000000000000000010000000,  // col b7   =  addr b7
//          0b0000000000000000000000000001000000,  // col b6   =  addr b6
//          0b0000000000000000000000000000100000,  // col b5   =  addr b5
//          0b0000000000000000000000000000010000,  // col b4   =  addr b4
//          0b0000000000000000000000000000001000,  // col b3   =  addr b3
//          0b0000000000000000000000000000000100,  // col b2   =  addr b2
//          0b0000000000000000000000000000000010,  // col b1   =  addr b1
//          0b0000000000000000000000000000000001,  // col b0   =  addr b0
//          0b1000000000000000000000000000000000,  // row b15  =  addr b33
//          0b0100000000000000000000000000000000,  // row b14  =  addr b32
//          0b0010000000000000000000000000000000,  // row b13  =  addr b31
//          0b0001000000000000000000000000000000,  // row b12  =  addr b30
//          0b0000100000000000000000000000000000,  // row b11  =  addr b29
//          0b0000010000000000000000000000000000,  // row b10  =  addr b28
//          0b0000001000000000000000000000000000,  // row b9   =  addr b27
//          0b0000000100000000000000000000000000,  // row b8   =  addr b26
//          0b0000000010000000000000000000000000,  // row b7   =  addr b25
//          0b0000000001000000000000000000000000,  // row b6   =  addr b24
//          0b0000000000100000000000000000000000,  // row b5   =  addr b23
//          0b0000000000010000000000000000000000,  // row b4   =  addr b22
//          0b0000000000001000000000000000000000,  // row b3   =  addr b21
//          0b0000000000000100000000000000000000,  // row b2   =  addr b20
//          0b0000000000000010000000000000000000,  // row b1   =  addr b19
//          0b0000000000000001000000000000000000,  // row b0   =  addr b18
//      },
//      /* maps a DRAM addr [subchannel (1b) | bankgroup (3b) | bank (2b) | col (8b) | row (16b)] to a virtual address */
//      .ADDR_MTX = {
//          0b0000000010000000001000000000000000,  // addr b33 =  row b15 + bk b1
//          0b0000010000000000000100000000000000,  // addr b32 =  row b14 + bg b2
//          0b0000001000000000000010000000000000,  // addr b31 =  row b13 + bg b1
//          0b0000000001000000000001000000000000,  // addr b30 =  row b12 + bk b0
//          0b0000000010000000000000100000000000,  // addr b29 =  row b11 + bk b1
//          0b0000010000000000000000010000000000,  // addr b28 =  row b10 + bg b2
//          0b0000001000000000000000001000000000,  // addr b27 =  row b9 + bg b1
//          0b0000000001000000000000000100000000,  // addr b26 =  row b8 + bk b0
//          0b0000000010000000000000000010000000,  // addr b25 =  row b7 + bk b1
//          0b0000010000000000000000000001000000,  // addr b24 =  row b6 + bg b2
//          0b0000001000000000000000000000100000,  // addr b23 =  row b5 + bg b1
//          0b0000000001000000000000000000010000,  // addr b22 =  row b4 + bk b0
//          0b0000000010000000000000000000001000,  // addr b21 =  row b3 + bk b1
//          0b0000010000000000000000000000000100,  // addr b20 =  row b2 + bg b2
//          0b0000100100000000000000000000000010,  // addr b19 =  row b1 + bg b0 + sc b0
//          0b0000101000000000000000000000000001,  // addr b18 =  row b0 + bg b1 + sc b0
//          0b0000000001000000000000000000000000,  // addr b17 =  bk b0
//          0b0000000010000000000000000000000000,  // addr b16 =  bk b1
//          0b0000010000000000000000000000000000,  // addr b15 =  bg b2
//          0b0000001000000000000000000000000000,  // addr b14 =  bg b1
//          0b0000100000000000000000000000000000,  // addr b13 =  sc b0
//          0b0000100100000000000000000000000000,  // addr b12 =  bg b0 + sc b0
//          0b0000000000000000000000000000000000,  // addr b11 =  UNUSED
//          0b0000000000000000000000000000000000,  // addr b10 =  UNUSED
//          0b0000100000000000000000000000000000,  // addr b9  =  sc b0
//          0b0000000100000000000000000000000000,  // addr b8  =  bg b0
//          0b0000000000100000000000000000000000,  // addr b7  =  col b0
//          0b0000000000010000000000000000000000,  // addr b6  =  col b1
//          0b0000000000001000000000000000000000,  // addr b5  =  col b2
//          0b0000000000000100000000000000000000,  // addr b4  =  col b3
//          0b0000000000000010000000000000000000,  // addr b3  =  col b4
//          0b0000000000000001000000000000000000,  // addr b2  =  col b5
//          0b0000000000000000100000000000000000,  // addr b1  =  col b6
//          0b0000000000000000010000000000000000,  // addr b0  =  col b7
//      }
//  };
  DRAMAddr::Configs = {
      {(CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(8UL) | BANKS(4UL)), single_rank}
  };
}

uint64_t DRAMAddr::get_row_increment() {
  // TODO: we need to find a way to handle this properly, for now we assume the page size (see JESD79-5, p.6) is 1KB;
  //  given that (we assume) we have 4 chips per subchannel, we get 4 KB per row
  return 4096;
}

void DRAMAddr::set_row(size_t new_row) {
  // FIXME: we ensure bit 25 is always 1, this is a hack because we do not know exactly how the row mask works in the
  //  higher bits (it seems like it's not just a linear function there)
  this->row = (new_row | (1<<6));
}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p) {
  j = {
      {"subchannel", p.subchan},
      {"bankgroup", p.bankgroup},
      {"bank", p.bank},
      {"row", p.row},
      {"col", p.col}
  };
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("subchannel").get_to(p.subchan);
  j.at("bankgroup").get_to(p.bankgroup);
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
}

nlohmann::json DRAMAddr::get_memcfg_json() {
  std::map<size_t, nlohmann::json> memcfg_to_json = {
      {
          (CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKGROUPS(8) | BANKS(4UL)),
          nlohmann::json{{"channels", 1}, {"dimms", 1}, {"ranks", 1}, {"bankgroups", 8}, {"banks", 4}}
      }
  };
  return memcfg_to_json[MemConfig.IDENTIFIER];
}


#endif
