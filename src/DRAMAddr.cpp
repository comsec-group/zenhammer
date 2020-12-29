#include "GlobalDefines.hpp"
#include "DRAMAddr.hpp"

void DRAMAddr::initialize(uint64_t num_bank_rank_functions, volatile char *start_address) {
  // TODO: This is a shortcut to check if it's a single rank dimm or dual rank in order to load the right memory
  //  configuration. We should get these infos from dmidecode to do it properly, but for now this is easier.
  size_t num_ranks;
  if (num_bank_rank_functions==5) {
    num_ranks = RANKS(2);
  } else if (num_bank_rank_functions==4) {
    num_ranks = RANKS(1);
  } else {
    Logger::log_error("Could not initialize DRAMAddr as #ranks seems not to be 1 or 2.");
    exit(0);
  }
  DRAMAddr::load_mem_config((CHANS(CHANNEL) | DIMMS(DIMM) | num_ranks | BANKS(NUM_BANKS)));
  DRAMAddr::set_base((void *) start_address);
}

void DRAMAddr::set_base(void *buff) {
  base_msb = (size_t) buff & (~((size_t) (1ULL << 30UL) - 1UL));  // get higher order bits above the super page
}

// TODO we can create a DRAMconfig class to load the right matrix depending on
// the configuration. You could also test it by checking if you can trigger bank conflcits
void DRAMAddr::load_mem_config(mem_config_t cfg) {
  MemConfig = Configs[cfg];
  valid_memcfg = true;
}

DRAMAddr::DRAMAddr(size_t bk, size_t r, size_t c) {
  valid_memcfg = false;
  if (!valid_memcfg) {
    bank = bk;
    row = r;
    col = c;
  } else {
    bank = bk & MemConfig.BK_MASK;
    row = r & MemConfig.ROW_MASK;
    col = c & MemConfig.COL_MASK;
  }
}

DRAMAddr::DRAMAddr(void *addr) {
  valid_memcfg = false;
  auto p = (size_t) addr;
  size_t res = 0;
  for (unsigned long i : MemConfig.DRAM_MTX) {
    res <<= 1ULL;
    res |= (size_t) __builtin_parityl(p & i);
  }
  bank = (res >> MemConfig.BK_SHIFT) & MemConfig.BK_MASK;
  row = (res >> MemConfig.ROW_SHIFT) & MemConfig.ROW_MASK;
  col = (res >> MemConfig.COL_SHIFT) & MemConfig.COL_MASK;
}

size_t DRAMAddr::linearize() const {
  return (this->bank << MemConfig.BK_SHIFT) | (this->row << MemConfig.ROW_SHIFT) | (this->col << MemConfig.COL_SHIFT);
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
  return v_addr;
}

std::string DRAMAddr::to_string() {
  char buff[1024];
  sprintf(buff, "DRAMAddr(b:%4ld, r:%10ld, c:%10ld) = %p",
          this->bank,
          this->row,
          this->col,
          this->to_virt());
  return std::string(buff);
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%ld,%ld,%ld)",
          this->bank,
          this->row,
          this->col);
  return std::string(buff);
}

// Define the static DRAM configs

MemConfiguration DRAMAddr::MemConfig;
size_t DRAMAddr::base_msb;
bool DRAMAddr::valid_memcfg;

std::map<size_t, MemConfiguration> DRAMAddr::Configs = {
    {(CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)),
     {
         .BK_SHIFT =  26,
         .BK_MASK =  (0b1111),
         .ROW_SHIFT =  0,
         .ROW_MASK =  (0b1111111111111),
         .COL_SHIFT =  13,
         .COL_MASK =  (0b1111111111111),
         .DRAM_MTX =  {
             0b000000000000000010000001000000,
             0b000000000000100100000000000000,
             0b000000000001001000000000000000,
             0b000000000010010000000000000000,
             0b000000000000000001000000000000,
             0b000000000000000000100000000000,
             0b000000000000000000010000000000,
             0b000000000000000000001000000000,
             0b000000000000000000000100000000,
             0b000000000000000000000010000000,
             0b000000000000000000000001000000,
             0b000000000000000000000000100000,
             0b000000000000000000000000010000,
             0b000000000000000000000000001000,
             0b000000000000000000000000000100,
             0b000000000000000000000000000010,
             0b000000000000000000000000000001,
             0b100000000000000000000000000000,
             0b010000000000000000000000000000,
             0b001000000000000000000000000000,
             0b000100000000000000000000000000,
             0b000010000000000000000000000000,
             0b000001000000000000000000000000,
             0b000000100000000000000000000000,
             0b000000010000000000000000000000,
             0b000000001000000000000000000000,
             0b000000000100000000000000000000,
             0b000000000010000000000000000000,
             0b000000000001000000000000000000,
             0b000000000000100000000000000000},
         .ADDR_MTX =  {
             0b000000000000000001000000000000,
             0b000000000000000000100000000000,
             0b000000000000000000010000000000,
             0b000000000000000000001000000000,
             0b000000000000000000000100000000,
             0b000000000000000000000010000000,
             0b000000000000000000000001000000,
             0b000000000000000000000000100000,
             0b000000000000000000000000010000,
             0b000000000000000000000000001000,
             0b000000000000000000000000000100,
             0b000000000000000000000000000010,
             0b000000000000000000000000000001,
             0b000100000000000000000000000100,
             0b001000000000000000000000000010,
             0b010000000000000000000000000001,
             0b100000000010000000000000000000,
             0b000010000000000000000000000000,
             0b000001000000000000000000000000,
             0b000000100000000000000000000000,
             0b000000010000000000000000000000,
             0b000000001000000000000000000000,
             0b000000000100000000000000000000,
             0b000000000010000000000000000000,
             0b000000000001000000000000000000,
             0b000000000000100000000000000000,
             0b000000000000010000000000000000,
             0b000000000000001000000000000000,
             0b000000000000000100000000000000,
             0b000000000000000010000000000000}
     }},
    {(CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)),
     {
         .BK_SHIFT =  25,
         .BK_MASK =  (0b11111),
         .ROW_SHIFT =  0,
         .ROW_MASK =  (0b111111111111),
         .COL_SHIFT =  12,
         .COL_MASK =  (0b1111111111111),
         .DRAM_MTX =  {
             0b000000000000000010000001000000,
             0b000000000001000100000000000000,
             0b000000000010001000000000000000,
             0b000000000100010000000000000000,
             0b000000001000100000000000000000,
             0b000000000000000001000000000000,
             0b000000000000000000100000000000,
             0b000000000000000000010000000000,
             0b000000000000000000001000000000,
             0b000000000000000000000100000000,
             0b000000000000000000000010000000,
             0b000000000000000000000001000000,
             0b000000000000000000000000100000,
             0b000000000000000000000000010000,
             0b000000000000000000000000001000,
             0b000000000000000000000000000100,
             0b000000000000000000000000000010,
             0b000000000000000000000000000001,
             0b100000000000000000000000000000,
             0b010000000000000000000000000000,
             0b001000000000000000000000000000,
             0b000100000000000000000000000000,
             0b000010000000000000000000000000,
             0b000001000000000000000000000000,
             0b000000100000000000000000000000,
             0b000000010000000000000000000000,
             0b000000001000000000000000000000,
             0b000000000100000000000000000000,
             0b000000000010000000000000000000,
             0b000000000001000000000000000000},
         .ADDR_MTX =  {
             0b000000000000000000100000000000,
             0b000000000000000000010000000000,
             0b000000000000000000001000000000,
             0b000000000000000000000100000000,
             0b000000000000000000000010000000,
             0b000000000000000000000001000000,
             0b000000000000000000000000100000,
             0b000000000000000000000000010000,
             0b000000000000000000000000001000,
             0b000000000000000000000000000100,
             0b000000000000000000000000000010,
             0b000000000000000000000000000001,
             0b000010000000000000000000001000,
             0b000100000000000000000000000100,
             0b001000000000000000000000000010,
             0b010000000000000000000000000001,
             0b100000000001000000000000000000,
             0b000001000000000000000000000000,
             0b000000100000000000000000000000,
             0b000000010000000000000000000000,
             0b000000001000000000000000000000,
             0b000000000100000000000000000000,
             0b000000000010000000000000000000,
             0b000000000001000000000000000000,
             0b000000000000100000000000000000,
             0b000000000000010000000000000000,
             0b000000000000001000000000000000,
             0b000000000000000100000000000000,
             0b000000000000000010000000000000,
             0b000000000000000001000000000000}
     }}};

DRAMAddr::DRAMAddr() {

}

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p) {
  j = {{"bank", p.bank},
       {"row", p.row},
       {"col", p.col}
  };
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
}

#endif
