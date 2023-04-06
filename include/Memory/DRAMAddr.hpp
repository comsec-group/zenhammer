#ifndef DRAMADDR
#define DRAMADDR

#include <map>
#include <string>
#include <vector>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

// no. of channels on the system (NOT subchannels per DIMM, we always assume 2)
#define CHANS(x) ((x) << (4UL * 4UL))
#define CHANS_INV(x) (((x) >> (4UL * 4UL)) && 0b11111)

// no. of DIMMs
#define DIMMS(x) ((x) << (4UL * 3UL))
#define DIMMS_INV(x) (((x) >> (4UL * 3UL)) && 0b11111)

// no. of ranks
#define RANKS(x) ((x) << (4UL * 2UL))
#define RANKS_INV(x) (((x) >> (4UL * 2UL)) && 0b11111)

// no. of bankgroups
#define BANKGROUPS(x) ((x) << (4UL * 1UL))
#define BANKGROUPS_INV(x) (((x) >> (4UL * 1UL)) && 0b11111)

// no. of banks per bankgroup
#define BANKS(x) ((x) << (4UL * 0UL))
#define BANKS_INV(x) (((x) >> (4UL * 0UL)) && 0b11111)

typedef uint64_t mem_config_t;

struct MemConfiguration {
  size_t IDENTIFIER;
  size_t SC_SHIFT;
  size_t SC_MASK;
  size_t RK_SHIFT;
  size_t RK_MASK;
  size_t BG_SHIFT;
  size_t BG_MASK;
  size_t BK_SHIFT;
  size_t BK_MASK;
  size_t ROW_SHIFT;
  size_t ROW_MASK;
  size_t COL_SHIFT;
  size_t COL_MASK;
  // to simplify our setup, as we have a single superpage only, we cut-off the
  // higher bits of the FNs s.t. we stay within [start,start+HUGEPAGE_SZ]
  size_t DRAM_MTX[29];
  size_t ADDR_MTX[29];
};

class DRAMAddr {
 private:
  static std::map<size_t, MemConfiguration> Configs;

  static MemConfiguration MemConfig;

  static uint64_t base_msb;

  size_t subchan{};
  size_t rank{};
  size_t bankgroup{};
  size_t bank{};
  size_t row{};
  size_t col{};

 public:

  /* constructor for backwards-compatibility */
  DRAMAddr(size_t bk, size_t r, size_t c);
  DRAMAddr(size_t sc, size_t bk, size_t r, size_t c);
  DRAMAddr(size_t sc, size_t rk,  size_t bg, size_t bk, size_t r, size_t c);

  // must be DefaultConstructible for JSON (de-)serialization
  DRAMAddr();

  static void initialize(volatile char *start_address, size_t num_ranks, size_t num_bankgroups, size_t num_banks);

  static void set_base_msb(void *buff);

  static void load_mem_config(mem_config_t cfg);

  static void initialize_configs();

  explicit DRAMAddr(void *vaddr);

  [[gnu::unused]] std::string to_string();

  [[nodiscard]] std::string to_string_compact() const;

  void *to_virt();

  void *to_phys();

  void add_inplace(size_t sc_increment,
                   size_t bg_increment,
                   size_t bk_increment,
                   size_t row_increment,
                   size_t col_increment);

  void add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment);

  [[nodiscard]] DRAMAddr add(size_t sc_increment,
                             size_t rk_increment,
                             size_t bankgroup_increment,
                             size_t bank_increment,
                             size_t row_increment,
                             size_t column_increment) const;

  size_t get_subchan() const;
  size_t get_bankgroup() const;
  size_t get_rank() const;
  size_t get_bank() const;
  size_t get_row() const;  
  size_t get_column() const;

  void set_row(size_t row_no);

  void increment_all_common();

#ifdef ENABLE_JSON
  nlohmann::json get_memcfg_json();

  friend void to_json(nlohmann::json &j, const DRAMAddr &p);

  friend void from_json(const nlohmann::json &j, DRAMAddr &p);
#endif

};

#ifdef ENABLE_JSON
void to_json(nlohmann::json &j, const DRAMAddr &p);
void from_json(const nlohmann::json &j, DRAMAddr &p);
#endif

#endif /* DRAMADDR */
