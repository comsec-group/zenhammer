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

// no. of DIMMs
#define DIMMS(x) ((x) << (4UL * 3UL))

// no. of ranks
#define RANKS(x) ((x) << (4UL * 2UL))

// no. of bankgroups
#define BANKGROUPS(x) ((x) << (4UL * 1UL))

// no. of banks per bankgroup
#define BANKS(x) ((x) << (4UL * 0UL))

//#define MTX_SIZE (34)
#define MTX_SIZE (30)

typedef uint64_t mem_config_t;

struct MemConfiguration {
  size_t IDENTIFIER;
  size_t SC_SHIFT;
  size_t SC_MASK;
  size_t BG_SHIFT;
  size_t BG_MASK;
  size_t BK_SHIFT;
  size_t BK_MASK;
  size_t ROW_SHIFT;
  size_t ROW_MASK;
  size_t COL_SHIFT;
  size_t COL_MASK;
  size_t DRAM_MTX[MTX_SIZE];
  size_t ADDR_MTX[MTX_SIZE];
};

class DRAMAddr {
 private:
  static std::map<size_t, MemConfiguration> Configs;

  static MemConfiguration MemConfig;

  static size_t base_msb;

  static std::unordered_map<size_t, std::pair<size_t, size_t>> bankIdx2bgbk;

  [[nodiscard]] size_t linearize() const;

 public:
  size_t subchan{};
  size_t bankgroup{};
  size_t bank{};
  size_t row{};
  size_t col{};

  /* constructor for backwards-compatibility */
  DRAMAddr(size_t bk, size_t r, size_t c);
  DRAMAddr(size_t sc, size_t bk, size_t r, size_t c);

  DRAMAddr(size_t sc, size_t bg, size_t bk, size_t r, size_t c);

  // must be DefaultConstructible for JSON (de-)serialization
  DRAMAddr();

  static void initialize(volatile char *start_address);

  static void set_base_msb(void *buff);

  static void load_mem_config(mem_config_t cfg);

  static uint64_t get_row_increment();

  static void initialize_configs();

  explicit DRAMAddr(void *vaddr);

  [[gnu::unused]] std::string to_string();

  [[nodiscard]] std::string to_string_compact() const;

  void *to_virt();

  [[nodiscard]] void *to_virt() const;

  void *to_phys();

  [[nodiscard]] void *to_phys() const;

  void add_inplace(size_t sc_increment,
                   size_t bg_increment,
                   size_t bk_increment,
                   size_t row_increment,
                   size_t col_increment);

  void add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment);

  [[nodiscard]] DRAMAddr add(size_t sc_increment,
                             size_t bankgroup_increment,
                             size_t bank_increment,
                             size_t row_increment,
                             size_t column_increment) const;

  [[nodiscard]] DRAMAddr add(size_t bank_increment, size_t row_increment, size_t column_increment) const;

#ifdef ENABLE_JSON
  static nlohmann::json get_memcfg_json();
  void set_row(size_t row);
#endif
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p);

void from_json(const nlohmann::json &j, DRAMAddr &p);

#endif

#endif /* DRAMADDR */
