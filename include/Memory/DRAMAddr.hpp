#ifndef DRAMADDR
#define DRAMADDR

#include <map>
#include <string>
#include <vector>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#define CHANS(x) ((x) << (8UL * 3UL))
#define DIMMS(x) ((x) << (8UL * 2UL))
#define RANKS(x) ((x) << (8UL * 1UL))
#define BANKS(x) ((x) << (8UL * 0UL))
#define MEM_CONFIG(ch, d, r, b) (CHANS(ch) | DIMMS(d) | RANKS(r) | BANKS(b))

#define MTX_SIZE (30)

typedef size_t mem_config_t;

typedef struct {
  size_t BK_SHIFT;
  size_t BK_MASK;
  size_t ROW_SHIFT;
  size_t ROW_MASK;
  size_t COL_SHIFT;
  size_t COL_MASK;
  size_t DRAM_MTX[MTX_SIZE];
  size_t ADDR_MTX[MTX_SIZE];
} MemConfiguration;

class DRAMAddr {
 private:
  // Class attributes
  static std::map<size_t, MemConfiguration> Configs;
  static MemConfiguration MemConfig;
  static bool valid_memcfg;
  static size_t base_msb;

  size_t linearize() const;

 public:
  size_t bank{};
  size_t row{};
  size_t col{};

  // class methods
  static void set_base_msb(void *buff);

  static void load_mem_config(mem_config_t cfg);

  // instance methods
  DRAMAddr(size_t bk, size_t r, size_t c);

  explicit DRAMAddr(void *addr);

  // must be DefaultConstructible for JSON (de-)serialization
  DRAMAddr();

  void *to_virt();

  [[gnu::unused]] std::string to_string();

  static void initialize(uint64_t num_bank_rank_functions, volatile char *start_address);

  std::string to_string_compact() const;

  void *to_virt() const;

  DRAMAddr add(size_t bank_increment, size_t row_increment, size_t column_increment) const;

  void add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment);
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p);

void from_json(const nlohmann::json &j, DRAMAddr &p);

#endif

#endif /* DRAMADDR */
