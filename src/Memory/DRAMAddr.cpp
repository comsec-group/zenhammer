#include "Memory/DRAMAddr.hpp"
#include "Memory/DRAMConfig.hpp"
#include "Utilities/Logger.hpp"

static std::map<int, size_t> base_msb_for_mapping;
static struct {
  int from_mapping_id { -1 };
  int to_mapping_id { -1 };
  std::vector<size_t> translation;
} translation_data;

void DRAMAddr::initialize_mapping(int mapping_id, volatile char *start_address) {
  // Set the bits above the ones covered by the matrices (i.e., the bits that stay constant for all addresses).
  auto matrix_mask = (1ULL << DRAMConfig::get().total_bits()) - 1;
  auto base_msb = (size_t)start_address & ~matrix_mask;
  base_msb_for_mapping[mapping_id] = base_msb;
  Logger::log_info(format_string("DRAMAddr: Initialized MSBs for mapping_id = %d: %p", mapping_id, (void*)base_msb));
}

void DRAMAddr::initialize_bank_translation(int from_mapping_id, int to_mapping_id, std::vector<size_t> translation) {
  translation_data.from_mapping_id = from_mapping_id;
  translation_data.to_mapping_id = to_mapping_id;
  translation_data.translation = std::move(translation);
}

size_t DRAMAddr::translate_bank(int from_mapping_id, int to_mapping_id, size_t bank) {
  if (translation_data.from_mapping_id != from_mapping_id || translation_data.to_mapping_id != to_mapping_id) {
    Logger::log_error(format_string(
      "Error: Cannot translate bank from mapping %d to mapping %d as no translation data is available.",
      from_mapping_id,
      to_mapping_id));
    Logger::log_info(format_string(
      "Translation data is available for translation from mapping %d to mapping %d.",
      translation_data.from_mapping_id,
      translation_data.to_mapping_id));
    exit(EXIT_FAILURE);
  }
  assert(translation_data.translation.size() == DRAMConfig::get().banks());
  return translation_data.translation[bank % DRAMConfig::get().banks()];
}

DRAMAddr::DRAMAddr(void *addr) {
  // FIXME: Make this work with arbitrary offsets. Currently, subtracting PHYS_DRAM_OFFSET is not required as the offset
  //        is guaranteed to only affect bits above the DRAM address matrix ("the MSBs").
  auto phys_addr = (size_t)addr;
  size_t linearized_dram_addr = DRAMConfig::get().apply_dram_matrix(phys_addr);
  // Returns result into out parameters bank, row, col.
  DRAMConfig::get().delinearize_dram_addr(linearized_dram_addr, bank, row, col);

  // Recover which mapping this address belongs to.
  auto matrix_mask = (1ULL << DRAMConfig::get().total_bits()) - 1;
  auto base_msb = (size_t)addr & ~matrix_mask;
  mapping_id = 0;
  for (auto const& [id, base_addr] : base_msb_for_mapping) {
    if (base_msb == base_addr) {
      mapping_id = id;
      break;
    }
  }

#ifdef DEBUG_ADDR_CONVERSIONS
  Logger::log_info(format_string("[DEBUG_ADDR_CONVERSIONS] 0x%010lx -> BK=0b%05b, ROW=0x%03x, COL=0x%02x", addr, bank, row, col));
#endif
}

void *DRAMAddr::to_virt() const {
  size_t linearized = DRAMConfig::get().linearize_dram_addr(bank, row, col);
  size_t result = DRAMConfig::get().apply_addr_matrix(linearized);

  void *virt_addr = (void *)(base_msb_for_mapping[mapping_id] | result);
#ifdef DEBUG_ADDR_CONVERSIONS
  Logger::log_info(format_string("[DEBUG_ADDR_CONVERSIONS] BK=0b%05b, ROW=0x%03x, COL=0x%02x -> %0x010lx", bank, row, col, virt_addr));
#endif
  return virt_addr;
}

std::string DRAMAddr::to_string() const {
  char buff[1024];
  if (mapping_id == 0) {
    sprintf(buff, "DRAMAddr(b: %zu, r: %zu, c: %zu) = %p",
            actual_bank(),
            actual_row(),
            actual_column(),
            this->to_virt());
  } else {
    sprintf(buff, "DRAMAddr(b: %zu, r: %zu, c: %zu, mapping_id: %d) = %p",
            actual_bank(),
            actual_row(),
            actual_column(),
            mapping_id,
            this->to_virt());
  }
  return { buff };
}

std::string DRAMAddr::to_string_compact() const {
  char buff[1024];
  if (mapping_id == 0) {
    sprintf(buff, "(%ld,%ld,%ld)",
            actual_bank(),
            actual_row(),
            actual_column());
  } else {
    sprintf(buff, "(%ld,%ld,%ld,mapping_id=%d)",
            actual_bank(),
            actual_row(),
            actual_column(),
            mapping_id);
  }
  return { buff };
}

DRAMAddr DRAMAddr::add(size_t bank_increment, size_t row_increment, size_t column_increment) const {
  return {bank + bank_increment, row + row_increment, col + column_increment};
}

void DRAMAddr::add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment) {
  bank += bank_increment;
  row += row_increment;
  col += column_increment;
}

#ifdef ENABLE_JSON
nlohmann::json DRAMAddr::get_memcfg_json() {
  // FIXME: Re-implement this.
  // std::map<size_t, nlohmann::json> memcfg_to_json = {
  //     {(CHANS(1UL) | DIMMS(1UL) | RANKS(1UL) | BANKS(16UL)),
  //      nlohmann::json{
  //          {"channels", 1},
  //          {"dimms", 1},
  //          {"ranks", 1},
  //          {"banks", 16}}},
  //     {(CHANS(1UL) | DIMMS(1UL) | RANKS(2UL) | BANKS(16UL)),
  //      nlohmann::json{
  //          {"channels", 1},
  //          {"dimms", 1},
  //          {"ranks", 2},
  //          {"banks", 16}}}
  // };
  return {};
}

void to_json(nlohmann::json &j, const DRAMAddr &p) {
  if (p.mapping_id == 0) {
    j = {{ "bank", p.bank },
         { "row",  p.row },
         { "col",  p.col }
    };
  } else {
    j = {{ "bank", p.bank },
         { "row",  p.row },
         { "col",  p.col },
         { "mapping_id", p.mapping_id }
    };
  }
}

void from_json(const nlohmann::json &j, DRAMAddr &p) {
  j.at("bank").get_to(p.bank);
  j.at("row").get_to(p.row);
  j.at("col").get_to(p.col);
  if (j.contains("mapping_id")) {
    j.at("mapping_id").get_to(p.mapping_id);
  } else {
    p.mapping_id = 0;
  }
}

#endif
