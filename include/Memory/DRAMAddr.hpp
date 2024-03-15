/*
 * Copyright (c) 2024 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef DRAMADDR
#define DRAMADDR

#include <string>
#include "DRAMConfig.hpp"

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif


class DRAMAddr {
 public:
  // These can overflow and underflow, and should be interpreted modulo {bank, row, col} count.
  // Example: If there are 16 banks, bank = 18 means actual bank 2 (the third bank).
  size_t bank { 0 };
  size_t row { 0 };
  size_t col { 0 };
  int mapping_id { 0 };

  [[nodiscard]] size_t actual_bank() const { return bank % DRAMConfig::get().banks(); }
  [[nodiscard]] size_t actual_row() const { return row % DRAMConfig::get().rows(); }
  [[nodiscard]] size_t actual_column() const { return col % DRAMConfig::get().columns(); }

  // instance methods
  DRAMAddr(size_t bk, size_t r, size_t c, int map_id = 0)
    : bank(bk), row(r), col(c), mapping_id(map_id) {

  }

  explicit DRAMAddr(void *addr);

  // must be DefaultConstructible for JSON (de-)serialization
  DRAMAddr() = default;

  static void initialize_mapping(int mapping_id, volatile char *start_address);
  static void initialize_bank_translation(int from_mapping_id, int to_mapping_id, std::vector<size_t> translation);
  static size_t translate_bank(int from_mapping_id, int to_mapping_id, size_t bank);

  [[nodiscard]] std::string to_string() const;
  [[nodiscard]] std::string to_string_compact() const;

  [[nodiscard]] void *to_virt() const;

  [[nodiscard]] DRAMAddr add(size_t bank_increment, size_t row_increment, size_t column_increment) const;

  void add_inplace(size_t bank_increment, size_t row_increment, size_t column_increment);

#ifdef ENABLE_JSON
  static nlohmann::json get_memcfg_json();
#endif
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const DRAMAddr &p);

void from_json(const nlohmann::json &j, DRAMAddr &p);

#endif

#endif /* DRAMADDR */
