/*
 * Copyright (c) 2024 by ETH Zurich.
 * Licensed under the MIT License, see LICENSE file for more details.
 */

#ifndef BLACKSMITH_DRAMCONFIG_HPP_
#define BLACKSMITH_DRAMCONFIG_HPP_

#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

// NOTE: Also update the to_string(), select_config() and check_cpu_for_microarchitecture() methods in the CPP file when
//       adding new microarchitectures.
enum class Microarchitecture {
  AMD_ZEN_1_PLUS,
  AMD_ZEN_2,
  AMD_ZEN_3,
  AMD_ZEN_4,
  INTEL_COFFEE_LAKE,
  // @iamywang, Jul 17, 2024: add Comet Lake
  INTEL_COMET_LAKE,
};

const char* to_string(Microarchitecture uarch);

class DRAMConfig {
public:
  // Get the selected DRAMConfig instance.
  static void select_config(Microarchitecture uarch, int ranks, int bank_groups, int banks, bool samsung_row_mapping);
  static void select_config(std::string const& uarch_str, int ranks, int bank_groups, int banks, bool samsung_row_mapping);

  // Get the selected DRAMConfig instance.
  static DRAMConfig& get();

  [[nodiscard]] Microarchitecture get_uarch() const { return uarch; }
  [[nodiscard]] uint64_t get_sync_ref_threshold() const { return sync_ref_threshold; }
  void set_sync_ref_threshold(size_t threshold) { sync_ref_threshold = threshold; }

  [[nodiscard]] size_t memory_size() const { return (1ULL << total_bits()); }
  [[nodiscard]] size_t total_bits() const { return matrix_size; }
  [[nodiscard]] size_t bank_bits() const { return __builtin_popcountll(bank_mask); }
  [[nodiscard]] size_t row_bits() const { return __builtin_popcountll(row_mask); }
  [[nodiscard]] size_t column_bits() const { return __builtin_popcountll(column_mask); }

  [[nodiscard]] size_t banks() const { return 1ULL << bank_bits(); }
  [[nodiscard]] size_t rows() const { return 1ULL << row_bits(); }
  [[nodiscard]] size_t columns() const { return 1ULL << column_bits(); }

  [[nodiscard]] size_t row_to_row_offset() const {
    auto least_significant_row_bit_index = row_shift;
    auto least_significant_row_bit_func= dram_matrix[matrix_size - least_significant_row_bit_index - 1];
    return least_significant_row_bit_func;
  }

  [[nodiscard]] size_t apply_dram_matrix(size_t phys_addr) const {
    return apply_matrix(dram_matrix, phys_addr);
  }
  [[nodiscard]] size_t apply_addr_matrix(size_t linearized_dram_addr) const {
    return apply_matrix(addr_matrix, linearized_dram_addr);
  }

  [[nodiscard]] size_t linearize_dram_addr(size_t bank, size_t row, size_t column) const {
    // This essentially wraps around any {bank,row,col} that is larger than allowed.
    return ((bank & bank_mask) << bank_shift)
      | ((row & row_mask) << row_shift)
      | ((column & column_mask) << column_shift);
  }

  void delinearize_dram_addr(
    size_t linearized_dram_addr, size_t& out_bank, size_t& out_row, size_t& out_column) const {
    out_bank = (linearized_dram_addr >> bank_shift) & bank_mask;
    out_row = (linearized_dram_addr >> row_shift) & row_mask;
    out_column = (linearized_dram_addr >> column_shift) & column_mask;
  }

private:
  [[nodiscard]] static size_t apply_matrix(const std::vector<size_t>& matrix, size_t addr);

  DRAMConfig() = default;

  // Checks that all preconditions for the configuration are fulfilled, or fails by calling exit().
  void check_validity();

  // Meta information not encoded in the shifts, masks and matrices.
  Microarchitecture uarch;

  // Information only dependent on the uarch.
  uint64_t sync_ref_threshold;

  // FIXME: Currently, phys_dram_offset is only supported in that it can only affects bits above what we calculate with
  //        the matrix. This is checked with an assertion. In the future, it may make sense to be more clever in
  //        DRAMAddr to be able to account for this.
  // phys_addr - phys_dram_offset = dram_addr
  size_t phys_dram_offset { 0 };

  // Internally, all "higher-order" address parts (e.g., rank, bank group, bank) are lumped together as "bank".
  size_t bank_shift { 0 };
  size_t bank_mask { 0 };

  size_t row_shift { 0 };
  size_t row_mask { 0 };

  size_t column_shift { 0 };
  size_t column_mask { 0 };

  size_t matrix_size { 0 };
  // maps physical addr -> DRAM addr (subch | rank | bankgroup | bank | row | col)
  std::vector<size_t> dram_matrix;
  // maps DRAM addr (subch | rank | bankgroup | bank | row | col) -> physical addr
  std::vector<size_t> addr_matrix;
};

#endif //BLACKSMITH_DRAMCONFIG_HPP_
