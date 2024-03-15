#include "GlobalDefines.hpp"
#include "Memory/DRAMConfig.hpp"
#include "Utilities/Logger.hpp"

#include <array>
#include <cassert>
#include <map>

static DRAMConfig* selected_config { nullptr };

const char* to_string(Microarchitecture uarch) {
  switch (uarch) {
    case Microarchitecture::AMD_ZEN_1_PLUS:
      return "AMD_ZEN_1_PLUS";
    case Microarchitecture::AMD_ZEN_2:
      return "AMD_ZEN_2";
    case Microarchitecture::AMD_ZEN_3:
      return "AMD_ZEN_3";
    case Microarchitecture::AMD_ZEN_4:
      return "AMD_ZEN_4";
    case Microarchitecture::INTEL_COFFEE_LAKE:
      return "INTEL_COFFEE_LAKE";
  }
  Logger::log_error("Selected microarchitecture does not implement the to_string() method. Please fix!");
  exit(1);
}

static std::string get_cpu_model_string() {
  std::string cpu_model;
  std::array<char, 128> buffer {};
  std::unique_ptr<FILE, decltype(&pclose)> pipe(popen("cat /proc/cpuinfo | grep \"model name\" | cut -d':' -f2 | awk '{$1=$1;print}' | head -1", "r"), pclose);
  if (!pipe) {
    throw std::runtime_error("popen() failed!");
  }
  while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
    cpu_model.append(buffer.data());
  }
  return cpu_model;
}

static void check_cpu_for_microarchitecture(Microarchitecture uarch) {
  Logger::log_info("Detecting CPU model:");
  auto cpu_model = get_cpu_model_string();
  Logger::log_data(cpu_model);

  std::vector<std::string> supported_cpus;

  switch (uarch) {
    case Microarchitecture::AMD_ZEN_1_PLUS:
      supported_cpus = {
        "Ryzen 5 2600X"
      };
      break;
    case Microarchitecture::AMD_ZEN_2:
      supported_cpus = {
        "Ryzen 5 3600X",
        "Ryzen 5 3600"
      };
      break;
    case Microarchitecture::AMD_ZEN_3:
      supported_cpus = {
        "Ryzen 5 5600G"
      };
      break;
    case Microarchitecture::AMD_ZEN_4:
      supported_cpus = {
        "Ryzen 7 7700X"
      };
      break;
    case Microarchitecture::INTEL_COFFEE_LAKE:
      supported_cpus = {
        // Coffee Lake
        "i5-8400",
        "i5-8500",
        "i5-8600",
        "i5-9400",
        "i5-9500",
        "i5-9600",
        "i7-8086",
        "i7-8700",
        "i7-9700",
        "i7-9900"
      };
      break;
    default:
      break;
  };

  bool cpu_supported = false;
  for (const auto& model : supported_cpus) {
    if (cpu_model.find(model) != std::string::npos) {
      cpu_supported = true;
      break;
    }
  }

  if (!cpu_supported) {
    Logger::log_error("Could not verify that the system's CPU matches the selected microarchitecture, \
      as the installed CPU is not in the list of supported CPUs.");
    Logger::log_error("CPU model is not supported. You need to run DRAMA to update the DRAM address matrices. \
      See the README.md for details.");
    exit(EXIT_FAILURE);
  }
}

void DRAMConfig::select_config(Microarchitecture uarch, int ranks, int bank_groups, int banks, bool samsung_row_mapping) {
  // Log what was selected.
  Logger::log_info("Selected the following DRAM configuration");
  Logger::log_data(format_string("    uarch       = %s", to_string(uarch)));
  Logger::log_data(format_string("    ranks       = %d", ranks));
  Logger::log_data(format_string("    bank groups = %d", bank_groups));
  Logger::log_data(format_string("    banks       = %d", banks));
  Logger::log_data(format_string("    row mapping = %s", samsung_row_mapping ? "Samsung" : "sequential"));

  check_cpu_for_microarchitecture(uarch);

  if (uarch == Microarchitecture::INTEL_COFFEE_LAKE && ranks == 1 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0;
    // 4 bank bits (consisting of rank, bank group, bank)
    selected_config->bank_shift = 26;
    selected_config->bank_mask = 0b1111;
    // 13 row bits (inside 1 GB)
    selected_config->row_shift = 0;
    selected_config->row_mask = 0b1111111111111;
    // 13 column bits
    selected_config->column_shift = 13;
    selected_config->column_mask = 0b1111111111111;

    // 30 bits (1 GB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      Logger::log_error("No Samsung row mappings available for chosen microarchitecture.");
      exit(EXIT_FAILURE);
    } else {
      selected_config->dram_matrix = {
        0b000000000000000010000001000000, /* 0x02040 bank b3 = addr b6 + b13 */
        0b000000000000100100000000000000, /* 0x24000 bank b2 = addr b14 + b17 */
        0b000000000001001000000000000000, /* 0x48000 bank b1 = addr b15 + b18 */
        0b000000000010010000000000000000, /* 0x90000 bank b0 = addr b16 + b19 */
        0b000000000000000010000000000000, /* col b12 = addr b13 */
        0b000000000000000001000000000000, /* col b11 = addr b12 */
        0b000000000000000000100000000000, /* col b10 = addr b11 */
        0b000000000000000000010000000000, /* col b9 = addr b10 */
        0b000000000000000000001000000000, /* col b8 = addr b9 */
        0b000000000000000000000100000000, /* col b7 = addr b8*/
        0b000000000000000000000010000000, /* col b6 = addr b7 */
        0b000000000000000000000000100000, /* col b5 = addr b5 */
        0b000000000000000000000000010000, /* col b4 = addr b4*/
        0b000000000000000000000000001000, /* col b3 = addr b3 */
        0b000000000000000000000000000100, /* col b2 = addr b2 */
        0b000000000000000000000000000010, /* col b1 = addr b1 */
        0b000000000000000000000000000001, /* col b0 = addr b0*/
        0b100000000000000000000000000000, /* row b12 = addr b29 */
        0b010000000000000000000000000000, /* row b11 = addr b28 */
        0b001000000000000000000000000000, /* row b10 = addr b27 */
        0b000100000000000000000000000000, /* row b9 = addr b26 */
        0b000010000000000000000000000000, /* row b8 = addr b25 */
        0b000001000000000000000000000000, /* row b7 = addr b24 */
        0b000000100000000000000000000000, /* row b6 = addr b23 */
        0b000000010000000000000000000000, /* row b5 = addr b22 */
        0b000000001000000000000000000000, /* row b4 = addr b21 */
        0b000000000100000000000000000000, /* row b3 = addr b20 */
        0b000000000010000000000000000000, /* row b2 = addr b19 */
        0b000000000001000000000000000000, /* row b1 = addr b18 */
        0b000000000000100000000000000000, /* row b0 = addr b17 */
      };
      selected_config->addr_matrix = {
        0b000000000000000001000000000000, /* addr b29 = row b12 */
        0b000000000000000000100000000000, /* addr b28 = row b11 */
        0b000000000000000000010000000000, /* addr b27 = row b10 */
        0b000000000000000000001000000000, /* addr b26 = row b9 */
        0b000000000000000000000100000000, /* addr b25 = row b8 */
        0b000000000000000000000010000000, /* addr b24 = row b7 */
        0b000000000000000000000001000000, /* addr b23 = row b6 */
        0b000000000000000000000000100000, /* addr b22 = row b5 */
        0b000000000000000000000000010000, /* addr b21 = row b4 */
        0b000000000000000000000000001000, /* addr b20 = row b3 */
        0b000000000000000000000000000100, /* addr b19 = row b2 */
        0b000000000000000000000000000010, /* addr b18 = row b1 */
        0b000000000000000000000000000001, /* addr b17 = row b0 */
        0b000100000000000000000000000100, /* addr b16 = bank b0 + row b2 (addr b19) */
        0b001000000000000000000000000010, /* addr b15 = bank b1 + row b1 (addr b18) */
        0b010000000000000000000000000001, /* addr b14 = bank b2 + row b0 (addr b17) */
        0b000010000000000000000000000000, /* addr b13 = col b12 */
        0b000001000000000000000000000000, /* addr b12 = col b11 */
        0b000000100000000000000000000000, /* addr b11 = col b10 */
        0b000000010000000000000000000000, /* addr b10 = col b9 */
        0b000000001000000000000000000000, /* addr b9 = col b8 */
        0b000000000100000000000000000000, /* addr b8 = col b7 */
        0b000000000010000000000000000000, /* addr b7 = col b6 */
        0b100010000000000000000000000000, /* addr b6 = bank b3 + col b12 (addr b13)*/
        0b000000000001000000000000000000, /* addr b5 = col b5 */
        0b000000000000100000000000000000, /* addr b4 = col b4 */
        0b000000000000010000000000000000, /* addr b3 = col b3 */
        0b000000000000001000000000000000, /* addr b2 = col b2 */
        0b000000000000000100000000000000, /* addr b1 = col b1 */
        0b000000000000000010000000000000  /* addr b0 = col b0 */
      };
    }
  } else if (uarch == Microarchitecture::INTEL_COFFEE_LAKE && ranks == 2 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0;
    // 5 bank bits (consisting of rank, bank group, bank)
    selected_config->bank_shift = 25;
    selected_config->bank_mask = 0b11111;
    // 12 row bits (inside 1 GB)
    selected_config->row_shift = 0;
    selected_config->row_mask = 0b111111111111;
    // 13 column bits
    selected_config->column_shift = 12;
    selected_config->column_mask = 0b1111111111111;

    // 30 bits (1 GB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      Logger::log_error("No Samsung row mappings available for chosen microarchitecture.");
      exit(EXIT_FAILURE);
    } else {
      selected_config->dram_matrix = {
        0b000000000000000010000001000000,
        0b000000000001000100000000000000,
        0b000000000010001000000000000000,
        0b000000000100010000000000000000,
        0b000000001000100000000000000000,
        0b000000000000000010000000000000,
        0b000000000000000001000000000000,
        0b000000000000000000100000000000,
        0b000000000000000000010000000000,
        0b000000000000000000001000000000,
        0b000000000000000000000100000000,
        0b000000000000000000000010000000,
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
        0b000000000001000000000000000000
      };
      selected_config->addr_matrix = {
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
        0b000001000000000000000000000000,
        0b000000100000000000000000000000,
        0b000000010000000000000000000000,
        0b000000001000000000000000000000,
        0b000000000100000000000000000000,
        0b000000000010000000000000000000,
        0b000000000001000000000000000000,
        0b100001000000000000000000000000,
        0b000000000000100000000000000000,
        0b000000000000010000000000000000,
        0b000000000000001000000000000000,
        0b000000000000000100000000000000,
        0b000000000000000010000000000000,
        0b000000000000000001000000000000
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_1_PLUS && ranks == 2 && bank_groups == 4 && banks == 4) {
    // NOTE: The number of row_bits (16 or 17) only affects bits above what is covered by the matrices, meaning the
    //       DRAMConfig is identical.
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x40000000;  /* 1 GB */
    // 5 bank bits (consisting of rank, bank group, bank)
    selected_config->bank_shift = 25;
    selected_config->bank_mask = 0b11111;
    // 12 row bits (inside 1 GB)
    selected_config->row_shift = 13;
    selected_config->row_mask = 0b111111111111;
    // 13 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b1111111111111;

    // 30 bits (1 GB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b111111111111100000000000000000,  /*  rank_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 */
        0b100010001000000100000000000000,  /*  bg_b1 = addr b29 b25 b21 b14 */
        0b000100010001001000000000000000,  /*  bg_b0 = addr b26 b22 b18 b15 */
        0b001000100010010000000000000000,  /*  bk_b1 = addr b27 b23 b19 b16 */
        0b010001000100000011111111000000,  /*  bk_b0 = addr b28 b24 b20 b13 b12 b11 b10 b9 b8 b7 b6 */
        0b100000000000000000000000000000,  /*  row_b11 = addr b29 */
        0b010000000000000000000000000000,  /*  row_b10 = addr b28 */
        0b001000000000000000000000000000,  /*  row_b9 = addr b27 */
        0b000100000000000000000000000000,  /*  row_b8 = addr b26 */
        0b000010000000000000000000000000,  /*  row_b7 = addr b25 */
        0b000001000000000000000000000000,  /*  row_b6 = addr b24 */
        0b000000100000000000000000000000,  /*  row_b5 = addr b23 */
        0b000000010000000000000000000000,  /*  row_b4 = addr b22 */
        0b000000001000000000000000000000,  /*  row_b3 = addr b21 */
        0b000000001100000000000000000000,  /*  row_b2 = addr b21 b20 */
        0b000000001010000000000000000000,  /*  row_b1 = addr b21 b19 */
        0b000000000001000000000000000000,  /*  row_b0 = addr b18 */
        0b000000000000000001000000000000,  /*  col_b12 = addr b12 */
        0b000000000000000000100000000000,  /*  col_b11 = addr b11 */
        0b000000000000000000010000000000,  /*  col_b10 = addr b10 */
        0b000000000000000000001000000000,  /*  col_b9 = addr b9 */
        0b000000000000000000000100000000,  /*  col_b8 = addr b8 */
        0b000000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b000000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b000000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b000000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b000000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b000000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b000000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b000000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000001000000000000000000000000,  /*  addr b29 = row_b11 */
        0b000000100000000000000000000000,  /*  addr b28 = row_b10 */
        0b000000010000000000000000000000,  /*  addr b27 = row_b9 */
        0b000000001000000000000000000000,  /*  addr b26 = row_b8 */
        0b000000000100000000000000000000,  /*  addr b25 = row_b7 */
        0b000000000010000000000000000000,  /*  addr b24 = row_b6 */
        0b000000000001000000000000000000,  /*  addr b23 = row_b5 */
        0b000000000000100000000000000000,  /*  addr b22 = row_b4 */
        0b000000000000010000000000000000,  /*  addr b21 = row_b3 */
        0b000000000000011000000000000000,  /*  addr b20 = row_b3 row_b2 */
        0b000000000000010100000000000000,  /*  addr b19 = row_b3 row_b1 */
        0b000000000000000010000000000000,  /*  addr b18 = row_b0 */
        0b100001111111111110000000000000,  /*  addr b17 = rank_b0 row_b11 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3 row_b2 row_b1 row_b0 */
        0b000100010001010100000000000000,  /*  addr b16 = bk_b1 row_b9 row_b5 row_b3 row_b1 */
        0b001000001000100010000000000000,  /*  addr b15 = bg_b0 row_b8 row_b4 row_b0 */
        0b010001000100010000000000000000,  /*  addr b14 = bg_b1 row_b11 row_b7 row_b3 */
        0b000010100010011001111111000000,  /*  addr b13 = bk_b0 row_b10 row_b6 row_b3 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6 */
        0b000000000000000001000000000000,  /*  addr b12 = col_b12 */
        0b000000000000000000100000000000,  /*  addr b11 = col_b11 */
        0b000000000000000000010000000000,  /*  addr b10 = col_b10 */
        0b000000000000000000001000000000,  /*  addr b9 = col_b9 */
        0b000000000000000000000100000000,  /*  addr b8 = col_b8 */
        0b000000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b000000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b000000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b000000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b000000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b000000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b000000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b000000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    }
    else {
      selected_config->dram_matrix = {
        0b111111111111100000000000000000,  /*  rank_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 */
        0b100010001000000100000000000000,  /*  bg_b1 = addr b29 b25 b21 b14 */
        0b000100010001001000000000000000,  /*  bg_b0 = addr b26 b22 b18 b15 */
        0b001000100010010000000000000000,  /*  bk_b1 = addr b27 b23 b19 b16 */
        0b010001000100000011111111000000,  /*  bk_b0 = addr b28 b24 b20 b13 b12 b11 b10 b9 b8 b7 b6 */
        0b100000000000000000000000000000,  /*  row_b11 = addr b29 */
        0b010000000000000000000000000000,  /*  row_b10 = addr b28 */
        0b001000000000000000000000000000,  /*  row_b9 = addr b27 */
        0b000100000000000000000000000000,  /*  row_b8 = addr b26 */
        0b000010000000000000000000000000,  /*  row_b7 = addr b25 */
        0b000001000000000000000000000000,  /*  row_b6 = addr b24 */
        0b000000100000000000000000000000,  /*  row_b5 = addr b23 */
        0b000000010000000000000000000000,  /*  row_b4 = addr b22 */
        0b000000001000000000000000000000,  /*  row_b3 = addr b21 */
        0b000000000100000000000000000000,  /*  row_b2 = addr b20 */
        0b000000000010000000000000000000,  /*  row_b1 = addr b19 */
        0b000000000001000000000000000000,  /*  row_b0 = addr b18 */
        0b000000000000000001000000000000,  /*  col_b12 = addr b12 */
        0b000000000000000000100000000000,  /*  col_b11 = addr b11 */
        0b000000000000000000010000000000,  /*  col_b10 = addr b10 */
        0b000000000000000000001000000000,  /*  col_b9 = addr b9 */
        0b000000000000000000000100000000,  /*  col_b8 = addr b8 */
        0b000000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b000000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b000000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b000000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b000000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b000000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b000000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b000000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000001000000000000000000000000,  /*  addr b29 = row_b11 */
        0b000000100000000000000000000000,  /*  addr b28 = row_b10 */
        0b000000010000000000000000000000,  /*  addr b27 = row_b9 */
        0b000000001000000000000000000000,  /*  addr b26 = row_b8 */
        0b000000000100000000000000000000,  /*  addr b25 = row_b7 */
        0b000000000010000000000000000000,  /*  addr b24 = row_b6 */
        0b000000000001000000000000000000,  /*  addr b23 = row_b5 */
        0b000000000000100000000000000000,  /*  addr b22 = row_b4 */
        0b000000000000010000000000000000,  /*  addr b21 = row_b3 */
        0b000000000000001000000000000000,  /*  addr b20 = row_b2 */
        0b000000000000000100000000000000,  /*  addr b19 = row_b1 */
        0b000000000000000010000000000000,  /*  addr b18 = row_b0 */
        0b100001111111111110000000000000,  /*  addr b17 = rank_b0 row_b11 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3 row_b2 row_b1 row_b0 */
        0b000100010001000100000000000000,  /*  addr b16 = bk_b1 row_b9 row_b5 row_b1 */
        0b001000001000100010000000000000,  /*  addr b15 = bg_b0 row_b8 row_b4 row_b0 */
        0b010001000100010000000000000000,  /*  addr b14 = bg_b1 row_b11 row_b7 row_b3 */
        0b000010100010001001111111000000,  /*  addr b13 = bk_b0 row_b10 row_b6 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6 */
        0b000000000000000001000000000000,  /*  addr b12 = col_b12 */
        0b000000000000000000100000000000,  /*  addr b11 = col_b11 */
        0b000000000000000000010000000000,  /*  addr b10 = col_b10 */
        0b000000000000000000001000000000,  /*  addr b9 = col_b9 */
        0b000000000000000000000100000000,  /*  addr b8 = col_b8 */
        0b000000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b000000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b000000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b000000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b000000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b000000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b000000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b000000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_1_PLUS && ranks == 1 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x40000000;  /* 1 GB */
    // 4 bank bits (consisting of bank group, bank)
    selected_config->bank_shift = 26;
    selected_config->bank_mask = 0b1111;
    // 13 row bits (inside 1 GB)
    selected_config->row_shift = 13;
    selected_config->row_mask = 0b1111111111111;
    // 13 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b1111111111111;

    // 30 bits (1 GB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b100010001000101000000000000000,  /*  bg_b1 = addr b29 b25 b21 b17 b15 */
        0b000100010001010000000000000000,  /*  bg_b0 = addr b26 b22 b18 b16 */
        0b001000100010000011111111000000,  /*  bk_b1 = addr b27 b23 b19 b13 b12 b11 b10 b9 b8 b7 b6 */
        0b010001000100000100000000000000,  /*  bk_b0 = addr b28 b24 b20 b14 */
        0b100000000000000000000000000000,  /*  row_b12 = addr b29 */
        0b010000000000000000000000000000,  /*  row_b11 = addr b28 */
        0b001000000000000000000000000000,  /*  row_b10 = addr b27 */
        0b000100000000000000000000000000,  /*  row_b9 = addr b26 */
        0b000010000000000000000000000000,  /*  row_b8 = addr b25 */
        0b000001000000000000000000000000,  /*  row_b7 = addr b24 */
        0b000000100000000000000000000000,  /*  row_b6 = addr b23 */
        0b000000010000000000000000000000,  /*  row_b5 = addr b22 */
        0b000000001000000000000000000000,  /*  row_b4 = addr b21 */
        0b000000000100000000000000000000,  /*  row_b3 = addr b20 */
        0b000000000110000000000000000000,  /*  row_b2 = addr b20 b19 */
        0b000000000101000000000000000000,  /*  row_b1 = addr b20 b18 */
        0b000000000000100000000000000000,  /*  row_b0 = addr b17 */
        0b000000000000000001000000000000,  /*  col_b12 = addr b12 */
        0b000000000000000000100000000000,  /*  col_b11 = addr b11 */
        0b000000000000000000010000000000,  /*  col_b10 = addr b10 */
        0b000000000000000000001000000000,  /*  col_b9 = addr b9 */
        0b000000000000000000000100000000,  /*  col_b8 = addr b8 */
        0b000000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b000000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b000000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b000000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b000000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b000000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b000000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b000000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000010000000000000000000000000,  /*  addr b29 = row_b12 */
        0b000001000000000000000000000000,  /*  addr b28 = row_b11 */
        0b000000100000000000000000000000,  /*  addr b27 = row_b10 */
        0b000000010000000000000000000000,  /*  addr b26 = row_b9 */
        0b000000001000000000000000000000,  /*  addr b25 = row_b8 */
        0b000000000100000000000000000000,  /*  addr b24 = row_b7 */
        0b000000000010000000000000000000,  /*  addr b23 = row_b6 */
        0b000000000001000000000000000000,  /*  addr b22 = row_b5 */
        0b000000000000100000000000000000,  /*  addr b21 = row_b4 */
        0b000000000000010000000000000000,  /*  addr b20 = row_b3 */
        0b000000000000011000000000000000,  /*  addr b19 = row_b3 row_b2 */
        0b000000000000010100000000000000,  /*  addr b18 = row_b3 row_b1 */
        0b000000000000000010000000000000,  /*  addr b17 = row_b0 */
        0b010000010001010100000000000000,  /*  addr b16 = bg_b0 row_b9 row_b5 row_b3 row_b1 */
        0b100010001000100010000000000000,  /*  addr b15 = bg_b1 row_b12 row_b8 row_b4 row_b0 */
        0b000101000100010000000000000000,  /*  addr b14 = bk_b0 row_b11 row_b7 row_b3 */
        0b001000100010011001111111000000,  /*  addr b13 = bk_b1 row_b10 row_b6 row_b3 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6 */
        0b000000000000000001000000000000,  /*  addr b12 = col_b12 */
        0b000000000000000000100000000000,  /*  addr b11 = col_b11 */
        0b000000000000000000010000000000,  /*  addr b10 = col_b10 */
        0b000000000000000000001000000000,  /*  addr b9 = col_b9 */
        0b000000000000000000000100000000,  /*  addr b8 = col_b8 */
        0b000000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b000000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b000000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b000000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b000000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b000000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b000000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b000000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    } else {
      selected_config->dram_matrix = {
        0b100010001000101000000000000000,  /*  bg_b1 = addr b29 b25 b21 b17 b15 */
        0b000100010001010000000000000000,  /*  bg_b0 = addr b26 b22 b18 b16 */
        0b001000100010000011111111000000,  /*  bk_b1 = addr b27 b23 b19 b13 b12 b11 b10 b9 b8 b7 b6 */
        0b010001000100000100000000000000,  /*  bk_b0 = addr b28 b24 b20 b14 */
        0b100000000000000000000000000000,  /*  row_b12 = addr b29 */
        0b010000000000000000000000000000,  /*  row_b11 = addr b28 */
        0b001000000000000000000000000000,  /*  row_b10 = addr b27 */
        0b000100000000000000000000000000,  /*  row_b9 = addr b26 */
        0b000010000000000000000000000000,  /*  row_b8 = addr b25 */
        0b000001000000000000000000000000,  /*  row_b7 = addr b24 */
        0b000000100000000000000000000000,  /*  row_b6 = addr b23 */
        0b000000010000000000000000000000,  /*  row_b5 = addr b22 */
        0b000000001000000000000000000000,  /*  row_b4 = addr b21 */
        0b000000000100000000000000000000,  /*  row_b3 = addr b20 */
        0b000000000010000000000000000000,  /*  row_b2 = addr b19 */
        0b000000000001000000000000000000,  /*  row_b1 = addr b18 */
        0b000000000000100000000000000000,  /*  row_b0 = addr b17 */
        0b000000000000000001000000000000,  /*  col_b12 = addr b12 */
        0b000000000000000000100000000000,  /*  col_b11 = addr b11 */
        0b000000000000000000010000000000,  /*  col_b10 = addr b10 */
        0b000000000000000000001000000000,  /*  col_b9 = addr b9 */
        0b000000000000000000000100000000,  /*  col_b8 = addr b8 */
        0b000000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b000000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b000000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b000000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b000000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b000000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b000000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b000000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000010000000000000000000000000,  /*  addr b29 = row_b12 */
        0b000001000000000000000000000000,  /*  addr b28 = row_b11 */
        0b000000100000000000000000000000,  /*  addr b27 = row_b10 */
        0b000000010000000000000000000000,  /*  addr b26 = row_b9 */
        0b000000001000000000000000000000,  /*  addr b25 = row_b8 */
        0b000000000100000000000000000000,  /*  addr b24 = row_b7 */
        0b000000000010000000000000000000,  /*  addr b23 = row_b6 */
        0b000000000001000000000000000000,  /*  addr b22 = row_b5 */
        0b000000000000100000000000000000,  /*  addr b21 = row_b4 */
        0b000000000000010000000000000000,  /*  addr b20 = row_b3 */
        0b000000000000001000000000000000,  /*  addr b19 = row_b2 */
        0b000000000000000100000000000000,  /*  addr b18 = row_b1 */
        0b000000000000000010000000000000,  /*  addr b17 = row_b0 */
        0b010000010001000100000000000000,  /*  addr b16 = bg_b0 row_b9 row_b5 row_b1 */
        0b100010001000100010000000000000,  /*  addr b15 = bg_b1 row_b12 row_b8 row_b4 row_b0 */
        0b000101000100010000000000000000,  /*  addr b14 = bk_b0 row_b11 row_b7 row_b3 */
        0b001000100010001001111111000000,  /*  addr b13 = bk_b1 row_b10 row_b6 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6 */
        0b000000000000000001000000000000,  /*  addr b12 = col_b12 */
        0b000000000000000000100000000000,  /*  addr b11 = col_b11 */
        0b000000000000000000010000000000,  /*  addr b10 = col_b10 */
        0b000000000000000000001000000000,  /*  addr b9 = col_b9 */
        0b000000000000000000000100000000,  /*  addr b8 = col_b8 */
        0b000000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b000000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b000000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b000000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b000000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b000000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b000000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b000000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_2 && ranks == 2 && bank_groups == 4 && banks == 4) {
    // NOTE: The number of row_bits (16 or 17) only affects bits above what is covered by the matrices, meaning the
    //       DRAMConfig is identical.
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x20000000;  /* 512 MB */
    // 5 bank bits (consisting of rank, bank group, bank)
    selected_config->bank_shift = 24;
    selected_config->bank_mask = 0b11111;
    // 12 row bits (inside 1 GB)
    selected_config->row_shift = 13;
    selected_config->row_mask = 0b11111111111;
    // 13 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b1111111111111;

    // 29 bits (512 MB)
    selected_config->matrix_size = 29;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b11111111111100000000000000000,  // rk_b0 = addr b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17
        0b00100010001001000000000000000,  // bg_b1 = addr b26 b22 b18 b15
        0b00010001000000100000000000000,  // bg_b0 = addr b25 b21 b14
        0b10001000100000011111111000000,  // ba_b1 = addr b28 b24 b20 b13 b12 b11 b10 b9 b8 b7 b6
        0b01000100010010000000000000000,  // ba_b0 = addr b27 b23 b19 b16
        0b10000000000000000000000000000,  // row_b10 = addr b28
        0b01000000000000000000000000000,  // row_b9 = addr b27
        0b00100000000000000000000000000,  // row_b8 = addr b26
        0b00010000000000000000000000000,  // row_b7 = addr b25
        0b00001000000000000000000000000,  // row_b6 = addr b24
        0b00000100000000000000000000000,  // row_b5 = addr b23
        0b00000010000000000000000000000,  // row_b4 = addr b22
        0b00000001000000000000000000000,  // row_b3 = addr b21
        0b00000001100000000000000000000,  // row_b2 = addr b21 b20
        0b00000001010000000000000000000,  // row_b1 = addr b21 b19
        0b00000000001000000000000000000,  // row_b0 = addr b18
        0b00000000000000001000000000000,  // col_b12 = addr b12
        0b00000000000000000100000000000,  // col_b11 = addr b11
        0b00000000000000000010000000000,  // col_b10 = addr b10
        0b00000000000000000001000000000,  // col_b9 = addr b9
        0b00000000000000000000100000000,  // col_b8 = addr b8
        0b00000000000000000000010000000,  // col_b7 = addr b7
        0b00000000000000000000001000000,  // col_b6 = addr b6
        0b00000000000000000000000100000,  // col_b5 = addr b5
        0b00000000000000000000000010000,  // col_b4 = addr b4
        0b00000000000000000000000001000,  // col_b3 = addr b3
        0b00000000000000000000000000100,  // col_b2 = addr b2
        0b00000000000000000000000000010,  // col_b1 = addr b1
        0b00000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b00000100000000000000000000000,  // addr b28 = row_b10
        0b00000010000000000000000000000,  // addr b27 = row_b9
        0b00000001000000000000000000000,  // addr b26 = row_b8
        0b00000000100000000000000000000,  // addr b25 = row_b7
        0b00000000010000000000000000000,  // addr b24 = row_b6
        0b00000000001000000000000000000,  // addr b23 = row_b5
        0b00000000000100000000000000000,  // addr b22 = row_b4
        0b00000000000010000000000000000,  // addr b21 = row_b3
        0b00000000000011000000000000000,  // addr b20 = row_b3 row_b2
        0b00000000000010100000000000000,  // addr b19 = row_b3 row_b1
        0b00000000000000010000000000000,  // addr b18 = row_b0
        0b10000111111111110000000000000,  // addr b17 = rk_b0 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3 row_b2 row_b1 row_b0
        0b00001010001010100000000000000,  // addr b16 = ba_b0 row_b9 row_b5 row_b3 row_b1
        0b01000001000100010000000000000,  // addr b15 = bg_b1 row_b8 row_b4 row_b0
        0b00100000100010000000000000000,  // addr b14 = bg_b0 row_b7 row_b3
        0b00010100010011001111111000000,  // addr b13 = ba_b1 row_b10 row_b6 row_b3 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6
        0b00000000000000001000000000000,  // addr b12 = col_b12
        0b00000000000000000100000000000,  // addr b11 = col_b11
        0b00000000000000000010000000000,  // addr b10 = col_b10
        0b00000000000000000001000000000,  // addr b9 = col_b9
        0b00000000000000000000100000000,  // addr b8 = col_b8
        0b00000000000000000000010000000,  // addr b7 = col_b7
        0b00000000000000000000001000000,  // addr b6 = col_b6
        0b00000000000000000000000100000,  // addr b5 = col_b5
        0b00000000000000000000000010000,  // addr b4 = col_b4
        0b00000000000000000000000001000,  // addr b3 = col_b3
        0b00000000000000000000000000100,  // addr b2 = col_b2
        0b00000000000000000000000000010,  // addr b1 = col_b1
        0b00000000000000000000000000001,  // addr b0 = col_b0
      };
    } else {
      selected_config->dram_matrix = {
        0b11111111111100000000000000000,  // rk_b0 = addr b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17
        0b00100010001001000000000000000,  // bg_b1 = addr b26 b22 b18 b15
        0b00010001000000100000000000000,  // bg_b0 = addr b25 b21 b14
        0b10001000100000011111111000000,  // ba_b1 = addr b28 b24 b20 b13 b12 b11 b10 b9 b8 b7 b6
        0b01000100010010000000000000000,  // ba_b0 = addr b27 b23 b19 b16
        0b10000000000000000000000000000,  // row_b10 = addr b28
        0b01000000000000000000000000000,  // row_b9 = addr b27
        0b00100000000000000000000000000,  // row_b8 = addr b26
        0b00010000000000000000000000000,  // row_b7 = addr b25
        0b00001000000000000000000000000,  // row_b6 = addr b24
        0b00000100000000000000000000000,  // row_b5 = addr b23
        0b00000010000000000000000000000,  // row_b4 = addr b22
        0b00000001000000000000000000000,  // row_b3 = addr b21
        0b00000000100000000000000000000,  // row_b2 = addr b20
        0b00000000010000000000000000000,  // row_b1 = addr b19
        0b00000000001000000000000000000,  // row_b0 = addr b18
        0b00000000000000001000000000000,  // col_b12 = addr b12
        0b00000000000000000100000000000,  // col_b11 = addr b11
        0b00000000000000000010000000000,  // col_b10 = addr b10
        0b00000000000000000001000000000,  // col_b9 = addr b9
        0b00000000000000000000100000000,  // col_b8 = addr b8
        0b00000000000000000000010000000,  // col_b7 = addr b7
        0b00000000000000000000001000000,  // col_b6 = addr b6
        0b00000000000000000000000100000,  // col_b5 = addr b5
        0b00000000000000000000000010000,  // col_b4 = addr b4
        0b00000000000000000000000001000,  // col_b3 = addr b3
        0b00000000000000000000000000100,  // col_b2 = addr b2
        0b00000000000000000000000000010,  // col_b1 = addr b1
        0b00000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b00000100000000000000000000000,  // addr b28 = row_b10
        0b00000010000000000000000000000,  // addr b27 = row_b9
        0b00000001000000000000000000000,  // addr b26 = row_b8
        0b00000000100000000000000000000,  // addr b25 = row_b7
        0b00000000010000000000000000000,  // addr b24 = row_b6
        0b00000000001000000000000000000,  // addr b23 = row_b5
        0b00000000000100000000000000000,  // addr b22 = row_b4
        0b00000000000010000000000000000,  // addr b21 = row_b3
        0b00000000000001000000000000000,  // addr b20 = row_b2
        0b00000000000000100000000000000,  // addr b19 = row_b1
        0b00000000000000010000000000000,  // addr b18 = row_b0
        0b10000111111111110000000000000,  // addr b17 = rk_b0 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3 row_b2 row_b1 row_b0
        0b00001010001000100000000000000,  // addr b16 = ba_b0 row_b9 row_b5 row_b1
        0b01000001000100010000000000000,  // addr b15 = bg_b1 row_b8 row_b4 row_b0
        0b00100000100010000000000000000,  // addr b14 = bg_b0 row_b7 row_b3
        0b00010100010001001111111000000,  // addr b13 = ba_b1 row_b10 row_b6 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6
        0b00000000000000001000000000000,  // addr b12 = col_b12
        0b00000000000000000100000000000,  // addr b11 = col_b11
        0b00000000000000000010000000000,  // addr b10 = col_b10
        0b00000000000000000001000000000,  // addr b9 = col_b9
        0b00000000000000000000100000000,  // addr b8 = col_b8
        0b00000000000000000000010000000,  // addr b7 = col_b7
        0b00000000000000000000001000000,  // addr b6 = col_b6
        0b00000000000000000000000100000,  // addr b5 = col_b5
        0b00000000000000000000000010000,  // addr b4 = col_b4
        0b00000000000000000000000001000,  // addr b3 = col_b3
        0b00000000000000000000000000100,  // addr b2 = col_b2
        0b00000000000000000000000000010,  // addr b1 = col_b1
        0b00000000000000000000000000001,  // addr b0 = col_b0
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_2 && ranks == 1 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x20000000;  /* 512 MB */
    // 4 bank bits (consisting of bank group, bank)
    selected_config->bank_shift = 25;
    selected_config->bank_mask = 0b1111;
    // 13 row bits (inside 1 GB)
    selected_config->row_shift = 13;
    selected_config->row_mask = 0b111111111111;
    // 13 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b1111111111111;

    // 29 bits (512 MB)
    selected_config->matrix_size = 29;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b00100010001010000000000000000,  // bg_b1 = addr b26 b22 b18 b16
        0b00010001000101000000000000000,  // bg_b0 = addr b25 b21 b17 b15
        0b10001000100000100000000000000,  // ba_b1 = addr b28 b24 b20 b14
        0b01000100010000011111111000000,  // ba_b0 = addr b27 b23 b19 b13 b12 b11 b10 b9 b8 b7 b6
        0b10000000000000000000000000000,  // row_b11 = addr b28
        0b01000000000000000000000000000,  // row_b10 = addr b27
        0b00100000000000000000000000000,  // row_b9 = addr b26
        0b00010000000000000000000000000,  // row_b8 = addr b25
        0b00001000000000000000000000000,  // row_b7 = addr b24
        0b00000100000000000000000000000,  // row_b6 = addr b23
        0b00000010000000000000000000000,  // row_b5 = addr b22
        0b00000001000000000000000000000,  // row_b4 = addr b21
        0b00000000100000000000000000000,  // row_b3 = addr b20
        0b00000000110000000000000000000,  // row_b2 = addr b20 b19
        0b00000000101000000000000000000,  // row_b1 = addr b20 b18
        0b00000000000100000000000000000,  // row_b0 = addr b17
        0b00000000000000001000000000000,  // col_b12 = addr b12
        0b00000000000000000100000000000,  // col_b11 = addr b11
        0b00000000000000000010000000000,  // col_b10 = addr b10
        0b00000000000000000001000000000,  // col_b9 = addr b9
        0b00000000000000000000100000000,  // col_b8 = addr b8
        0b00000000000000000000010000000,  // col_b7 = addr b7
        0b00000000000000000000001000000,  // col_b6 = addr b6
        0b00000000000000000000000100000,  // col_b5 = addr b5
        0b00000000000000000000000010000,  // col_b4 = addr b4
        0b00000000000000000000000001000,  // col_b3 = addr b3
        0b00000000000000000000000000100,  // col_b2 = addr b2
        0b00000000000000000000000000010,  // col_b1 = addr b1
        0b00000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b00001000000000000000000000000,  // addr b28 = row_b11
        0b00000100000000000000000000000,  // addr b27 = row_b10
        0b00000010000000000000000000000,  // addr b26 = row_b9
        0b00000001000000000000000000000,  // addr b25 = row_b8
        0b00000000100000000000000000000,  // addr b24 = row_b7
        0b00000000010000000000000000000,  // addr b23 = row_b6
        0b00000000001000000000000000000,  // addr b22 = row_b5
        0b00000000000100000000000000000,  // addr b21 = row_b4
        0b00000000000010000000000000000,  // addr b20 = row_b3
        0b00000000000011000000000000000,  // addr b19 = row_b3 row_b2
        0b00000000000010100000000000000,  // addr b18 = row_b3 row_b1
        0b00000000000000010000000000000,  // addr b17 = row_b0
        0b10000010001010100000000000000,  // addr b16 = bg_b1 row_b9 row_b5 row_b3 row_b1
        0b01000001000100010000000000000,  // addr b15 = bg_b0 row_b8 row_b4 row_b0
        0b00101000100010000000000000000,  // addr b14 = ba_b1 row_b11 row_b7 row_b3
        0b00010100010011001111111000000,  // addr b13 = ba_b0 row_b10 row_b6 row_b3 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6
        0b00000000000000001000000000000,  // addr b12 = col_b12
        0b00000000000000000100000000000,  // addr b11 = col_b11
        0b00000000000000000010000000000,  // addr b10 = col_b10
        0b00000000000000000001000000000,  // addr b9 = col_b9
        0b00000000000000000000100000000,  // addr b8 = col_b8
        0b00000000000000000000010000000,  // addr b7 = col_b7
        0b00000000000000000000001000000,  // addr b6 = col_b6
        0b00000000000000000000000100000,  // addr b5 = col_b5
        0b00000000000000000000000010000,  // addr b4 = col_b4
        0b00000000000000000000000001000,  // addr b3 = col_b3
        0b00000000000000000000000000100,  // addr b2 = col_b2
        0b00000000000000000000000000010,  // addr b1 = col_b1
        0b00000000000000000000000000001,  // addr b0 = col_b0
      };
    } else {
      selected_config->dram_matrix = {
        0b00100010001010000000000000000,  // bg_b1 = addr b26 b22 b18 b16
        0b00010001000101000000000000000,  // bg_b0 = addr b25 b21 b17 b15
        0b10001000100000100000000000000,  // ba_b1 = addr b28 b24 b20 b14
        0b01000100010000011111111000000,  // ba_b0 = addr b27 b23 b19 b13 b12 b11 b10 b9 b8 b7 b6
        0b10000000000000000000000000000,  // row_b11 = addr b28
        0b01000000000000000000000000000,  // row_b10 = addr b27
        0b00100000000000000000000000000,  // row_b9 = addr b26
        0b00010000000000000000000000000,  // row_b8 = addr b25
        0b00001000000000000000000000000,  // row_b7 = addr b24
        0b00000100000000000000000000000,  // row_b6 = addr b23
        0b00000010000000000000000000000,  // row_b5 = addr b22
        0b00000001000000000000000000000,  // row_b4 = addr b21
        0b00000000100000000000000000000,  // row_b3 = addr b20
        0b00000000010000000000000000000,  // row_b2 = addr b19
        0b00000000001000000000000000000,  // row_b1 = addr b18
        0b00000000000100000000000000000,  // row_b0 = addr b17
        0b00000000000000001000000000000,  // col_b12 = addr b12
        0b00000000000000000100000000000,  // col_b11 = addr b11
        0b00000000000000000010000000000,  // col_b10 = addr b10
        0b00000000000000000001000000000,  // col_b9 = addr b9
        0b00000000000000000000100000000,  // col_b8 = addr b8
        0b00000000000000000000010000000,  // col_b7 = addr b7
        0b00000000000000000000001000000,  // col_b6 = addr b6
        0b00000000000000000000000100000,  // col_b5 = addr b5
        0b00000000000000000000000010000,  // col_b4 = addr b4
        0b00000000000000000000000001000,  // col_b3 = addr b3
        0b00000000000000000000000000100,  // col_b2 = addr b2
        0b00000000000000000000000000010,  // col_b1 = addr b1
        0b00000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b00001000000000000000000000000,  // addr b28 = row_b11
        0b00000100000000000000000000000,  // addr b27 = row_b10
        0b00000010000000000000000000000,  // addr b26 = row_b9
        0b00000001000000000000000000000,  // addr b25 = row_b8
        0b00000000100000000000000000000,  // addr b24 = row_b7
        0b00000000010000000000000000000,  // addr b23 = row_b6
        0b00000000001000000000000000000,  // addr b22 = row_b5
        0b00000000000100000000000000000,  // addr b21 = row_b4
        0b00000000000010000000000000000,  // addr b20 = row_b3
        0b00000000000001000000000000000,  // addr b19 = row_b2
        0b00000000000000100000000000000,  // addr b18 = row_b1
        0b00000000000000010000000000000,  // addr b17 = row_b0
        0b10000010001000100000000000000,  // addr b16 = bg_b1 row_b9 row_b5 row_b1
        0b01000001000100010000000000000,  // addr b15 = bg_b0 row_b8 row_b4 row_b0
        0b00101000100010000000000000000,  // addr b14 = ba_b1 row_b11 row_b7 row_b3
        0b00010100010001001111111000000,  // addr b13 = ba_b0 row_b10 row_b6 row_b2 col_b12 col_b11 col_b10 col_b9 col_b8 col_b7 col_b6
        0b00000000000000001000000000000,  // addr b12 = col_b12
        0b00000000000000000100000000000,  // addr b11 = col_b11
        0b00000000000000000010000000000,  // addr b10 = col_b10
        0b00000000000000000001000000000,  // addr b9 = col_b9
        0b00000000000000000000100000000,  // addr b8 = col_b8
        0b00000000000000000000010000000,  // addr b7 = col_b7
        0b00000000000000000000001000000,  // addr b6 = col_b6
        0b00000000000000000000000100000,  // addr b5 = col_b5
        0b00000000000000000000000010000,  // addr b4 = col_b4
        0b00000000000000000000000001000,  // addr b3 = col_b3
        0b00000000000000000000000000100,  // addr b2 = col_b2
        0b00000000000000000000000000010,  // addr b1 = col_b1
        0b00000000000000000000000000001,  // addr b0 = col_b0
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_3 && ranks == 2 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x30000000;  /* 768 MB */
    // 5 bank bits (consisting of rank, bank group, bank)
    selected_config->bank_shift = 23;
    selected_config->bank_mask = 0b11111;
    // 10 row bits (inside 256 MB)
    selected_config->row_shift = 13;
    selected_config->row_mask = 0b1111111111;
    // 13 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b1111111111111;

    // 28 bits (256 MB)
    selected_config->matrix_size = 28;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b1111111111100000000000000000,  /*  rank_b0 = addr b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 */
        0b0100010001000000000100000000,  /*  bg_b1 = addr b26 b22 b18 b8 */
        0b1000100010000000001000000000,  /*  bg_b0 = addr b27 b23 b19 b9 */
        0b0001000100000000010000000000,  /*  bk_b1 = addr b24 b20 b10 */
        0b0010001000000000100000000000,  /*  bk_b0 = addr b25 b21 b11 */
        0b1000000000000000000000000000,  /*  row_b9 = addr b27 */
        0b0100000000000000000000000000,  /*  row_b8 = addr b26 */
        0b0010000000000000000000000000,  /*  row_b7 = addr b25 */
        0b0001000000000000000000000000,  /*  row_b6 = addr b24 */
        0b0000100000000000000000000000,  /*  row_b5 = addr b23 */
        0b0000010000000000000000000000,  /*  row_b4 = addr b22 */
        0b0000001000000000000000000000,  /*  row_b3 = addr b21 */
        0b0000001100000000000000000000,  /*  row_b2 = addr b21 b20 */
        0b0000001010000000000000000000,  /*  row_b1 = addr b21 b19 */
        0b0000000001000000000000000000,  /*  row_b0 = addr b18 */
        0b0000000000010000000000000000,  /*  col_b12 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b11 = addr b15 */
        0b0000000000000100000000000000,  /*  col_b10 = addr b14 */
        0b0000000000000010000000000000,  /*  col_b9 = addr b13 */
        0b0000000000000001000000000000,  /*  col_b8 = addr b12 */
        0b0000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b0000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b0000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b0000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b0000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b0000010000000000000000000000,  /*  addr b27 = row_b9 */
        0b0000001000000000000000000000,  /*  addr b26 = row_b8 */
        0b0000000100000000000000000000,  /*  addr b25 = row_b7 */
        0b0000000010000000000000000000,  /*  addr b24 = row_b6 */
        0b0000000001000000000000000000,  /*  addr b23 = row_b5 */
        0b0000000000100000000000000000,  /*  addr b22 = row_b4 */
        0b0000000000010000000000000000,  /*  addr b21 = row_b3 */
        0b0000000000011000000000000000,  /*  addr b20 = row_b3 row_b2 */
        0b0000000000010100000000000000,  /*  addr b19 = row_b3 row_b1 */
        0b0000000000000010000000000000,  /*  addr b18 = row_b0 */
        0b1000011111111110000000000000,  /*  addr b17 = rank_b0 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3 row_b2 row_b1 row_b0 */
        0b0000000000000001000000000000,  /*  addr b16 = col_b12 */
        0b0000000000000000100000000000,  /*  addr b15 = col_b11 */
        0b0000000000000000010000000000,  /*  addr b14 = col_b10 */
        0b0000000000000000001000000000,  /*  addr b13 = col_b9 */
        0b0000000000000000000100000000,  /*  addr b12 = col_b8 */
        0b0000100100010000000000000000,  /*  addr b11 = bk_b0 row_b7 row_b3 */
        0b0001000010011000000000000000,  /*  addr b10 = bk_b1 row_b6 row_b3 row_b2 */
        0b0010010001010100000000000000,  /*  addr b9 = bg_b0 row_b9 row_b5 row_b3 row_b1 */
        0b0100001000100010000000000000,  /*  addr b8 = bg_b1 row_b8 row_b4 row_b0 */
        0b0000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b0000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b0000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b0000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b0000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b0000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b0000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b0000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    } else {
      selected_config->dram_matrix = {
        0b1111111111100000000000000000,  /*  rank_b0 = addr b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 */
        0b0100010001000000000100000000,  /*  bg_b1 = addr b26 b22 b18 b8 */
        0b1000100010000000001000000000,  /*  bg_b0 = addr b27 b23 b19 b9 */
        0b0001000100000000010000000000,  /*  bk_b1 = addr b24 b20 b10 */
        0b0010001000000000100000000000,  /*  bk_b0 = addr b25 b21 b11 */
        0b1000000000000000000000000000,  /*  row_b9 = addr b27 */
        0b0100000000000000000000000000,  /*  row_b8 = addr b26 */
        0b0010000000000000000000000000,  /*  row_b7 = addr b25 */
        0b0001000000000000000000000000,  /*  row_b6 = addr b24 */
        0b0000100000000000000000000000,  /*  row_b5 = addr b23 */
        0b0000010000000000000000000000,  /*  row_b4 = addr b22 */
        0b0000001000000000000000000000,  /*  row_b3 = addr b21 */
        0b0000000100000000000000000000,  /*  row_b2 = addr b20 */
        0b0000000010000000000000000000,  /*  row_b1 = addr b19 */
        0b0000000001000000000000000000,  /*  row_b0 = addr b18 */
        0b0000000000010000000000000000,  /*  col_b12 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b11 = addr b15 */
        0b0000000000000100000000000000,  /*  col_b10 = addr b14 */
        0b0000000000000010000000000000,  /*  col_b9 = addr b13 */
        0b0000000000000001000000000000,  /*  col_b8 = addr b12 */
        0b0000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b0000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b0000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b0000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b0000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b0000010000000000000000000000,  /*  addr b27 = row_b9 */
        0b0000001000000000000000000000,  /*  addr b26 = row_b8 */
        0b0000000100000000000000000000,  /*  addr b25 = row_b7 */
        0b0000000010000000000000000000,  /*  addr b24 = row_b6 */
        0b0000000001000000000000000000,  /*  addr b23 = row_b5 */
        0b0000000000100000000000000000,  /*  addr b22 = row_b4 */
        0b0000000000010000000000000000,  /*  addr b21 = row_b3 */
        0b0000000000001000000000000000,  /*  addr b20 = row_b2 */
        0b0000000000000100000000000000,  /*  addr b19 = row_b1 */
        0b0000000000000010000000000000,  /*  addr b18 = row_b0 */
        0b1000011111111110000000000000,  /*  addr b17 = rank_b0 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3 row_b2 row_b1 row_b0 */
        0b0000000000000001000000000000,  /*  addr b16 = col_b12 */
        0b0000000000000000100000000000,  /*  addr b15 = col_b11 */
        0b0000000000000000010000000000,  /*  addr b14 = col_b10 */
        0b0000000000000000001000000000,  /*  addr b13 = col_b9 */
        0b0000000000000000000100000000,  /*  addr b12 = col_b8 */
        0b0000100100010000000000000000,  /*  addr b11 = bk_b0 row_b7 row_b3 */
        0b0001000010001000000000000000,  /*  addr b10 = bk_b1 row_b6 row_b2 */
        0b0010010001000100000000000000,  /*  addr b9 = bg_b0 row_b9 row_b5 row_b1 */
        0b0100001000100010000000000000,  /*  addr b8 = bg_b1 row_b8 row_b4 row_b0 */
        0b0000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b0000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b0000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b0000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b0000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b0000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b0000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b0000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_3 && ranks == 1 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x30000000;  /* 768 MB */
    // 4 bank bits (consisting of bank group, bank)
    selected_config->bank_shift = 24;
    selected_config->bank_mask = 0b1111;
    // 11 row bits (inside 256 MB)
    selected_config->row_shift = 13;
    selected_config->row_mask = 0b11111111111;
    // 13 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b1111111111111;

    // 28 bits (256 MB)
    selected_config->matrix_size = 28;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b0010001000100000000100000000,  /*  bg_b1 = addr b25 b21 b17 b8 */
        0b0100010001000000001000000000,  /*  bg_b0 = addr b26 b22 b18 b9 */
        0b1000100010000000010000000000,  /*  bk_b1 = addr b27 b23 b19 b10 */
        0b0001000100000000100000000000,  /*  bk_b0 = addr b24 b20 b11 */
        0b1000000000000000000000000000,  /*  row_b10 = addr b27 */
        0b0100000000000000000000000000,  /*  row_b9 = addr b26 */
        0b0010000000000000000000000000,  /*  row_b8 = addr b25 */
        0b0001000000000000000000000000,  /*  row_b7 = addr b24 */
        0b0000100000000000000000000000,  /*  row_b6 = addr b23 */
        0b0000010000000000000000000000,  /*  row_b5 = addr b22 */
        0b0000001000000000000000000000,  /*  row_b4 = addr b21 */
        0b0000000100000000000000000000,  /*  row_b3 = addr b20 */
        0b0000000110000000000000000000,  /*  row_b2 = addr b20 b19 */
        0b0000000101000000000000000000,  /*  row_b1 = addr b20 b18 */
        0b0000000000100000000000000000,  /*  row_b0 = addr b17 */
        0b0000000000010000000000000000,  /*  col_b12 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b11 = addr b15 */
        0b0000000000000100000000000000,  /*  col_b10 = addr b14 */
        0b0000000000000010000000000000,  /*  col_b9 = addr b13 */
        0b0000000000000001000000000000,  /*  col_b8 = addr b12 */
        0b0000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b0000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b0000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b0000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b0000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b0000100000000000000000000000,  /*  addr b27 = row_b10 */
        0b0000010000000000000000000000,  /*  addr b26 = row_b9 */
        0b0000001000000000000000000000,  /*  addr b25 = row_b8 */
        0b0000000100000000000000000000,  /*  addr b24 = row_b7 */
        0b0000000010000000000000000000,  /*  addr b23 = row_b6 */
        0b0000000001000000000000000000,  /*  addr b22 = row_b5 */
        0b0000000000100000000000000000,  /*  addr b21 = row_b4 */
        0b0000000000010000000000000000,  /*  addr b20 = row_b3 */
        0b0000000000011000000000000000,  /*  addr b19 = row_b3 row_b2 */
        0b0000000000010100000000000000,  /*  addr b18 = row_b3 row_b1 */
        0b0000000000000010000000000000,  /*  addr b17 = row_b0 */
        0b0000000000000001000000000000,  /*  addr b16 = col_b12 */
        0b0000000000000000100000000000,  /*  addr b15 = col_b11 */
        0b0000000000000000010000000000,  /*  addr b14 = col_b10 */
        0b0000000000000000001000000000,  /*  addr b13 = col_b9 */
        0b0000000000000000000100000000,  /*  addr b12 = col_b8 */
        0b0001000100010000000000000000,  /*  addr b11 = bk_b0 row_b7 row_b3 */
        0b0010100010011000000000000000,  /*  addr b10 = bk_b1 row_b10 row_b6 row_b3 row_b2 */
        0b0100010001010100000000000000,  /*  addr b9 = bg_b0 row_b9 row_b5 row_b3 row_b1 */
        0b1000001000100010000000000000,  /*  addr b8 = bg_b1 row_b8 row_b4 row_b0 */
        0b0000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b0000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b0000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b0000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b0000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b0000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b0000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b0000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    } else {
      selected_config->dram_matrix = {
        0b0010001000100000000100000000,  /*  bg_b1 = addr b25 b21 b17 b8 */
        0b0100010001000000001000000000,  /*  bg_b0 = addr b26 b22 b18 b9 */
        0b1000100010000000010000000000,  /*  bk_b1 = addr b27 b23 b19 b10 */
        0b0001000100000000100000000000,  /*  bk_b0 = addr b24 b20 b11 */
        0b1000000000000000000000000000,  /*  row_b10 = addr b27 */
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
        0b0000000000010000000000000000,  /*  col_b12 = addr b16 */
        0b0000000000001000000000000000,  /*  col_b11 = addr b15 */
        0b0000000000000100000000000000,  /*  col_b10 = addr b14 */
        0b0000000000000010000000000000,  /*  col_b9 = addr b13 */
        0b0000000000000001000000000000,  /*  col_b8 = addr b12 */
        0b0000000000000000000010000000,  /*  col_b7 = addr b7 */
        0b0000000000000000000001000000,  /*  col_b6 = addr b6 */
        0b0000000000000000000000100000,  /*  col_b5 = addr b5 */
        0b0000000000000000000000010000,  /*  col_b4 = addr b4 */
        0b0000000000000000000000001000,  /*  col_b3 = addr b3 */
        0b0000000000000000000000000100,  /*  col_b2 = addr b2 */
        0b0000000000000000000000000010,  /*  col_b1 = addr b1 */
        0b0000000000000000000000000001,  /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b0000100000000000000000000000,  /*  addr b27 = row_b10 */
        0b0000010000000000000000000000,  /*  addr b26 = row_b9 */
        0b0000001000000000000000000000,  /*  addr b25 = row_b8 */
        0b0000000100000000000000000000,  /*  addr b24 = row_b7 */
        0b0000000010000000000000000000,  /*  addr b23 = row_b6 */
        0b0000000001000000000000000000,  /*  addr b22 = row_b5 */
        0b0000000000100000000000000000,  /*  addr b21 = row_b4 */
        0b0000000000010000000000000000,  /*  addr b20 = row_b3 */
        0b0000000000001000000000000000,  /*  addr b19 = row_b2 */
        0b0000000000000100000000000000,  /*  addr b18 = row_b1 */
        0b0000000000000010000000000000,  /*  addr b17 = row_b0 */
        0b0000000000000001000000000000,  /*  addr b16 = col_b12 */
        0b0000000000000000100000000000,  /*  addr b15 = col_b11 */
        0b0000000000000000010000000000,  /*  addr b14 = col_b10 */
        0b0000000000000000001000000000,  /*  addr b13 = col_b9 */
        0b0000000000000000000100000000,  /*  addr b12 = col_b8 */
        0b0001000100010000000000000000,  /*  addr b11 = bk_b0 row_b7 row_b3 */
        0b0010100010001000000000000000,  /*  addr b10 = bk_b1 row_b10 row_b6 row_b2 */
        0b0100010001000100000000000000,  /*  addr b9 = bg_b0 row_b9 row_b5 row_b1 */
        0b1000001000100010000000000000,  /*  addr b8 = bg_b1 row_b8 row_b4 row_b0 */
        0b0000000000000000000010000000,  /*  addr b7 = col_b7 */
        0b0000000000000000000001000000,  /*  addr b6 = col_b6 */
        0b0000000000000000000000100000,  /*  addr b5 = col_b5 */
        0b0000000000000000000000010000,  /*  addr b4 = col_b4 */
        0b0000000000000000000000001000,  /*  addr b3 = col_b3 */
        0b0000000000000000000000000100,  /*  addr b2 = col_b2 */
        0b0000000000000000000000000010,  /*  addr b1 = col_b1 */
        0b0000000000000000000000000001,  /*  addr b0 = col_b0 */
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_4 && ranks == 1 && bank_groups == 8 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x80000000; /* 2048 MB */
    // 5 bank bits (consisting of subchannel, bank group, bank)
    selected_config->bank_shift = 24;
    selected_config->bank_mask = 0b111111;
    // 12 row bits (inside 1024 MB)
    selected_config->row_shift = 12;
    selected_config->row_mask = 0b111111111111;
    // 12 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b111111111111;

    // 30 bits (1024 MB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b111111111111000000000001000000,  // sc_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b6
        0b001000010000000001000000000000,  // bg_b2 = addr b27 b22 b12
        0b000100001000000000001000000000,  // bg_b1 = addr b26 b21 b9
        0b000010000100000000000100000000,  // bg_b0 = addr b25 b20 b8
        0b100001000010000000100000000000,  // ba_b1 = addr b29 b24 b19 b11
        0b010000100001000000010000000000,  // ba_b0 = addr b28 b23 b18 b10
        0b100000000000000000000000000000,  // row_b11 = addr b29
        0b010000000000000000000000000000,  // row_b10 = addr b28
        0b001000000000000000000000000000,  // row_b9 = addr b27
        0b000100000000000000000000000000,  // row_b8 = addr b26
        0b000010000000000000000000000000,  // row_b7 = addr b25
        0b000001000000000000000000000000,  // row_b6 = addr b24
        0b000000100000000000000000000000,  // row_b5 = addr b23
        0b000000010000000000000000000000,  // row_b4 = addr b22
        0b000000001000000000000000000000,  // row_b3 = addr b21
        0b000000001100000000000000000000,  // row_b2 = addr b21 b20
        0b000000001010000000000000000000,  // row_b1 = addr b21 b19
        0b000000000001000000000000000000,  // row_b0 = addr b18
        0b000000000000100000000000000000,  // col_b11 = addr b17
        0b000000000000010000000000000000,  // col_b10 = addr b16
        0b000000000000001000000000000000,  // col_b9 = addr b15
        0b000000000000000100000000000000,  // col_b8 = addr b14
        0b000000000000000010000000000000,  // col_b7 = addr b13
        0b000000000000000000000010000000,  // col_b6 = addr b7
        0b000000000000000000000000100000,  // col_b5 = addr b5
        0b000000000000000000000000010000,  // col_b4 = addr b4
        0b000000000000000000000000001000,  // col_b3 = addr b3
        0b000000000000000000000000000100,  // col_b2 = addr b2
        0b000000000000000000000000000010,  // col_b1 = addr b1
        0b000000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b000000100000000000000000000000,  // addr b29 = row_b11
        0b000000010000000000000000000000,  // addr b28 = row_b10
        0b000000001000000000000000000000,  // addr b27 = row_b9
        0b000000000100000000000000000000,  // addr b26 = row_b8
        0b000000000010000000000000000000,  // addr b25 = row_b7
        0b000000000001000000000000000000,  // addr b24 = row_b6
        0b000000000000100000000000000000,  // addr b23 = row_b5
        0b000000000000010000000000000000,  // addr b22 = row_b4
        0b000000000000001000000000000000,  // addr b21 = row_b3
        0b000000000000001100000000000000,  // addr b20 = row_b3 row_b2
        0b000000000000001010000000000000,  // addr b19 = row_b3 row_b1
        0b000000000000000001000000000000,  // addr b18 = row_b0
        0b000000000000000000100000000000,  // addr b17 = col_b11
        0b000000000000000000010000000000,  // addr b16 = col_b10
        0b000000000000000000001000000000,  // addr b15 = col_b9
        0b000000000000000000000100000000,  // addr b14 = col_b8
        0b000000000000000000000010000000,  // addr b13 = col_b7
        0b010000001000010000000000000000,  // addr b12 = bg_b2 row_b9 row_b4
        0b000010100001001010000000000000,  // addr b11 = ba_b1 row_b11 row_b6 row_b3 row_b1
        0b000001010000100001000000000000,  // addr b10 = ba_b0 row_b10 row_b5 row_b0
        0b001000000100001000000000000000,  // addr b9 = bg_b1 row_b8 row_b3
        0b000100000010001100000000000000,  // addr b8 = bg_b0 row_b7 row_b3 row_b2
        0b000000000000000000000001000000,  // addr b7 = col_b6
        0b100000111111111111000000000000,  // addr b6 = sc_b0 row_b11 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5
                                            // row_b4 row_b3 row_b2 row_b1 row_b0
        0b000000000000000000000000100000,  // addr b5 = col_b5
        0b000000000000000000000000010000,  // addr b4 = col_b4
        0b000000000000000000000000001000,  // addr b3 = col_b3
        0b000000000000000000000000000100,  // addr b2 = col_b2
        0b000000000000000000000000000010,  // addr b1 = col_b1
        0b000000000000000000000000000001,  // addr b0 = col_b0
      };
    } else {
      selected_config->dram_matrix = {
        0b111111111111000000000001000000, /*  subch_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b6 */
        0b001000010000000001000000000000, /*  bg_b2 = addr b27 b22 b12 */
        0b000100001000000000001000000000, /*  bg_b1 = addr b26 b21 b9 */
        0b000010000100000000000100000000, /*  bg_b0 = addr b25 b20 b8 */
        0b100001000010000000100000000000, /*  bk_b1 = addr b29 b24 b19 b11 */
        0b010000100001000000010000000000, /*  bk_b0 = addr b28 b23 b18 b10 */
        0b100000000000000000000000000000, /*  row_b11 = addr b29 */
        0b010000000000000000000000000000, /*  row_b10 = addr b28 */
        0b001000000000000000000000000000, /*  row_b9 = addr b27 */
        0b000100000000000000000000000000, /*  row_b8 = addr b26 */
        0b000010000000000000000000000000, /*  row_b7 = addr b25 */
        0b000001000000000000000000000000, /*  row_b6 = addr b24 */
        0b000000100000000000000000000000, /*  row_b5 = addr b23 */
        0b000000010000000000000000000000, /*  row_b4 = addr b22 */
        0b000000001000000000000000000000, /*  row_b3 = addr b21 */
        0b000000000100000000000000000000, /*  row_b2 = addr b20 */
        0b000000000010000000000000000000, /*  row_b1 = addr b19 */
        0b000000000001000000000000000000, /*  row_b0 = addr b18 */
        0b000000000000100000000000000000, /*  col_b11 = addr b17 */
        0b000000000000010000000000000000, /*  col_b10 = addr b16 */
        0b000000000000001000000000000000, /*  col_b9 = addr b15 */
        0b000000000000000100000000000000, /*  col_b8 = addr b14 */
        0b000000000000000010000000000000, /*  col_b7 = addr b13 */
        0b000000000000000000000010000000, /*  col_b6 = addr b7 */
        0b000000000000000000000000100000, /*  col_b5 = addr b5 */
        0b000000000000000000000000010000, /*  col_b4 = addr b4 */
        0b000000000000000000000000001000, /*  col_b3 = addr b3 */
        0b000000000000000000000000000100, /*  col_b2 = addr b2 */
        0b000000000000000000000000000010, /*  col_b1 = addr b1 */
        0b000000000000000000000000000001, /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000000100000000000000000000000, /*  addr b29 = row_b11 */
        0b000000010000000000000000000000, /*  addr b28 = row_b10 */
        0b000000001000000000000000000000, /*  addr b27 = row_b9 */
        0b000000000100000000000000000000, /*  addr b26 = row_b8 */
        0b000000000010000000000000000000, /*  addr b25 = row_b7 */
        0b000000000001000000000000000000, /*  addr b24 = row_b6 */
        0b000000000000100000000000000000, /*  addr b23 = row_b5 */
        0b000000000000010000000000000000, /*  addr b22 = row_b4 */
        0b000000000000001000000000000000, /*  addr b21 = row_b3 */
        0b000000000000000100000000000000, /*  addr b20 = row_b2 */
        0b000000000000000010000000000000, /*  addr b19 = row_b1 */
        0b000000000000000001000000000000, /*  addr b18 = row_b0 */
        0b000000000000000000100000000000, /*  addr b17 = col_b11 */
        0b000000000000000000010000000000, /*  addr b16 = col_b10 */
        0b000000000000000000001000000000, /*  addr b15 = col_b9 */
        0b000000000000000000000100000000, /*  addr b14 = col_b8 */
        0b000000000000000000000010000000, /*  addr b13 = col_b7 */
        0b010000001000010000000000000000, /*  addr b12 = bg_b2 row_b9 row_b4 */
        0b000010100001000010000000000000, /*  addr b11 = bk_b1 row_b11 row_b6 row_b1 */
        0b000001010000100001000000000000, /*  addr b10 = bk_b0 row_b10 row_b5 row_b0 */
        0b001000000100001000000000000000, /*  addr b9 = bg_b1 row_b8 row_b3 */
        0b000100000010000100000000000000, /*  addr b8 = bg_b0 row_b7 row_b2 */
        0b000000000000000000000001000000, /*  addr b7 = col_b6 */
        0b100000111111111111000000000000, /*  addr b6 = subch_b0 row_b11 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5
                                              row_b4 row_b3 row_b2 row_b1 row_b0 */
        0b000000000000000000000000100000, /*  addr b5 = col_b5 */
        0b000000000000000000000000010000, /*  addr b4 = col_b4 */
        0b000000000000000000000000001000, /*  addr b3 = col_b3 */
        0b000000000000000000000000000100, /*  addr b2 = col_b2 */
        0b000000000000000000000000000010, /*  addr b1 = col_b1 */
        0b000000000000000000000000000001, /*  addr b0 = col_b0 */
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_4 && ranks == 1 && bank_groups == 4 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x80000000; /* 2048 MB */
    // 5 bank bits (consisting of subchannel, bank group, bank)
    selected_config->bank_shift = 25;
    selected_config->bank_mask = 0b11111;
    // 13 row bits (inside 1024 MB)
    selected_config->row_shift = 12;
    selected_config->row_mask = 0b1111111111111;
    // 12 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b111111111111;

    // 30 bits (1024 MB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b111111111111100000000001000000,  // sc_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 b6
        0b010001000100000000001000000000,  // bg_b1 = addr b28 b24 b20 b9
        0b001000100010000000000100000000,  // bg_b0 = addr b27 b23 b19 b8
        0b000100010001000000100000000000,  // ba_b1 = addr b26 b22 b18 b11
        0b100010001000100000010000000000,  // ba_b0 = addr b29 b25 b21 b17 b10
        0b100000000000000000000000000000,  // row_b12 = addr b29
        0b010000000000000000000000000000,  // row_b11 = addr b28
        0b001000000000000000000000000000,  // row_b10 = addr b27
        0b000100000000000000000000000000,  // row_b9 = addr b26
        0b000010000000000000000000000000,  // row_b8 = addr b25
        0b000001000000000000000000000000,  // row_b7 = addr b24
        0b000000100000000000000000000000,  // row_b6 = addr b23
        0b000000010000000000000000000000,  // row_b5 = addr b22
        0b000000001000000000000000000000,  // row_b4 = addr b21
        0b000000000100000000000000000000,  // row_b3 = addr b20
        0b000000000110000000000000000000,  // row_b2 = addr b20 b19
        0b000000000101000000000000000000,  // row_b1 = addr b20 b18
        0b000000000000100000000000000000,  // row_b0 = addr b17
        0b000000000000010000000000000000,  // col_b11 = addr b16
        0b000000000000001000000000000000,  // col_b10 = addr b15
        0b000000000000000100000000000000,  // col_b9 = addr b14
        0b000000000000000010000000000000,  // col_b8 = addr b13
        0b000000000000000001000000000000,  // col_b7 = addr b12
        0b000000000000000000000010000000,  // col_b6 = addr b7
        0b000000000000000000000000100000,  // col_b5 = addr b5
        0b000000000000000000000000010000,  // col_b4 = addr b4
        0b000000000000000000000000001000,  // col_b3 = addr b3
        0b000000000000000000000000000100,  // col_b2 = addr b2
        0b000000000000000000000000000010,  // col_b1 = addr b1
        0b000000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b000001000000000000000000000000,  // addr b29 = row_b12
        0b000000100000000000000000000000,  // addr b28 = row_b11
        0b000000010000000000000000000000,  // addr b27 = row_b10
        0b000000001000000000000000000000,  // addr b26 = row_b9
        0b000000000100000000000000000000,  // addr b25 = row_b8
        0b000000000010000000000000000000,  // addr b24 = row_b7
        0b000000000001000000000000000000,  // addr b23 = row_b6
        0b000000000000100000000000000000,  // addr b22 = row_b5
        0b000000000000010000000000000000,  // addr b21 = row_b4
        0b000000000000001000000000000000,  // addr b20 = row_b3
        0b000000000000001100000000000000,  // addr b19 = row_b3 row_b2
        0b000000000000001010000000000000,  // addr b18 = row_b3 row_b1
        0b000000000000000001000000000000,  // addr b17 = row_b0
        0b000000000000000000100000000000,  // addr b16 = col_b11
        0b000000000000000000010000000000,  // addr b15 = col_b10
        0b000000000000000000001000000000,  // addr b14 = col_b9
        0b000000000000000000000100000000,  // addr b13 = col_b8
        0b000000000000000000000010000000,  // addr b12 = col_b7
        0b000100001000101010000000000000,  // addr b11 = ba_b1 row_b9 row_b5 row_b3 row_b1
        0b000011000100010001000000000000,  // addr b10 = ba_b0 row_b12 row_b8 row_b4 row_b0
        0b010000100010001000000000000000,  // addr b9 = bg_b1 row_b11 row_b7 row_b3
        0b001000010001001100000000000000,  // addr b8 = bg_b0 row_b10 row_b6 row_b3 row_b2
        0b000000000000000000000001000000,  // addr b7 = col_b6
        0b100001111111111111000000000000,  // addr b6 = sc_b0 row_b12 row_b11 row_b10 row_b9 row_b8 row_b7 row_b6
                                            // row_b5 row_b4 row_b3 row_b2 row_b1 row_b0
        0b000000000000000000000000100000,  // addr b5 = col_b5
        0b000000000000000000000000010000,  // addr b4 = col_b4
        0b000000000000000000000000001000,  // addr b3 = col_b3
        0b000000000000000000000000000100,  // addr b2 = col_b2
        0b000000000000000000000000000010,  // addr b1 = col_b1
        0b000000000000000000000000000001,  // addr b0 = col_b0
      };
    } else {
      selected_config->dram_matrix = {
        0b111111111111100000000001000000, /*  subch_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b18 b17 b6
                                            */
        0b001000100010000000000100000000, /*  bg_b1 = addr b27 b23 b19 b8 */
        0b010001000100000000001000000000, /*  bg_b0 = addr b28 b24 b20 b9 */
        0b100010001000100000010000000000, /*  bk_b1 = addr b29 b25 b21 b17 b10 */
        0b000100010001000000100000000000, /*  bk_b0 = addr b26 b22 b18 b11 */
        0b100000000000000000000000000000, /*  row_b12 = addr b29 */
        0b010000000000000000000000000000, /*  row_b11 = addr b28 */
        0b001000000000000000000000000000, /*  row_b10 = addr b27 */
        0b000100000000000000000000000000, /*  row_b9 = addr b26 */
        0b000010000000000000000000000000, /*  row_b8 = addr b25 */
        0b000001000000000000000000000000, /*  row_b7 = addr b24 */
        0b000000100000000000000000000000, /*  row_b6 = addr b23 */
        0b000000010000000000000000000000, /*  row_b5 = addr b22 */
        0b000000001000000000000000000000, /*  row_b4 = addr b21 */
        0b000000000100000000000000000000, /*  row_b3 = addr b20 */
        0b000000000010000000000000000000, /*  row_b2 = addr b19 */
        0b000000000001000000000000000000, /*  row_b1 = addr b18 */
        0b000000000000100000000000000000, /*  row_b0 = addr b17 */
        0b000000000000010000000000000000, /*  col_b11 = addr b16 */
        0b000000000000001000000000000000, /*  col_b10 = addr b15 */
        0b000000000000000100000000000000, /*  col_b9 = addr b14 */
        0b000000000000000010000000000000, /*  col_b8 = addr b13 */
        0b000000000000000001000000000000, /*  col_b7 = addr b12 */
        0b000000000000000000000010000000, /*  col_b6 = addr b7 */
        0b000000000000000000000000100000, /*  col_b5 = addr b5 */
        0b000000000000000000000000010000, /*  col_b4 = addr b4 */
        0b000000000000000000000000001000, /*  col_b3 = addr b3 */
        0b000000000000000000000000000100, /*  col_b2 = addr b2 */
        0b000000000000000000000000000010, /*  col_b1 = addr b1 */
        0b000000000000000000000000000001, /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000001000000000000000000000000, /*  addr b29 = row_b12 */
        0b000000100000000000000000000000, /*  addr b28 = row_b11 */
        0b000000010000000000000000000000, /*  addr b27 = row_b10 */
        0b000000001000000000000000000000, /*  addr b26 = row_b9 */
        0b000000000100000000000000000000, /*  addr b25 = row_b8 */
        0b000000000010000000000000000000, /*  addr b24 = row_b7 */
        0b000000000001000000000000000000, /*  addr b23 = row_b6 */
        0b000000000000100000000000000000, /*  addr b22 = row_b5 */
        0b000000000000010000000000000000, /*  addr b21 = row_b4 */
        0b000000000000001000000000000000, /*  addr b20 = row_b3 */
        0b000000000000000100000000000000, /*  addr b19 = row_b2 */
        0b000000000000000010000000000000, /*  addr b18 = row_b1 */
        0b000000000000000001000000000000, /*  addr b17 = row_b0 */
        0b000000000000000000100000000000, /*  addr b16 = col_b11 */
        0b000000000000000000010000000000, /*  addr b15 = col_b10 */
        0b000000000000000000001000000000, /*  addr b14 = col_b9 */
        0b000000000000000000000100000000, /*  addr b13 = col_b8 */
        0b000000000000000000000010000000, /*  addr b12 = col_b7 */
        0b000010001000100010000000000000, /*  addr b11 = bk_b0 row_b9 row_b5 row_b1 */
        0b000101000100010001000000000000, /*  addr b10 = bk_b1 row_b12 row_b8 row_b4 row_b0 */
        0b001000100010001000000000000000, /*  addr b9 = bg_b0 row_b11 row_b7 row_b3 */
        0b010000010001000100000000000000, /*  addr b8 = bg_b1 row_b10 row_b6 row_b2 */
        0b000000000000000000000001000000, /*  addr b7 = col_b6 */
        0b100001111111111111000000000000, /*  addr b6 = subch_b0 row_b12 row_b11 row_b10 row_b9 row_b8 row_b7 row_b6
                                              row_b5 row_b4 row_b3 row_b2 row_b1 row_b0 */
        0b000000000000000000000000100000, /*  addr b5 = col_b5 */
        0b000000000000000000000000010000, /*  addr b4 = col_b4 */
        0b000000000000000000000000001000, /*  addr b3 = col_b3 */
        0b000000000000000000000000000100, /*  addr b2 = col_b2 */
        0b000000000000000000000000000010, /*  addr b1 = col_b1 */
        0b000000000000000000000000000001, /*  addr b0 = col_b0 */
      };
    }
  } else if (uarch == Microarchitecture::AMD_ZEN_4 && ranks == 2 && bank_groups == 8 && banks == 4) {
    selected_config = new DRAMConfig;
    selected_config->phys_dram_offset = 0x80000000; /* 2048 MB */
    // 7 bank bits (consisting of subchannel, rank, bank group, bank)
    selected_config->bank_shift = 23;
    selected_config->bank_mask = 0b1111111;
    // 11 row bits (inside 1 GB)
    selected_config->row_shift = 12;
    selected_config->row_mask = 0b11111111111;
    // 12 column bits
    selected_config->column_shift = 0;
    selected_config->column_mask = 0b111111111111;

    // 30 bits (1024 MB)
    selected_config->matrix_size = 30;
    if (samsung_row_mapping) {
      selected_config->dram_matrix = {
        0b111111111110000000000001000000,  // sc_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b6
        0b000000000001000000000000000000,  // rk_b0 = addr b18
        0b010000100000000001000000000000,  // bg_b2 = addr b28 b23 b12
        0b001000010000000000001000000000,  // bg_b1 = addr b27 b22 b9
        0b000100001000000000000100000000,  // bg_b0 = addr b26 b21 b8
        0b000010000100000000100000000000,  // ba_b1 = addr b25 b20 b11
        0b100001000010000000010000000000,  // ba_b0 = addr b29 b24 b19 b10
        0b100000000000000000000000000000,  // row_b10 = addr b29
        0b010000000000000000000000000000,  // row_b9 = addr b28
        0b001000000000000000000000000000,  // row_b8 = addr b27
        0b000100000000000000000000000000,  // row_b7 = addr b26
        0b000010000000000000000000000000,  // row_b6 = addr b25
        0b000001000000000000000000000000,  // row_b5 = addr b24
        0b000000100000000000000000000000,  // row_b4 = addr b23
        0b000000010000000000000000000000,  // row_b3 = addr b22
        0b000000011000000000000000000000,  // row_b2 = addr b22 b21
        0b000000010100000000000000000000,  // row_b1 = addr b22 b20
        0b000000000010000000000000000000,  // row_b0 = addr b19
        0b000000000000100000000000000000,  // col_b11 = addr b17
        0b000000000000010000000000000000,  // col_b10 = addr b16
        0b000000000000001000000000000000,  // col_b9 = addr b15
        0b000000000000000100000000000000,  // col_b8 = addr b14
        0b000000000000000010000000000000,  // col_b7 = addr b13
        0b000000000000000000000010000000,  // col_b6 = addr b7
        0b000000000000000000000000100000,  // col_b5 = addr b5
        0b000000000000000000000000010000,  // col_b4 = addr b4
        0b000000000000000000000000001000,  // col_b3 = addr b3
        0b000000000000000000000000000100,  // col_b2 = addr b2
        0b000000000000000000000000000010,  // col_b1 = addr b1
        0b000000000000000000000000000001,  // col_b0 = addr b0
      };
      selected_config->addr_matrix = {
        0b000000010000000000000000000000,  // addr b29 = row_b10
        0b000000001000000000000000000000,  // addr b28 = row_b9
        0b000000000100000000000000000000,  // addr b27 = row_b8
        0b000000000010000000000000000000,  // addr b26 = row_b7
        0b000000000001000000000000000000,  // addr b25 = row_b6
        0b000000000000100000000000000000,  // addr b24 = row_b5
        0b000000000000010000000000000000,  // addr b23 = row_b4
        0b000000000000001000000000000000,  // addr b22 = row_b3
        0b000000000000001100000000000000,  // addr b21 = row_b3 row_b2
        0b000000000000001010000000000000,  // addr b20 = row_b3 row_b1
        0b000000000000000001000000000000,  // addr b19 = row_b0
        0b010000000000000000000000000000,  // addr b18 = rk_b0
        0b000000000000000000100000000000,  // addr b17 = col_b11
        0b000000000000000000010000000000,  // addr b16 = col_b10
        0b000000000000000000001000000000,  // addr b15 = col_b9
        0b000000000000000000000100000000,  // addr b14 = col_b8
        0b000000000000000000000010000000,  // addr b13 = col_b7
        0b001000001000010000000000000000,  // addr b12 = bg_b2 row_b9 row_b4
        0b000001000001001010000000000000,  // addr b11 = ba_b1 row_b6 row_b3 row_b1
        0b000000110000100001000000000000,  // addr b10 = ba_b0 row_b10 row_b5 row_b0
        0b000100000100001000000000000000,  // addr b9 = bg_b1 row_b8 row_b3
        0b000010000010001100000000000000,  // addr b8 = bg_b0 row_b7 row_b3 row_b2
        0b000000000000000000000001000000,  // addr b7 = col_b6
        0b100000011111111111000000000000,  // addr b6 = sc_b0 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4 row_b3
                                            // row_b2 row_b1 row_b0
        0b000000000000000000000000100000,  // addr b5 = col_b5
        0b000000000000000000000000010000,  // addr b4 = col_b4
        0b000000000000000000000000001000,  // addr b3 = col_b3
        0b000000000000000000000000000100,  // addr b2 = col_b2
        0b000000000000000000000000000010,  // addr b1 = col_b1
        0b000000000000000000000000000001,  // addr b0 = col_b0
      };
    } else {
      selected_config->dram_matrix = {
        0b111111111110000000000001000000, /*  subch_b0 = addr b29 b28 b27 b26 b25 b24 b23 b22 b21 b20 b19 b6 */
        0b000000000001000000000000000000, /*  rank_b0 = addr b18 */
        0b000100001000000000000100000000, /*  bg_b2 = addr b26 b21 b8 */
        0b001000010000000000001000000000, /*  bg_b1 = addr b27 b22 b9 */
        0b010000100000000001000000000000, /*  bg_b0 = addr b28 b23 b12 */
        0b100001000010000000010000000000, /*  bk_b1 = addr b29 b24 b19 b10 */
        0b000010000100000000100000000000, /*  bk_b0 = addr b25 b20 b11 */
        0b100000000000000000000000000000, /*  row_b10 = addr b29 */
        0b010000000000000000000000000000, /*  row_b9 = addr b28 */
        0b001000000000000000000000000000, /*  row_b8 = addr b27 */
        0b000100000000000000000000000000, /*  row_b7 = addr b26 */
        0b000010000000000000000000000000, /*  row_b6 = addr b25 */
        0b000001000000000000000000000000, /*  row_b5 = addr b24 */
        0b000000100000000000000000000000, /*  row_b4 = addr b23 */
        0b000000010000000000000000000000, /*  row_b3 = addr b22 */
        0b000000001000000000000000000000, /*  row_b2 = addr b21 */
        0b000000000100000000000000000000, /*  row_b1 = addr b20 */
        0b000000000010000000000000000000, /*  row_b0 = addr b19 */
        0b000000000000100000000000000000, /*  col_b11 = addr b17 */
        0b000000000000010000000000000000, /*  col_b10 = addr b16 */
        0b000000000000001000000000000000, /*  col_b9 = addr b15 */
        0b000000000000000100000000000000, /*  col_b8 = addr b14 */
        0b000000000000000010000000000000, /*  col_b7 = addr b13 */
        0b000000000000000000000010000000, /*  col_b6 = addr b7 */
        0b000000000000000000000000100000, /*  col_b5 = addr b5 */
        0b000000000000000000000000010000, /*  col_b4 = addr b4 */
        0b000000000000000000000000001000, /*  col_b3 = addr b3 */
        0b000000000000000000000000000100, /*  col_b2 = addr b2 */
        0b000000000000000000000000000010, /*  col_b1 = addr b1 */
        0b000000000000000000000000000001, /*  col_b0 = addr b0 */
      };
      selected_config->addr_matrix = {
        0b000000010000000000000000000000, /*  addr b29 = row_b10 */
        0b000000001000000000000000000000, /*  addr b28 = row_b9 */
        0b000000000100000000000000000000, /*  addr b27 = row_b8 */
        0b000000000010000000000000000000, /*  addr b26 = row_b7 */
        0b000000000001000000000000000000, /*  addr b25 = row_b6 */
        0b000000000000100000000000000000, /*  addr b24 = row_b5 */
        0b000000000000010000000000000000, /*  addr b23 = row_b4 */
        0b000000000000001000000000000000, /*  addr b22 = row_b3 */
        0b000000000000000100000000000000, /*  addr b21 = row_b2 */
        0b000000000000000010000000000000, /*  addr b20 = row_b1 */
        0b000000000000000001000000000000, /*  addr b19 = row_b0 */
        0b010000000000000000000000000000, /*  addr b18 = rank_b0 */
        0b000000000000000000100000000000, /*  addr b17 = col_b11 */
        0b000000000000000000010000000000, /*  addr b16 = col_b10 */
        0b000000000000000000001000000000, /*  addr b15 = col_b9 */
        0b000000000000000000000100000000, /*  addr b14 = col_b8 */
        0b000000000000000000000010000000, /*  addr b13 = col_b7 */
        0b000010001000010000000000000000, /*  addr b12 = bg_b0 row_b9 row_b4 */
        0b000000100001000010000000000000, /*  addr b11 = bk_b0 row_b6 row_b1 */
        0b000001010000100001000000000000, /*  addr b10 = bk_b1 row_b10 row_b5 row_b0 */
        0b000100000100001000000000000000, /*  addr b9 = bg_b1 row_b8 row_b3 */
        0b001000000010000100000000000000, /*  addr b8 = bg_b2 row_b7 row_b2 */
        0b000000000000000000000001000000, /*  addr b7 = col_b6 */
        0b100000011111111111000000000000, /*  addr b6 = subch_b0 row_b10 row_b9 row_b8 row_b7 row_b6 row_b5 row_b4
                                              row_b3 row_b2 row_b1 row_b0 */
        0b000000000000000000000000100000, /*  addr b5 = col_b5 */
        0b000000000000000000000000010000, /*  addr b4 = col_b4 */
        0b000000000000000000000000001000, /*  addr b3 = col_b3 */
        0b000000000000000000000000000100, /*  addr b2 = col_b2 */
        0b000000000000000000000000000010, /*  addr b1 = col_b1 */
        0b000000000000000000000000000001, /*  addr b0 = col_b0 */
      };
    }
  }

  if (!selected_config) {
    Logger::log_error("No DRAMConfig present for the selected configuration tuple.");
    exit(EXIT_FAILURE);
  }

  selected_config->uarch = uarch;

  Logger::log_info("Selected DRAM config includes the following parameters:");
  Logger::log_data(format_string("    sync_ref_threshold = %lu", selected_config->sync_ref_threshold));

  selected_config->check_validity();
}

void DRAMConfig::select_config(std::string const& uarch_str, int ranks, int bank_groups, int banks, bool samsung_row_mapping) {
  static const std::map<std::string, Microarchitecture> str_to_uarch = {
    { "coffeelake", Microarchitecture::INTEL_COFFEE_LAKE },
    { "zen1plus", Microarchitecture::AMD_ZEN_1_PLUS },
    { "zen2", Microarchitecture::AMD_ZEN_2 },
    { "zen3", Microarchitecture::AMD_ZEN_3 },
    { "zen4", Microarchitecture::AMD_ZEN_4 },
  };

  auto it = str_to_uarch.find(uarch_str);
  if (it == str_to_uarch.end()) {
    Logger::log_error(format_string("Microarchitecture/platform string '%s' does not exist.", uarch_str.c_str()));
    Logger::log_data("Possible strings:");
    for (auto const& element : str_to_uarch) {
      Logger::log_data(format_string("* %s => %s", element.first.c_str(), to_string(element.second)));
    }
    exit(EXIT_FAILURE);
  }

  auto uarch = it->second;

  DRAMConfig::select_config(uarch, ranks, bank_groups, banks, samsung_row_mapping);
}

DRAMConfig& DRAMConfig::get() {
  if (!selected_config) {
    Logger::log_error("DRAMConfig::get() called, but no configuration has been selected.");
    exit(EXIT_FAILURE);
  }

  return *selected_config;
}

static bool matrix_product_is_identity_matrix(std::vector<size_t> const& mat_a, std::vector<size_t> const& mat_b) {
  // NOTE: This assumes square matrices.
  assert(mat_a.size() == mat_b.size() && "Both matrices are the same size.");
  auto size = mat_a.size();

  std::vector<size_t> result(size, 0);

  // NOTE: The first column of the matrix is at the LSB, so we have to "reverse" the column index.
  for (size_t i = 0; i < size; i++) {
    for (size_t j = 0; j < size; j++) {
      for (size_t k = 0; k < size; k++) {
        // op_a = A[i][k]
        auto op_a = (mat_a[i] >> (size - k - 1)) & 0x1;
        // op_b = B[k][j]
        auto op_b = (mat_b[k] >> (size - j - 1)) & 0x1;
        // result[i][j] += op_a * op_b (mod 2)
        result[i] ^= (op_a * op_b) << (size - j - 1);
      }
    }
  }

  // Verify we have the identity matrix.
  for (size_t i = 0; i < size; i++) {
    auto expected = BIT_SET(size - i - 1);
    if (result[i] != expected) {
      return false;
    }
  }

  return true;
}

void DRAMConfig::check_validity() {
  // Check the number of DRAM address bits is the same as the matrix size.
  size_t total_num_bits = bank_bits() + row_bits() + column_bits();
  if (total_num_bits != matrix_size) {
    Logger::log_error(
      "Total number of DRAM address bits (rank + bank group + bank + row + column) did not match address matrix size.");
    exit(EXIT_FAILURE);
  }

  // Check the matrices are of the size specified.
  if (dram_matrix.size() != matrix_size || addr_matrix.size() != matrix_size) {
    Logger::log_error("The address matrices do not have the size indicated in 'matrix_size'.");
    exit(EXIT_FAILURE);
  }

  // Check the mask for the different DRAM address parts don't overlap. Do this by checking that the OR of all masks
  // has the required shape (i.e., the (matrix_size) least significant bits are set).
  size_t combined_mask = (bank_mask << bank_shift) | (row_mask << row_shift) | (column_mask << column_shift);
  size_t required_mask = (1ULL << matrix_size) - 1;
  if (combined_mask != required_mask) {
    Logger::log_error(format_string(
      "The combined mask of all DRAM address parts is\n  %064b,\nwhich is different from the mask required:\n  %064b",
      combined_mask, required_mask));
    exit(EXIT_FAILURE);
  }

  if (phys_dram_offset % memory_size() != 0) {
    Logger::log_error(
      "Adding/subtracting PHYS_DRAM_OFFSET does not only change the MSBs above the DRAM address matrix.");
    exit(EXIT_FAILURE);
  }

  // Check that dram_matrix and addr_matrix are inverses of each other (by checking that their product is the identity
  // matrix).
  if (!matrix_product_is_identity_matrix(dram_matrix, addr_matrix)) {
    Logger::log_error("The address matrix is not the inverse of the DRAM matrix.");
    exit(EXIT_FAILURE);
  }
}

size_t DRAMConfig::apply_matrix(const std::vector<size_t>& matrix, size_t addr) {
  size_t result = 0;
  for (auto row : matrix) {
    result <<= 1;
    result |= (size_t)__builtin_parityll(row & addr);
  }
  return result;
}
