#include "Fuzzer/BitFlip.hpp"

#include <bitset>

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const BitFlip &p) {
  j = nlohmann::json{{"dram_addr", p.address},
                     {"bitmask", p.bitmask},
                     {"corrupted_data", p.corrupted_data},
  };
}

void from_json(const nlohmann::json &j, BitFlip &p) {
  j.at("dram_addr").get_to(p.address);
  j.at("bitmask").get_to(p.bitmask);
  j.at("corrupted_data").get_to(p.corrupted_data);
}

#endif

BitFlip::BitFlip(const DRAMAddr &address, uint8_t flips_bitmask, uint8_t corrupted_data)
    : address(address), bitmask(flips_bitmask), corrupted_data(corrupted_data) {}

BitFlip::BitFlip() : address(DRAMAddr()), bitmask(0), corrupted_data(0) {}

size_t BitFlip::count_z2o_corruptions() const {
  const auto bitmask_nbits = sizeof(bitmask)/8;
  std::bitset<bitmask_nbits> mask_bits(bitmask);
  const auto data_nbits = sizeof(corrupted_data)/8;
  std::bitset<data_nbits> data_bits(corrupted_data);
  // we assume that both (corrupted_data, bitmask) have the same no. of bits
  auto z2o_corruptions = 0;
  for (size_t i = 0; i < mask_bits.size(); ++i) {
    if (mask_bits[i]==1 && data_bits[i]==0) z2o_corruptions++;
  }
  return z2o_corruptions;
}

size_t BitFlip::count_o2z_corruptions() const {
  const auto bitmask_nbits = sizeof(bitmask)/8;
  std::bitset<bitmask_nbits> mask_bits(bitmask);
  const auto data_nbits = sizeof(corrupted_data)/8;
  std::bitset<data_nbits> data_bits(corrupted_data);
  // we assume that both (corrupted_data, bitmask) have the same no. of bits
  auto o2z_corruptions = 0;
  for (size_t i = 0; i < mask_bits.size(); ++i) {
    if (mask_bits[i]==1 && data_bits[i]==1) o2z_corruptions++;
  }
  return o2z_corruptions;
}
