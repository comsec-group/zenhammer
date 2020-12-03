#ifndef BLACKSMITH_INCLUDE_FUZZER_BITFLIP_HPP_
#define BLACKSMITH_INCLUDE_FUZZER_BITFLIP_HPP_

#include "DRAMAddr.hpp"

class BitFlip {
 public:
  // the address where the bit flip was observed
  DRAMAddr address{};

  // mask of the bits that flipped, i.e., positions where value == 1 flipped
  uint8_t bitmask{};

  // data containing the bit flips
  uint8_t data{};

  BitFlip();

  BitFlip(const DRAMAddr &address, uint8_t bitmask, uint8_t data);
};

void to_json(nlohmann::json &j, const BitFlip &p);

void from_json(const nlohmann::json &j, BitFlip &p);

#endif //BLACKSMITH_INCLUDE_FUZZER_BITFLIP_HPP_
