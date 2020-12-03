#include "Fuzzer/BitFlip.hpp"

void to_json(nlohmann::json &j, const BitFlip &p) {
  j = nlohmann::json{{"dram_addr", p.address},
                     {"bitmask", p.bitmask},
                     {"data", p.data},
  };
}

void from_json(const nlohmann::json &j, BitFlip &p) {
  j.at("dram_addr").get_to(p.address);
  j.at("bitmask").get_to(p.bitmask);
  j.at("data").get_to(p.data);
}

BitFlip::BitFlip(const DRAMAddr &address, uint8_t bitmask, uint8_t data)
    : address(address), bitmask(bitmask), data(data) {}
