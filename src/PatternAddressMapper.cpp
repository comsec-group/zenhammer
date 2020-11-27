#include "Fuzzer/PatternAddressMapper.h"

PatternAddressMapper::PatternAddressMapper(HammeringPattern &hp)
    : instance_id(uuid::gen_uuid()), hammering_pattern(hp) {
  // standard mersenne_twister_engine seeded with rd()
  std::random_device rd;
  gen = std::mt19937(rd());

  // initialize pointers for first and last address of address pool
  highest_address = (volatile char *) nullptr;
  lowest_address = (volatile char *) (~(0UL));
}

void PatternAddressMapper::randomize_addresses(size_t bank) {
  aggressor_to_addr.clear();
  const int agg_intra_distance = 2;
  const int agg_inter_distance = Range(4, 6).get_random_number(gen);
  bool use_seq_addresses = (bool) (Range(0, 1).get_random_number(gen));
  std::cout << "use_seq_addresses: " << use_seq_addresses << std::endl;
  size_t cur_row = 1;

  int start_row = Range(0, 8192).get_random_number(gen);
  cur_row = start_row;

  // we can make use here of the fact that each aggressor (identified by its ID) has a fixed N, that means, is
  // either accessed individually (N=1) or in a group of multiple aggressors (N>1; e.g., N=2 for double sided)
  // => if we already know the address of any aggressor in an aggressor access pattern, we already must know
  // addresses for all of them as we must have accessed all of them together before
  // however, we will consider mapping multiple aggressors to the same address to simulate hammering an aggressor of
  // a pair more frequently, for that we just choose a random row
  for (auto &acc_pattern : hammering_pattern.agg_access_patterns) {
    bool known_agg = false;
    for (size_t i = 0; i < acc_pattern.offset_aggressor_map.size(); i++) {
      Aggressor &current_agg = acc_pattern.offset_aggressor_map[i];
      if (aggressor_to_addr.count(current_agg.id) > 0) {
        // this indicates that all following aggressors must also have known addresses, otherwise there's something
        // wrong with this pattern
        known_agg = true;
      } else if (known_agg) {
        // a previous aggressor was known but this aggressor is not known -> this must never happen
        fprintf(stderr,
                "[-] Something went wrong with the aggressor's address selection. "
                "Only one address of an N-sided pair is known. That's strange!\n");
        exit(1);
      } else if (i > 0) {
        // if this aggressor has any partners, we need to add the appropriate distance and cannot choose randomly
        Aggressor &last_agg = acc_pattern.offset_aggressor_map.at(i - 1);
        auto last_addr = aggressor_to_addr.at(last_agg.id);
        cur_row = cur_row + (size_t) agg_intra_distance;
        size_t row = use_seq_addresses ? cur_row : (last_addr.row + (size_t) agg_intra_distance);
        aggressor_to_addr.insert({current_agg.id, DRAMAddr(bank, row, last_addr.col)});
      } else {
        cur_row = cur_row + (size_t) agg_inter_distance;
        // pietro suggested to consider the first 512 rows only because hassan found out that they are in a subarray
        // and hammering spanning rows across multiple subarrays doesn't lead to bit flips
        // TODO: Change this back?
        size_t row = use_seq_addresses ? cur_row : Range(start_row, start_row + 256).get_random_number(gen);
        aggressor_to_addr.insert({current_agg.id, DRAMAddr(bank, row, 0)});
      }
      auto cur_addr = (volatile char *) aggressor_to_addr.at(current_agg.id).to_virt();
      if (cur_addr < lowest_address) lowest_address = cur_addr;
      if (cur_addr > highest_address) highest_address = cur_addr;
    }
  }
}

std::vector<volatile char *> PatternAddressMapper::export_pattern_for_jitting() {
  std::vector<volatile char *> address_pattern;
  std::cout << "Pattern (bank = ";
  std::cout << aggressor_to_addr.at(hammering_pattern.accesses.at(0).id).bank
            << "): "
            << std::endl;

  for (auto &agg : hammering_pattern.accesses) {
    // TODO: Debug this... could it be that there are still placeholder aggressors? Add a check in pattern generation!
    address_pattern.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
    std::cout << aggressor_to_addr.at(agg.id).row << " ";

  }
  std::cout << std::endl;
  return address_pattern;
}

volatile char *PatternAddressMapper::get_lowest_address() const {
  if (lowest_address==nullptr) {
    fprintf(stderr, "[-] Cannot get lowest address because no address has been assigned to field.");
    exit(1);
  }
  // printf("lowest_address: %p\n", (volatile char *)lowest_address);
  return lowest_address;
}

volatile char *PatternAddressMapper::get_highest_address() const {
  if (lowest_address==nullptr) {
    fprintf(stderr, "[-] Cannot get highest address because no address has been assigned to field.");
    exit(1);
  }
  // printf("highest_address: %p\n", (volatile char *)highest_address);
  return highest_address;
}