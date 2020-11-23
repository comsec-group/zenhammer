#ifndef HAMMERING_PATTERN
#define HAMMERING_PATTERN

#include <unordered_map>
#include <vector>
#include <random>

#include "AggressorAccessPattern.hpp"
#include "Range.hpp"

class HammeringPattern {
 public:
  // the base period this hammering pattern was generated for
  size_t base_period;

  // the order in which accesses happen
  std::vector<Aggressor> accesses;

  // additional and more structured information about the aggressors involved in this pattern such as whether they are 1-sided or 2-sided
  std::vector<AggressorAccessPattern> agg_access_patterns;

  HammeringPattern(size_t base_period, std::vector<Aggressor> &&accesses, std::vector<AggressorAccessPattern> &&access_patterns)
      : base_period(base_period), accesses(std::move(accesses)), agg_access_patterns(std::move(access_patterns)) {
  }
};

class PatternAddressMapper {
 public:
  // data about the pattern
  HammeringPattern &hammering_pattern;

  // a mapping from aggressors included in this pattern to memory addresses (DRAMAddr)
  std::unordered_map<AGGRESSOR_ID_TYPE, DRAMAddr> aggressor_to_addr;

  // a randomization engine
  std::mt19937 gen;

  PatternAddressMapper(HammeringPattern hp) : hammering_pattern(hp) {
    // standard mersenne_twister_engine seeded with rd()
    std::random_device rd;
    gen = std::mt19937(rd());
  }

  // chooses new addresses for the aggressors involved in its referenced HammeringPattern
  void randomize_addresses(int bank) {
    const int agg_intra_distance = 2;

    // we can make use here of the fact that each aggressor (identified by its ID) has a fixed N, that means, is
    // either accessed individually (N=1) or in a group of multiple aggressors (N>1; e.g., N=2 for double sided)
    // => if we already know the address of any aggressor in an aggressor access pattern, we already must know
    // addresses for all of them as we must have accessed all of them together before
    // however, we will consider mapping multiple aggressors to the same address to simulate hammering an aggressor of
    // a pair more frequently, for that we just choose a random row
    aggressor_to_addr.clear();
    for (auto &acc_pattern : hammering_pattern.agg_access_patterns) {
      bool known_agg = false;
      for (size_t i = 0; i < acc_pattern.offset_aggressor_map.size(); i++) {
        Aggressor &current_agg = acc_pattern.offset_aggressor_map[i];
        if (aggressor_to_addr.count(current_agg.id) > 0) {
          // this indicates that all following aggressors must also have known addresses, otherwise there's something
          // wrong with this pattern
          known_agg = true;
        } else if (known_agg == true) {
          // a previous aggressor was known but this aggressor is not known -> this must never happen
          fprintf(stderr,
                  "[-] Something went wrong with the aggressor's address selection. "
                  "Only one address of an N-sided pair is known. That's strange!\n");
          exit(1);
        } else if (i > 0) {
          Aggressor &last_agg = acc_pattern.offset_aggressor_map.at(i - 1);
          DRAMAddr &last_addr = aggressor_to_addr.at(last_agg.id);
          aggressor_to_addr[current_agg.id] = DRAMAddr(last_addr.bank, last_addr.row + agg_intra_distance, last_addr.col);
        } else {
          // pietro suggested to consider the first 512 rows only because hassan found out that they are in a subarray
          // and hammering across multiple subarrays doesn't work
          aggressor_to_addr[current_agg.id] = DRAMAddr(bank, Range(0, 511).get_random_number(gen), 0);
        }
      }
    }
  }

  // exports this pattern in a format that can be used by the CodeJitter
  std::vector<volatile char *> export_pattern_for_jitting() {
    // TODO: Implement me!
    return {};
  }
};

#endif /* HAMMERING_PATTERN */
