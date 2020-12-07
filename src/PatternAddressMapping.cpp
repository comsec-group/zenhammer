#include <cassert>
#include <GlobalDefines.hpp>
#include <Utilities/Uuid.hpp>
#include <Utilities/Range.hpp>
#include <iostream>
#include <Fuzzer/FuzzingParameterSet.hpp>
#include "Fuzzer/PatternAddressMapping.hpp"

PatternAddressMapping::PatternAddressMapping() : instance_id(uuid::gen_uuid()) { /* NOLINT */
  // standard mersenne_twister_engine seeded with rd()
  std::random_device rd;
  gen = std::mt19937(rd());

  // initialize pointers for first and last address of address pool
  highest_address = (volatile char *) nullptr;
  lowest_address = (volatile char *) (~(0UL));
}

void PatternAddressMapping::randomize_addresses(FuzzingParameterSet &fuzzing_params,
                                                std::vector<AggressorAccessPattern> &agg_access_patterns) {
  aggressor_to_addr.clear();
  const int bank_no = fuzzing_params.get_random_bank_no();
  const int agg_inter_distance = fuzzing_params.get_random_inter_distance();
  bool use_seq_addresses = fuzzing_params.get_random_use_seq_addresses();

  int start_row = Range<int>(0, 8192).get_random_number(gen);
  size_t cur_row = start_row;

  // we can make use here of the fact that each aggressor (identified by its ID) has a fixed N, that means, is
  // either accessed individually (N=1) or in a group of multiple aggressors (N>1; e.g., N=2 for double sided)
  // => if we already know the address of any aggressor in an aggressor access pattern, we already must know
  // addresses for all of them as we must have accessed all of them together before
  // however, we will consider mapping multiple aggressors to the same address to simulate hammering an aggressor of
  // a pair more frequently, for that we just choose a random row
  for (auto &acc_pattern : agg_access_patterns) {
    bool known_agg = false;
    for (size_t i = 0; i < acc_pattern.aggressors.size(); i++) {
      Aggressor &current_agg = acc_pattern.aggressors[i];
      if (aggressor_to_addr.count(current_agg.id) > 0) {
        // this indicates that all following aggressors must also have known addresses, otherwise there's something
        // wrong with this pattern
        known_agg = true;
      } else if (known_agg) {
        // a previous aggressor was known but this aggressor is not known -> this must never happen because we use
        // Aggressor objects only once (e.g., either 1-sided or within a 2-sided pair); reusing addresses is achieve by
        // mapping the different Aggressors to the same address
        fprintf(stderr,
                "[-] Something went wrong with the aggressor's address selection. "
                "Only one address of an N-sided pair has been accessed before. That's strange!\n");
        exit(1);
      } else if (i > 0) {
        // if this aggressor has any partners, we need to add the appropriate distance and cannot choose randomly
        Aggressor &last_agg = acc_pattern.aggressors.at(i - 1);
        auto last_addr = aggressor_to_addr.at(last_agg.id);
        cur_row = cur_row + (size_t) fuzzing_params.get_agg_intra_distance();
        size_t row = use_seq_addresses ? cur_row : (last_addr.row + (size_t) fuzzing_params.get_agg_intra_distance());
        aggressor_to_addr.insert({current_agg.id, DRAMAddr(bank_no, row, last_addr.col)});
      } else {
        cur_row = cur_row + (size_t) agg_inter_distance;
        // pietro suggested to consider the first 512 rows only because hassan found out that they are in a subarray
        // and hammering spanning rows across multiple subarrays doesn't lead to bit flips
        // TODO: Change this back?
        size_t row = use_seq_addresses ? cur_row : Range<int>(start_row, start_row + 256).get_random_number(gen);
        aggressor_to_addr.insert({current_agg.id, DRAMAddr(bank_no, row, 0)});
      }
      auto cur_addr = (volatile char *) aggressor_to_addr.at(current_agg.id).to_virt();
      if (cur_addr < lowest_address) lowest_address = cur_addr;
      if (cur_addr > highest_address) highest_address = cur_addr;
    }
  }
}

std::vector<volatile char *> PatternAddressMapping::export_pattern_for_jitting(std::vector<Aggressor> &aggressors,
                                                                               size_t base_period) {
  std::stringstream stdout_str;
  stdout_str << "Pattern (bank = " << aggressor_to_addr.at(aggressors.at(0).id).bank << "): " << std::endl;

  std::vector<volatile char *> address_pattern;
  bool invalid_aggs{false};

  for (size_t i = 0; i < aggressors.size(); ++i) {
    // for better visualization: add whitespace after each base period
    if (i!=0 && (i%base_period)==0) {
      stdout_str << std::endl;
    }

    // check whether this is a valid aggressor, i.e., the aggressor's ID != -1
    auto agg = aggressors[i];
    if (agg.id==ID_PLACEHOLDER_AGG) {
      stdout_str << FRED << "-1" << NONE;
      invalid_aggs = true;
      continue;
    }

    // check whether there exists a aggressor ID -> address mapping before trying to access it
    if (aggressor_to_addr.count(agg.id)==0) {
      fprintf(stderr, "[-] ");
      continue;
    }

    // retrieve virtual address of current aggressor in pattern and add it to output vector
    address_pattern.push_back((volatile char *) aggressor_to_addr.at(agg.id).to_virt());
    stdout_str << aggressor_to_addr.at(agg.id).row << " ";
  }

  // print string representation of pattern
  std::cout << stdout_str.str() << std::endl;
  std::cout << std::endl;

  if (invalid_aggs) {
    printf("[-] Found at least an invalid aggressor in the pattern. "
           "These aggressors were NOT added but printed to visualize their position.\n");
  }
  return address_pattern;
}

volatile char *PatternAddressMapping::get_lowest_address() const {
  if (lowest_address==nullptr) {
    fprintf(stderr, "[-] Cannot get lowest address because no address has been assigned.");
    exit(1);
  }
  return lowest_address;
}

volatile char *PatternAddressMapping::get_highest_address() const {
  if (lowest_address==nullptr) {
    fprintf(stderr, "[-] Cannot get highest address because no address has been assigned");
    exit(1);
  }
  return highest_address;
}

void to_json(nlohmann::json &j, const PatternAddressMapping &p) {
  j = nlohmann::json{{"id", p.instance_id},
                     {"aggressor_to_addr", p.aggressor_to_addr},
                     {"bit_flips", p.bit_flips},
  };
}

void from_json(const nlohmann::json &j, PatternAddressMapping &p) {
  j.at("id").get_to(p.instance_id);
  j.at("aggressor_to_addr").get_to(p.aggressor_to_addr);
  j.at("bit_flips").get_to(p.bit_flips);
}
