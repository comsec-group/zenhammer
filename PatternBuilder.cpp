#include "PatternBuilder.h"

#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

std::ostream& operator<<(std::ostream& o, const FormattedNumber& a) {
  o.fill(a.fill);
  o.width(a.width);
  return o;
}

PatternBuilder::PatternBuilder()
    : num_refresh_intervals(Range(1, 8)),
      num_hammering_pairs(Range(1, 20)),
      num_nops(Range(1, 4)),
      multiplicator_hammering_pairs(Range(2, 12)),
      multiplicator_nops(Range(1, 22)) {}

int PatternBuilder::get_total_duration_pi(int num_ref_intervals) {
  return num_ref_intervals * duration_full_refresh;
}

// TODO: Measure how many accesses are possible in a given interval

std::vector<std::string> gen_random_pairs(size_t N) {
  std::vector<std::string> all_pairs;
  while (all_pairs.size() < N) {
    int i = rand() % 98;
    std::stringstream ss;
    ss << "H_" << FormattedNumber() << i << " H_" << FormattedNumber() << i + 1;
    all_pairs.push_back(ss.str());
  }
  return all_pairs;
}

std::vector<std::string> gen_random_accesses(size_t N) {
  std::vector<std::string> all_accesses;
  while (all_accesses.size() < N) {
    int i = rand() % 98;
    std::stringstream ss;
    // expand the digits to always have two digits
    ss << "N_" << FormattedNumber() << i;
    all_accesses.push_back(ss.str());
  }
  return all_accesses;
}

void PatternBuilder::print_patterns(int num_patterns, int accesses_per_pattern) {
  std::cout << "Printing generated patterns..." << std::endl;

  std::vector<std::vector<std::string>> patterns(num_patterns,
                                                 std::vector<std::string>());
  for (int i = 0; i < num_patterns; i++) {
    int H = num_hammering_pairs.get_random_number();
    std::cout << "[+] Selected random params: H = " << H << ", ";
    int N = num_nops.get_random_number();
    std::cout << "N = " << N << std::endl;

    std::vector<std::string> Hs = gen_random_pairs(H);
    std::vector<std::string> Ns = gen_random_accesses(N);
    std::cout << "[+] Generated random pairs (#Hs: " << Hs.size()
              << ", #Ns: " << Ns.size() << ")" << std::endl;

    int accesses_counter = 0;
    auto get_remaining_accesses = [&]() -> int {
      return accesses_per_pattern - accesses_counter;
    };
    while (accesses_counter < accesses_per_pattern) {
      auto selection = rand() % 2;
      if (selection % 2 == 0) {
        // use a randomly picked hammering pair
        std::string pair = *select_randomly(Hs.begin(), Hs.end());

        std::stringstream result;
        int multiplicator = multiplicator_hammering_pairs.get_random_number(
            get_remaining_accesses() / 2);
        if (multiplicator == -1) {
          std::cout << "[-] Skipping choice and rolling the dice again."
                    << std::endl;
          continue;
        }
        accesses_counter += 2 * multiplicator;
        while (multiplicator--) {
          result << pair;
          result << " ";
        }
        // result.seekp(-1, std::ios_base::end);
        // result << "|";
        patterns[i].push_back(result.str());
      } else if (selection % 2 == 1) {
        // use a randomly picked nop
        std::string pair = *select_randomly(Ns.begin(), Ns.end());

        std::stringstream result;
        int multiplicator =
            multiplicator_nops.get_random_number(get_remaining_accesses());
        if (multiplicator == -1) {
          std::cout << "[-] Skipping choice and rolling the dice again."
                    << std::endl;
          continue;
        }
        accesses_counter += multiplicator;
        while (multiplicator--) {
          result << pair;
          result << " ";
        }
        // result << "|";
        // result.seekp(-1, std::ios_base::end);
        patterns[i].push_back(result.str());
      }
    }

    // print the recently generated pattern
    std::ostringstream vts;
    // Convert all but the last element to avoid a trailing ","
    std::copy(patterns[i].begin(), patterns[i].end() - 1,
              std::ostream_iterator<std::string>(vts, ""));
    vts << patterns[i].back();
    std::cout << "[+] Generated pattern (" << accesses_counter << "):\t\t\t\t"
              << vts.str() << std::endl;

    // TODO: determine how long the pattern should be, i.e., how many accesses
    //  by printing stats from n_sided_hammer
  }
}
