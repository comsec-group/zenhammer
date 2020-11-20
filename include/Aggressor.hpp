#ifndef AGGRESSOR
#define AGGRESSOR

#include "DRAMAddr.hpp"

const int ID_PLACEHOLDER_AGG = -1;

class Aggressor {
 public:
  int id;

  Aggressor() : id(ID_PLACEHOLDER_AGG) {};

  Aggressor(int id) : id(id) {
  }

  std::string to_string() {
    std::stringstream ss;
    ss << "agg" << std::setfill('0') << std::setw(3) << id;
    return ss.str();
  }
};

// class AggressorAccess {
//  public:
//   int frequency;

//   int offset_start;

//   int amplitude;

//   int N_sided;

//   std::vector<DRAMAddr> aggressors;

//   // TODO: Ensure that always aggressors.size() < N.sided

//   std::string get_id() {
//     std::stringstream ss;
//     ss << "(";
//     for (size_t i = 0; i < aggressors.size(); ++i) {
//       ss << "agg" << id + i;
//       if (i + 1 < aggressors.size()) ss << " ";
//     }
//     ss << ")";
//     return ss.str();
//   }
// };

#endif /* AGGRESSOR */
