#ifndef AGGRESSOR
#define AGGRESSOR

#include <sstream>
#include <iomanip>

#include "DRAMAddr.hpp"

const int ID_PLACEHOLDER_AGG = -1;

typedef int AGGRESSOR_ID_TYPE;

class Aggressor {
 public:
  AGGRESSOR_ID_TYPE id;

  // default constructor: required to enable vector initialization
  Aggressor() : id(ID_PLACEHOLDER_AGG){};

  // creates a new Aggressor; the caller must ensure that the ID is valid
  explicit Aggressor(int id) : id(id) {}

  std::string to_string() const {
    if (id == ID_PLACEHOLDER_AGG) return "EMPTY";
    std::stringstream ss;
    ss << "agg" << std::setfill('0') << std::setw(2) << id;
    return ss.str();
  }
};

#endif /* AGGRESSOR */
