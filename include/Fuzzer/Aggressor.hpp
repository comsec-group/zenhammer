#ifndef AGGRESSOR
#define AGGRESSOR

#include <sstream>
#include <iomanip>
#include <nlohmann/json.hpp>

#include "DRAMAddr.hpp"

const int ID_PLACEHOLDER_AGG = -1;

typedef int AGGRESSOR_ID_TYPE;

class Aggressor {
 public:
  AGGRESSOR_ID_TYPE id;

  // default constructor: required to enable vector initialization
  Aggressor() : id(ID_PLACEHOLDER_AGG) {};

  // creates a new Aggressor; the caller must ensure that the ID is valid
  explicit Aggressor(int id) : id(id) {}

  std::string to_string() const;
};

void to_json(nlohmann::json &j, const Aggressor &p);

void from_json(const nlohmann::json &j, Aggressor &p);

#endif /* AGGRESSOR */
