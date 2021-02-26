#ifndef AGGRESSOR
#define AGGRESSOR

#include <sstream>
#include <iomanip>

#ifdef ENABLE_JSON
#include <nlohmann/json.hpp>
#endif

#include "Memory/DRAMAddr.hpp"

const int ID_PLACEHOLDER_AGG = -1;

typedef int AGGRESSOR_ID_TYPE;

class Aggressor {
 public:
  AGGRESSOR_ID_TYPE id = ID_PLACEHOLDER_AGG;

  // default constructor: required to enable vector initialization
  Aggressor() = default;

  // creates a new Aggressor; the caller must ensure that the ID is valid
  explicit Aggressor(int id);

  std::string to_string() const;

  static std::vector<AGGRESSOR_ID_TYPE> get_agg_ids(const std::vector<Aggressor> &aggressors);

  static std::vector<Aggressor> create_aggressors(const std::vector<AGGRESSOR_ID_TYPE> &agg_ids);
};

#ifdef ENABLE_JSON

void to_json(nlohmann::json &j, const Aggressor &p);

void from_json(const nlohmann::json &j, Aggressor &p);

#endif

#endif /* AGGRESSOR */
