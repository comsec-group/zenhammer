#include "Utilities/Enums.hpp"

#include <string>
#include <map>
#include <Utilities/Range.hpp>

std::string get_string(FLUSHING_STRATEGY strategy) {
  std::map<FLUSHING_STRATEGY, std::string> map =
      {
          {FLUSHING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"},
          {FLUSHING_STRATEGY::LATEST_POSSIBLE, "LATEST_POSSIBLE"}
      };
  return map.at(strategy);
}

std::string get_string(FENCING_STRATEGY strategy) {
  std::map<FENCING_STRATEGY, std::string> map =
      {
          {FENCING_STRATEGY::LATEST_POSSIBLE, "LATEST_POSSIBLE"},
          {FENCING_STRATEGY::EARLIEST_POSSIBLE, "EARLIEST_POSSIBLE"},
          {FENCING_STRATEGY::OMIT_FENCING, "OMIT_FENCING"}
      };
  return map.at(strategy);
}

std::pair<FLUSHING_STRATEGY, FENCING_STRATEGY> get_valid_strategies() {
  std::vector<std::pair<FLUSHING_STRATEGY, FENCING_STRATEGY>> valid_strategies = {
      std::make_pair(FLUSHING_STRATEGY::EARLIEST_POSSIBLE, FENCING_STRATEGY::OMIT_FENCING),
      std::make_pair(FLUSHING_STRATEGY::EARLIEST_POSSIBLE, FENCING_STRATEGY::LATEST_POSSIBLE),
      std::make_pair(FLUSHING_STRATEGY::LATEST_POSSIBLE, FENCING_STRATEGY::LATEST_POSSIBLE),
  };

  auto num_strategies = valid_strategies.size();
  std::random_device rd;
  std::mt19937 gen(rd());
  auto strategy_idx = Range<int>(0, num_strategies-1).get_random_number(gen);
  return valid_strategies.at(strategy_idx);
}
