#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

#include <string>

// number of repetitions we hammer the same pattern at the same location
int REPS_PER_PATTERN = 1;

int main(int argc, char **argv);

char *get_cmd_parameter(char **begin, char **end, const std::string &parameter_name);

bool cmd_parameter_exists(char **begin, char **end, const std::string &parameter_name);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
