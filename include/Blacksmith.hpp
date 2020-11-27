#ifndef BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
#define BLACKSMITH_INCLUDE_BLACKSMITH_HPP_

int main(int argc, char **argv);

void print_metadata();

size_t count_acts_per_ref(std::vector<std::vector<volatile char *>> &banks);

#endif //BLACKSMITH_INCLUDE_BLACKSMITH_HPP_
