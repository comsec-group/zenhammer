#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/HammeringPattern.hpp"


HammeringPattern::HammeringPattern(size_t base_period) : instance_id(0), base_period(base_period) {}
