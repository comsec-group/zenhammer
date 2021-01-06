#ifndef BLACKSMITH_INCLUDE_UTILITIES_ENUMS_HPP_
#define BLACKSMITH_INCLUDE_UTILITIES_ENUMS_HPP_

enum class FLUSHING_STRATEGY {
  // flush an accessed aggressor as soon as it has been accessed (i.e., pairs are flushed in-between)
  EARLIEST_POSSIBLE
};

std::string get_string(FLUSHING_STRATEGY strategy);

enum class FENCING_STRATEGY {
  // add the fence right before the next access of the aggressor if it has been flushed before
  LATEST_POSSIBLE,
  // do not fence before accessing an aggressor even if it has been accessed before
  OMIT_FENCING
};

std::string get_string(FENCING_STRATEGY strategy);

#endif //BLACKSMITH_INCLUDE_UTILITIES_ENUMS_HPP_
