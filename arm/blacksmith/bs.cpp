#include "bs.h"
#include "Blacksmith.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/PatternAddressMapping.hpp"


#include <iostream>

void bs_cpp() {
    printf("Hello from CPP!\n");
}
void bs_generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses) {
  for (int i = 0; i < max_accesses; i++) {
    rows_to_access[i] = 0;
  }

  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

  printf("[+] Randomizing fuzzing parameters.\n");
  fuzzing_params.randomize_parameters(true);

  if (trials_per_pattern > 1 && trials_per_pattern < MAX_TRIALS_PER_PATTERN) {
    trials_per_pattern++;
    accesses.clear();
  } else {
    trials_per_pattern = 0;
    accesses.clear();
    agg_access_patterns.clear();
  }

  printf("[+] Generating ARM hammering pattern...\n");
  PatternBuilder *pb = new PatternBuilder();

  pb->generate_frequency_based_pattern(fuzzing_params, accesses, agg_access_patterns);

  // choose random addresses for pattern
  PatternAddressMapping mapping(true);
  mapping.randomize_addresses(fuzzing_params, agg_access_patterns);
  mapping.export_pattern(accesses, fuzzing_params.get_base_period(), rows_to_access, max_accesses);

  delete(pb);
}
