#include "bs.h"
#if 0
#include "Blacksmith.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/HammeringPattern.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/PatternAddressMapping.hpp"
#endif


#include <iostream>

void bs_cpp() {
    printf("Hello from CPP!\n");
}
void bs_generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses) {
    printf("[%s]\n", __func__);

    for (int i = 0; i < max_accesses; i++) {
        rows_to_access[i] = 0;
    }
#if 0
  FuzzingParameterSet fuzzing_params(acts);
  fuzzing_params.print_static_parameters();

  printf("Hoi\n");
  printf("[+] Randomizing fuzzing parameters.\n");
  fuzzing_params.randomize_parameters(true);

  if (trials_per_pattern > 1 && trials_per_pattern < MAX_TRIALS_PER_PATTERN) {
    trials_per_pattern++;
  } else {
    trials_per_pattern = 0;
    hammering_pattern = HammeringPattern(fuzzing_params.get_base_period());
  }

  printf("[+] Generating ARM hammering pattern %s.\n", hammering_pattern.instance_id.c_str());
  PatternBuilder pattern_builder(hammering_pattern);
  pattern_builder.generate_frequency_based_pattern(fuzzing_params);

  // choose random addresses for pattern
  PatternAddressMapping mapping(true);
  mapping.randomize_addresses(fuzzing_params, hammering_pattern.agg_access_patterns);
  mapping.export_pattern(hammering_pattern.accesses, hammering_pattern.base_period, rows_to_access, max_accesses);
#endif
}
