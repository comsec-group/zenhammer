#include "bs.h"
#include "Blacksmith.hpp"
#include "Fuzzer/FuzzingParameterSet.hpp"
#include "Fuzzer/PatternBuilder.hpp"
#include "Fuzzer/PatternAddressMapping.hpp"

extern "C" {
#include "rh_misc.h"
}


#include <iostream>

void bs_cpp() {
    printf("Hello from CPP!\n");
}
int bs_generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses) {
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

  printf("[%lu] [%s] new PatternBuilder()\n", misc_get_us(), __func__);
  PatternBuilder *pb = new PatternBuilder();
  printf("[%lu] [%s] new PatternBuilder() done\n", misc_get_us(), __func__);

  printf("[%lu] [%s] generate_frequency_based_pattern\n", misc_get_us(), __func__);
  pb->generate_frequency_based_pattern(fuzzing_params, accesses, agg_access_patterns);
  printf("[%lu] [%s] generate_frequency_based_pattern done\n", misc_get_us(), __func__);

  // choose random addresses for pattern
  printf("[%lu] [%s] mapping(true)\n", misc_get_us(), __func__);
  PatternAddressMapping mapping(true);
  printf("[%lu] [%s] mapping(true) done\n", misc_get_us(), __func__);

  printf("[%lu] [%s] randomize_addresses\n", misc_get_us(), __func__);
  mapping.randomize_addresses(fuzzing_params, agg_access_patterns);
  printf("[%lu] [%s] randomize_addresses done\n", misc_get_us(), __func__);

  if (max_accesses < (int)accesses.size()) {
    printf("[-] Exporting pattern failed! Given plain-C 'rows' array is too small to hold all accesses.");
    return -1;
  }

  printf("[%lu] [%s] export_pattern\n", misc_get_us(), __func__);
  mapping.export_pattern(accesses, fuzzing_params.get_base_period(), rows_to_access, max_accesses);
  printf("[%lu] [%s] export_pattern done\n", misc_get_us(), __func__);

  printf("[%lu] [%s] delete(pb)\n", misc_get_us(), __func__);
  delete(pb);
  printf("[%lu] [%s] delete(pb) done\n", misc_get_us(), __func__);

  return (int)accesses.size();
}
