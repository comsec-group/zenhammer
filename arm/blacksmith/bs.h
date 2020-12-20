#ifndef BS_H__
#define BS_H__

#ifdef __cplusplus
extern "C" {
#endif

void bs_cpp();

int bs_generate_pattern_for_ARM(int acts, int *rows_to_access, int max_accesses);

#ifdef __cplusplus
}
#endif

#endif
