#include <cstdio>
#include <cstdlib>
#include <cstring>

#pragma once

#define TERM_FC_RED "\033[0;31m"
#define TERM_FC_CYAN "\033[0;36m"
#define TERM_FC_GRAY "\033[0;37m"
#define TERM_F_RESET "\033[0m"

// Logging
extern bool log_verbose;
#define LOG(fstr, ...)                                                  \
    do {                                                                \
        fprintf(stdout, TERM_FC_CYAN fstr TERM_F_RESET, ##__VA_ARGS__); \
    } while (false)

#define LOG_ERROR(fstr, ...)                                           \
    do {                                                               \
        fprintf(stdout, TERM_FC_RED fstr TERM_F_RESET, ##__VA_ARGS__); \
    } while (false)

#define LOG_VERBOSE(fstr, ...)                                              \
    do {                                                                    \
        if (log_verbose) {                                                  \
            fprintf(stdout, TERM_FC_GRAY fstr TERM_F_RESET, ##__VA_ARGS__); \
        }                                                                   \
    } while (false)

#define BIT(x) (1ULL << size_t(x))

constexpr size_t MiB = (1ULL << 20);
constexpr size_t GiB = (1ULL << 30);

constexpr size_t SUPERPAGE_SHIFT = 30;
constexpr size_t SUPERPAGE = (1ULL << SUPERPAGE_SHIFT);
constexpr size_t SUPERPAGE_MASK = SUPERPAGE - 1;

inline size_t msb_set(size_t value) {
    constexpr size_t TOTAL_BITS = sizeof(size_t) * 8;
    size_t leading_zeros = __builtin_clzl(value);
    return TOTAL_BITS - leading_zeros - 1;
}

inline size_t lsb_set(size_t value) {
    return ffsll((long long)value);
}
