#include <array>
#include <cstdint>
#include <cstdio>
#include <numeric>
#include <vector>

#include "config.hpp"
#include "utils.hpp"

#pragma once

using bin_t = uint8_t;
using func_t = size_t;
constexpr size_t FUNC_NUM_BITS = 8 * sizeof(func_t);

[[maybe_unused]] static void func_print(func_t func) {
    printf("0x%010zx (", func);

    bool first = true;
    for (ssize_t i = FUNC_NUM_BITS - 1; i >= 0; i--) {
        size_t coeff = (func >> i) & 1;
        if (coeff) {
            if (!first) {
                putchar(' ');
            }
            first = false;
            printf("%zd", i);
        }
    }
    printf(")\n");
}

[[maybe_unused]] static void func_print_bits(func_t func) {
    printf("MSB -> LSB:");
    for (ssize_t i = FUNC_NUM_BITS - 1; i >= 0; i--) {
        size_t coeff = (func >> i) & 1;
        printf(" %zu", coeff);
    }
    printf("\n");
}

[[maybe_unused]] static void func_print_coeffs(func_t func) {
    printf("Set coeffs:");
    for (ssize_t i = FUNC_NUM_BITS - 1; i >= 0; i--) {
        size_t coeff = (func >> i) & 1;
        if (coeff) {
            printf(" %zd", i);
        }
    }
    printf("\n");
}

[[maybe_unused]] static uint8_t func_apply(func_t func, uintptr_t addr) {
    return __builtin_parityll(func & (uintptr_t)addr);
}

[[maybe_unused]] static func_t func_set_bit(func_t func, size_t bit_idx) {
    return func | (func_t(1) << bit_idx);
}

[[maybe_unused]] static func_t func_clear_bit(func_t func, size_t bit_idx) {
    return func & ~(func_t(1) << bit_idx);
}

[[maybe_unused]] static func_t func_first_permutation(size_t num_bits, size_t msb_considered, size_t lsb_considered) {
    (void)msb_considered;
    return ((1ULL << num_bits) - 1) << lsb_considered;
}

[[maybe_unused]] static func_t func_last_permutation(size_t num_bits, size_t msb_considered, size_t lsb_considered) {
    (void)lsb_considered;
    return ((1ULL << num_bits) - 1) << (msb_considered + 1 - num_bits);
}

// https://graphics.stanford.edu/~seander/bithacks.html#NextBitPermutation
[[maybe_unused]] static func_t func_next_permutation(func_t current) {
    func_t t, v, w;
    v = current;
    t = v | (v - 1); // t gets v's least significant 0 bits set to 1
    // Next set to 1 the most significant bit to change,
    // set to 0 the least significant ones, and add the necessary 1 bits.
    w = (t + 1) | (((~t & -~t) - 1) >> (__builtin_ctzl(v) + 1));
    return w;
}

[[maybe_unused]] static bool func_are_linearly_independent(std::vector<func_t> funcs) {
    // Do Gaussian elimination in GF(2). If at the end, there is still full
    // rank, the functions are linearly independent.

    size_t rank = 0;
    for (ssize_t bit = 8 * sizeof(func_t) - 1; bit >= 0; bit--) {
        // Find the pivot row for this column.
        size_t pivot = -1;
        for (size_t i = rank; i < funcs.size(); i++) {
            if (funcs[i] & BIT(bit)) {
                pivot = i;
                break;
            }
        }

        if (pivot == (size_t)-1) {
            // No row has this bit set.
            continue;
        }

        // Swap rows.
        std::swap(funcs[rank], funcs[pivot]);

        // Now, funcs[rank] has this bit set.

        for (size_t i = rank + 1; i < funcs.size(); i++) {
            if (funcs[i] & BIT(bit)) {
                // Unset the bit by XOR-ing this row with row 0.
                funcs[i] ^= funcs[rank];
            }
        }

        rank++;

        if (rank == funcs.size()) {
            break;
        }
    }

    return rank == funcs.size();
}
