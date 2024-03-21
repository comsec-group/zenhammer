#include <cassert>

#include "solver.hpp"

// Returns 0 or 1 if the function was "constant enough" over the cluster, else -1.
static int apply_function_to_cluster(func_t func, std::vector<uintptr_t> const& cluster) {
    size_t num_ones = 0;
    for (auto addr : cluster) {
        num_ones += func_apply(func, addr);
    }
    auto threshold = BRUTE_FORCE_PASS_THRESHOLD_PERCENTAGE * cluster.size() / 100;
    if (num_ones >= threshold) {
        return 1;
    }
    auto num_zeros = cluster.size() - num_ones;
    if (num_zeros >= threshold) {
        return 0;
    }
    return -1;
}

static bool function_is_feasible(func_t function, std::vector<std::vector<uintptr_t>> const& clusters) {
    // 1. Check if function is "constant enough" over all addresses in one cluster.
    auto first_cluster_result = apply_function_to_cluster(function, clusters.front());
    if (first_cluster_result < 0) {
        // Function not "constant enough" over the first cluster.
        return false;
    }

    // 2. Check if function is "constant enough" in all clusters.
    size_t clusters_with_result_one = 0;
    for (auto const& cluster : clusters) {
        auto result_for_cluster = apply_function_to_cluster(function, cluster);
        if (result_for_cluster < 0) {
            // The function is not constant over this cluster.
            return false;
        }

        assert(result_for_cluster == 0 || result_for_cluster == 1);
        clusters_with_result_one += result_for_cluster;
    }

    if (clusters_with_result_one * 2 == clusters.size()) {
        return true;
    }

    if (clusters_with_result_one == 0 || clusters_with_result_one == clusters.size()) {
        // This is nothing special, just ignore it.
    } else {
        LOG("[solver] %zu of %zu clusters had result 1 (function 0x%010lx)\n", clusters_with_result_one, clusters.size(), function);
    }
    return false;
}

std::vector<func_t> solver::find_bank_functions(size_t phys_dram_offset) const {
    // Create copy of clusters that takes offset into account.
    std::vector<std::vector<uintptr_t>> clusters_with_offset;
    for (auto const& cluster : m_clusters_phys) {
        clusters_with_offset.emplace_back();
        clusters_with_offset.back().reserve(cluster.size());
        for (auto addr : cluster) {
            clusters_with_offset.back().push_back(addr - phys_dram_offset);
        }
    }

    // Find MSB that is non-constant over all addresses.
    size_t msb_considered = SUPERPAGE_SHIFT;
    while (msb_considered < 8 * sizeof(void*) - 1) {
        auto first_value = (clusters_with_offset.front().front() & BIT(msb_considered)) > 0;
        bool have_different = false;
        for (auto const& cluster : clusters_with_offset) {
            for (auto addr : cluster) {
                auto value = (addr & BIT(msb_considered)) > 0;
                if (value != first_value) {
                    have_different = true;
                    break;
                }
            }
            if (have_different) {
                break;
            }
        }
        if (!have_different) {
            // This bit is always the same. We should only consider bits up to previous one.
            msb_considered--;
            break;
        }
        msb_considered++;
    }
    auto lsb_considered = BRUTE_FORCE_LSB;
    LOG_VERBOSE("Considering only functions with bits in range [%zu, %zu].\n", lsb_considered, msb_considered);

    std::vector<func_t> functions;
    for (size_t num_bits = 1; num_bits <= BRUTE_FORCE_MAX_BITS; num_bits++) {
        auto candidate = func_first_permutation(num_bits, msb_considered, lsb_considered);
        auto last_candidate = func_last_permutation(num_bits, msb_considered, lsb_considered);

        LOG_VERBOSE("[solve] Brute-forcing functions with %zu bits...\n", num_bits);

        while (true) {
            if (function_is_feasible(candidate, clusters_with_offset)) {
                functions.push_back(candidate);

                // Check the functions are still linearly independent.
                if (!func_are_linearly_independent(functions)) {
                    functions.pop_back();
                }
            }
            if (candidate == last_candidate) {
                break;
            }
            candidate = func_next_permutation(candidate);
        }
    }

    printf("Found %zu functions (up to %zu bits):\n", functions.size(), BRUTE_FORCE_MAX_BITS);

    if (!functions.empty()) {
        func_t all_xored = 0;
        for (auto func : functions) {
            all_xored ^= func;
            func_print(func);
        }

        printf("XOR of all found functions:\n");
        func_print(all_xored);
    }

    return functions;
}

void solver::find_bank_functions_automatic() const {
    // As we expect this offset to only exist above 4 GiB, it makes sense that the offset itself is 4 GiB at most.
    constexpr size_t PHYS_DRAM_OFFSET_MAX = 4 * GiB;
    // This value is chosen experimentally.
    constexpr size_t PHYS_DRAM_OFFSET_STEP = 256 * MiB;

    for (size_t phys_dram_offset = 0; phys_dram_offset <= PHYS_DRAM_OFFSET_MAX; phys_dram_offset += PHYS_DRAM_OFFSET_STEP) {
        LOG("[solver] Solving for bank functions with phys_dram_offset = %zu MiB\n", phys_dram_offset / MiB);
        auto functions = find_bank_functions(phys_dram_offset);
        LOG("[solver] Found %zu functions.\n", functions.size());
    }
}
