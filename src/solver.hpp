#include "function.hpp"
#include <cstdint>
#include <cstdlib>
#include <vector>

#pragma once

class solver {
public:
    explicit solver(std::vector<std::vector<uintptr_t>> clusters)
        : m_clusters_phys(std::move(clusters)) {
    }

    [[nodiscard]] std::vector<func_t> find_bank_functions(size_t phys_dram_offset) const;

    void find_bank_functions_automatic() const;

private:
    std::vector<std::vector<uintptr_t>> m_clusters_phys;
};
