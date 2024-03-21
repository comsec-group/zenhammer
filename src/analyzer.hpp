#include <optional>
#include <string>

#include "function.hpp"
#include "memory.hpp"
#include "utils.hpp"

#pragma once

class analyzer {
public:
    explicit analyzer(size_t num_superpages);

    void find_row_conflict_threshold(size_t num_clusters, std::optional<std::string> const& out_file = {});
    void set_row_conflict_threshold(uint64_t threshold) {
        LOG_VERBOSE("[analyzer] Setting row conflict threshold to %zu.\n", threshold);
        m_row_conflict_threshold = threshold;
    }

    void build_clusters(size_t num_clusters);

    [[nodiscard]] std::vector<std::vector<uintptr_t>> const& clusters() const { return m_clusters; }

    void dump_clusters(std::string const& out_file);

private:
    [[nodiscard]] bool has_row_conflict(uint8_t* first, uint8_t* second) const;
    void clean_cluster(std::vector<uint8_t*>& cluster) const;

    memory m_memory;
    uint64_t m_row_conflict_threshold { 0 };
    std::vector<std::vector<uintptr_t>> m_clusters;
};
