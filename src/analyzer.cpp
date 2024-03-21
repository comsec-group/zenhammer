#include "sched.h"
#include "x86intrin.h"
#include <algorithm>
#include <cassert>
#include <cmath>
#include <cstdio>
#include <limits>
#include <list>
#include <vector>

#include "analyzer.hpp"
#include "assembly.hpp"
#include "config.hpp"

// Measurements as described in section 3.2.1 of the Intel "How to Benchmark
// Code Execution Times" whitepaper:
// https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
static uint64_t dare_time(uint8_t* first, uint8_t* second) {
    auto* f = (volatile uint8_t*)first;
    auto* s = (volatile uint8_t*)second;

    uint64_t min_cycles = std::numeric_limits<uint64_t>::max();

    for (size_t i = 0; i < DARE_ITERATIONS; i++) {
        // before measurement: CPUID + RDTSC
        assembly::cpuid();
        auto start = assembly::rdtsc();
        _mm_lfence();

        for (size_t j = 0; j < DARE_ACCESSES_PER_ITER; j++) {
            _mm_clflush((void*)f);
            _mm_clflush((void*)s);
            // clflush is only serialized by mfence, not lfence or sfence
            _mm_mfence();

            *f;
            *s;
        }

        // after measurement: RDTSCP + CPUID
        auto stop = assembly::rdtscp();
        assembly::cpuid();

        auto cycles = (stop - start) / DARE_ACCESSES_PER_ITER;
        if (cycles < min_cycles) {
            min_cycles = cycles;
        }
    }

    return min_cycles;
}

analyzer::analyzer(size_t num_superpages) {
    m_memory.allocate(num_superpages);
}

void analyzer::find_row_conflict_threshold(size_t num_clusters, std::optional<std::string> const& out_file) {
    constexpr size_t NUM_SAMPLES = 32 * 1024;
    std::vector<uint64_t> samples;
    samples.reserve(NUM_SAMPLES);

    LOG("[analyzer] Determining row conflict threshold using %zu samples...\n", NUM_SAMPLES);

    for (size_t i = 0; i < NUM_SAMPLES; i++) {
        auto* first = m_memory.get_random_address();
        auto* second = m_memory.get_random_address();
        auto delta = dare_time(first, second);
        samples.push_back(delta);
    }

    std::sort(samples.begin(), samples.end());

    if (out_file.has_value()) {
        // Write access times to output file.
        FILE* fp = fopen(out_file->c_str(), "w");
        if (!fp) {
            perror("fopen");
            LOG_ERROR("[analyzer] Error: Could not open out file '%s' for writing.\n", out_file->c_str());
            exit(EXIT_FAILURE);
        }

        for (auto const& sample : samples) {
            fprintf(fp, "%lu\n", sample);
        }

        if (fclose(fp) != 0) {
            perror("close");
            LOG_ERROR("[analyzer] Error: Could not close out file '%s'.\n", out_file->c_str());
        }

        LOG("[analyzer] Wrote %zu histogram samples to '%s'.\n", samples.size(), out_file->c_str());
    }

    LOG_VERBOSE("[analyzer] Cycles times are between %zu and %zu.\n", samples.front(), samples.back());

    LOG_VERBOSE("[analyzer] Making sure 1 in %zu (number of clusters) measurements is above threshold...\n", num_clusters);
    assert(num_clusters > 1);
    auto num_above_threshold = samples.size() / num_clusters;
    m_row_conflict_threshold = samples[samples.size() - num_above_threshold];

    LOG("[analyzer] Found row conflict threshold to be %zu cycles.\n", m_row_conflict_threshold);
}

void analyzer::clean_cluster(std::vector<uint8_t*>& cluster) const {
    LOG_VERBOSE("[analyzer] Cleaning cluster...\n");
    auto initial_size = cluster.size();
    bool removed_addr = false;

    do {
        removed_addr = false;
        // Check every address in a cluster against all other addresses in the cluster.
        for (size_t i = 0; i < cluster.size(); i++) {
            size_t passed = 0;
            for (size_t j = 0; j < cluster.size(); j++) {
                if (i == j) {
                    continue;
                }
                if (has_row_conflict(cluster[i], cluster[j])) {
                    passed++;
                }
            }
            auto passed_percentage = 100.0 * (double)passed / (double)cluster.size();
            constexpr double PASS_PERCENTAGE_THRESHOLD = 75.0;
            if (passed_percentage < PASS_PERCENTAGE_THRESHOLD) {
                LOG_VERBOSE("[analyzer] Address %p passed only %.1f%% (less then %.1f%%) of tests, removing.\n",
                    cluster[i], passed_percentage, PASS_PERCENTAGE_THRESHOLD);
                cluster.erase(cluster.begin() + i);
                // Start over.
                removed_addr = true;
                break;
            }
        }
    } while (removed_addr);

    LOG("[analyzer] Cleaned cluster, removed %zu addresses (out of %zu).\n", initial_size - cluster.size(), initial_size);
}

void analyzer::build_clusters(size_t num_clusters) {
    assert(m_clusters.empty());

    constexpr size_t NUM_ADDRS_PER_CLUSTER = 64;
    auto address_pool_size = NUM_ADDRS_PER_CLUSTER * num_clusters;
    LOG("[analyzer] Building %zu clusters out of address pool with %zu addresses.\n", num_clusters, address_pool_size);

    // Build address pool.
    std::list<uint8_t*> address_pool;
    for (size_t i = 0; i < address_pool_size; i++) {
        address_pool.push_back(m_memory.get_random_address());
    }

    size_t total_addrs_in_clusters = 0;
    std::vector<std::vector<uint8_t*>> clusters_virt;

    while (clusters_virt.size() < num_clusters) {
        if (address_pool.empty()) {
            LOG_ERROR("[analyzer] No more addresses in pool after building %zu clusters. Cannot continue. "
                      "Is the number of clusters correct?\n",
                clusters_virt.size());
            exit(EXIT_FAILURE);
        }

        std::vector<uint8_t*> cluster;

        uint8_t* needle = address_pool.back();
        address_pool.pop_back();

        LOG_VERBOSE("[analyzer] Testing needle %p against all addresses in pool...\n", needle);

        // Test `needle` against all addresses in the pool.
        auto it = address_pool.begin();
        while (it != address_pool.end()) {
            if (has_row_conflict(needle, *it)) {
                // These belong to the same cluster.
                sched_yield();
                sched_yield();
                if (has_row_conflict(needle, *it)) {
                    cluster.push_back(*it);
                    address_pool.erase(it++);
                } else {
                    ++it;
                }
            } else {
                ++it;
            }
        }

        if (cluster.size() < NUM_ADDRS_PER_CLUSTER / 3) {
            LOG("[analyzer] Cluster %zu only has %zu addresses, retrying...\n", clusters_virt.size(), cluster.size());
            continue;
        }

        LOG_VERBOSE("[analyzer] Cluster %zu has %zu addresses (%zu still in pool)\n", clusters_virt.size(), cluster.size(), address_pool.size());

        total_addrs_in_clusters += cluster.size();
        clusters_virt.push_back(std::move(cluster));

        auto avg_addrs_per_cluster = (double)total_addrs_in_clusters / (double)clusters_virt.size();
        LOG_VERBOSE("    average addresses per cluster: %.1f\n", avg_addrs_per_cluster);
        LOG_VERBOSE("    predicted number of clusters: %ld\n", std::lround(address_pool_size / avg_addrs_per_cluster));
    }

    LOG("[analyzer] Built %zu clusters. Cleaning clusters...\n", clusters_virt.size());
    for (auto& cluster : clusters_virt) {
        clean_cluster(cluster);
    }

    LOG("[analyzer] Converting clusters to physical addresses.\n");

    // Now, convert to physical addresses.
    for (auto& cluster_virt : clusters_virt) {
        m_clusters.emplace_back();
        for (auto* addr_virt : cluster_virt) {
            auto addr_phys = m_memory.virt_to_phys(addr_virt);
            m_clusters.back().push_back(addr_phys);
        }
    }

    LOG("[analyzer] Cluster generation finished.\n");
}

bool analyzer::has_row_conflict(uint8_t* first, uint8_t* second) const {
    return dare_time(first, second) > m_row_conflict_threshold;
}

void analyzer::dump_clusters(const std::string& out_file) {
    if (m_clusters.empty()) {
        LOG_ERROR("[analyzer] Error: Cannot dump clusters to file, as there are no clusters.\n");
        exit(EXIT_FAILURE);
    }

    FILE* fp = fopen(out_file.c_str(), "w");
    if (!fp) {
        perror("fopen");
        LOG_ERROR("[analyzer] Error: Could not open out file '%s' for writing.\n", out_file.c_str());
        exit(EXIT_FAILURE);
    }

    for (auto const& cluster : m_clusters) {
        for (size_t i = 0; i < cluster.size(); i++) {
            if (i != 0) {
                fputc(';', fp);
            }
            fprintf(fp, "%p", (void*)cluster[i]);
        }
        fputc('\n', fp);
    }

    if (fclose(fp) != 0) {
        perror("close");
        LOG_ERROR("[analyzer] Error: Could not close out file '%s'.\n", out_file.c_str());
    }

    LOG("[analyzer] Wrote %zu clusters to '%s'.\n", m_clusters.size(), out_file.c_str());
}
