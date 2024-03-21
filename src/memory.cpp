#include "sys/mman.h"
#include <cassert>
#include <random>

#include "memory.hpp"
#include "pagemap.hpp"
#include "utils.hpp"

// Defined as described in man mmap(2).
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)

memory::~memory() {
    if (m_ptr) {
        if (munmap(m_ptr, m_size) < 0) {
            perror("munmap");
            LOG("[memory] munmap() failed.\n");
        }
    }
}

void memory::allocate(size_t num_superpages) {
    assert(m_ptr == nullptr && m_size == 0);

    m_size = num_superpages * SUPERPAGE;
    LOG("[memory] Allocating %zu superpages (%zu bytes) of memory...\n", num_superpages, m_size);

    auto mmap_prot = PROT_READ | PROT_WRITE;
    auto mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB | MAP_HUGE_1GB;

    m_ptr = (uint8_t*)mmap(nullptr, m_size, mmap_prot, mmap_flags, -1, 0);

    if (m_ptr == MAP_FAILED) {
        m_ptr = nullptr;
        perror("mmap");
        LOG("[memory] Allocation using mmap() failed. Are 1 GB superpages enabled?\n");
        exit(1);
    }

    if (mlock(m_ptr, m_size) < 0) {
        perror("mlock");
        LOG("[allocate] Could not mlock() the allocation. Superuser privileges are required for this.\n");
        exit(1);
    }

    LOG_VERBOSE("[memory] Populating virtual-to-physical mappings.\n");
    for (size_t offset = 0; offset < m_size; offset += SUPERPAGE) {
        auto* virt_base = m_ptr + offset;
        auto phys_base = pagemap::virt_to_phys(virt_base);
        m_virt_phys_mappings.emplace_back(virt_base, phys_base);
        LOG_VERBOSE("    %p -> %p\n", virt_base, (void*)phys_base);
    }
    assert(m_virt_phys_mappings.size() == num_superpages);
}

uint8_t* memory::get_random_address() const {
    assert(m_ptr != nullptr && m_size > 0);

    static std::random_device rd;
    static std::default_random_engine generator(rd());
    static std::uniform_int_distribution<size_t> distribution(0, m_size - 1);

    size_t offset = distribution(generator);
    return m_ptr + offset;
}

uintptr_t memory::virt_to_phys(uint8_t* virt) const {
    auto offset = (size_t)virt & SUPERPAGE_MASK;
    auto virt_base = virt - offset;

    // Determine phys_base by searching through m_virt_phys_mappings.
    uintptr_t phys_base = -1;
    for (auto& [superpage_virt, superpage_phys] : m_virt_phys_mappings) {
        if (virt_base == superpage_virt) {
            phys_base = superpage_phys;
            break;
        }
    }
    assert(phys_base != (uintptr_t)-1);

    return phys_base + offset;
}

uint8_t* memory::phys_to_virt(uintptr_t phys) const {
    auto offset = (size_t)phys & SUPERPAGE_MASK;
    auto phys_base = phys - offset;

    // Determine virt_base by searching through m_virt_phys_mappings.
    auto virt_base = (uint8_t*)-1;
    for (auto& [superpage_virt, superpage_phys] : m_virt_phys_mappings) {
        if (phys_base == superpage_phys) {
            virt_base = superpage_virt;
            break;
        }
    }
    assert(virt_base != (uint8_t*)-1);

    return virt_base + offset;
}