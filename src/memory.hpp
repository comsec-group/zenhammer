#include <cstdint>
#include <cstdlib>
#include <vector>

#pragma once

class memory {
public:
    memory() = default;
    ~memory();

    void allocate(size_t num_superpages);

    [[nodiscard]] uint8_t* get_random_address() const;

    [[nodiscard]] uintptr_t virt_to_phys(uint8_t*) const;
    [[nodiscard]] uint8_t* phys_to_virt(uintptr_t) const;

    [[nodiscard]] uint8_t* ptr() const { return m_ptr; }
    [[nodiscard]] size_t size() const { return m_size; }

private:
    uint8_t* m_ptr { nullptr };
    size_t m_size { 0 };
    std::vector<std::pair<uint8_t*, uintptr_t>> m_virt_phys_mappings;
};