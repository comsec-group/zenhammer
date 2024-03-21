#include <cstdint>

#include "pagemap.hpp"
#include "utils.hpp"

constexpr size_t PAGE_OFFSET_BITS = 12;
constexpr uintptr_t PAGE_OFFSET_MASK = (uintptr_t(1) << PAGE_OFFSET_BITS) - 1;
constexpr uint64_t PFN_MASK = (uint64_t(1) << 55) - 1;

static FILE* pagemap_fp;

uintptr_t pagemap::virt_to_phys(void* virt_addr) {
    size_t vpn = (uintptr_t)virt_addr >> PAGE_OFFSET_BITS;

    if (!pagemap_fp) {
        pagemap_fp = fopen("/proc/self/pagemap", "rb");
        if (!pagemap_fp) {
            perror("fopen (pagemap)");
            exit(1);
        }
    }

    // There is 1 64-bit value for each VPN.
    size_t offset = vpn * sizeof(uint64_t);

    if (fseek(pagemap_fp, offset, SEEK_SET) < 0) {
        perror("fseek (pagemap)");
        exit(1);
    }

    uint64_t info;
    if (fread(&info, sizeof(uint64_t), 1, pagemap_fp) < 1) {
        perror("fread (pagemap)");
        exit(1);
    }

    uint64_t pfn = info & PFN_MASK;

    if (pfn == 0) {
        LOG_ERROR("Error: PFN is zero, please run as superuser.\n");
        exit(1);
    }

    uintptr_t phys_addr = (pfn << PAGE_OFFSET_BITS) | (uintptr_t(virt_addr) & PAGE_OFFSET_MASK);
    return phys_addr;
}
