#ifndef BLACKSMITH_CONFLICTCLUSTER_H
#define BLACKSMITH_CONFLICTCLUSTER_H

#include <cstdlib>
#include <unordered_map>
#include <string>

class SimpleDramAddress {
public:
    size_t bank_id;
    size_t row_id;
    volatile char* vaddr;
    volatile char* paddr;

    SimpleDramAddress(size_t bank_id, size_t row_id, volatile char* vaddr, volatile char* paddr)
        : bank_id(bank_id), row_id(row_id), vaddr(vaddr), paddr(paddr) {};
public:
    SimpleDramAddress() = default;
};

class ConflictCluster {
private:
    std::unordered_map<size_t, std::unordered_map<size_t, SimpleDramAddress>> cluster;

public:
    void load_conflict_cluster(const std::string& filepath);

    SimpleDramAddress get_next_row(SimpleDramAddress &addr);

    SimpleDramAddress get_nth_next_row(SimpleDramAddress &addr, size_t nth);
};

#endif //BLACKSMITH_CONFLICTCLUSTER_H
