#include "Memory/ConflictCluster.hpp"
#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <iostream>

void ConflictCluster::load_conflict_cluster(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open())
        throw std::runtime_error("[-] could not open file " + filename);

    std::string last_bank_id;
    size_t row_id_cnt = 0;

    std::string line;
    while (std::getline(file, line, '\n')) {
        std::cout << "line: " << line << std::endl;

        std::istringstream iss(line);
        std::string item;
        std::vector<std::string> items;
        while (std::getline(iss, item, ',')) {
            std::cout << "item: " << item << std::endl;
            items.push_back(item);
            item.clear();
        }

        if (items[0] != last_bank_id && !last_bank_id.empty())
            row_id_cnt = 0;

        SimpleDramAddress addr{};
        addr.bank_id = (size_t)atoll(items[0].c_str());
        addr.row_id = row_id_cnt;
        addr.vaddr = (volatile char*)strtoull((const char *) items[1].c_str(), nullptr, 16);
        addr.paddr = (volatile char*)strtoull((const char *) items[2].c_str(), nullptr, 0);

        cluster[addr.bank_id][addr.row_id] = addr;

//        std::cout
//            << addr.bank_id << " "
//            << addr.row_id << " "
//            << std::hex << "0x" << (uint64_t)addr.vaddr << " "
//            << std::hex << "0x" << (uint64_t)addr.paddr
//            << std::endl;

        row_id_cnt++;
        last_bank_id = items[0];

        line.clear();
    }
}

SimpleDramAddress ConflictCluster::get_next_row(SimpleDramAddress &addr) {
    return get_nth_next_row(addr, 1);
}

SimpleDramAddress ConflictCluster::get_nth_next_row(SimpleDramAddress &addr, size_t nth) {
    auto next_row = (addr.row_id + nth) % cluster[addr.bank_id].size();
    return cluster[addr.bank_id][next_row];
}

