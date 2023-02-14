#include "Memory/ConflictCluster.hpp"
#include "Utilities/Logger.hpp"

#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>

std::string SimpleDramAddress::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%2ld,%3ld,0x%lx,0x%lx)",
          this->cluster_id, row_id, (uint64_t) vaddr, (uint64_t) paddr);
  return {buff};
}

ConflictCluster::ConflictCluster(std::string &filepath_rowlist,
                                 std::string &filepath_rowlist_bgbk) {
  load_conflict_cluster(filepath_rowlist);
  load_bgbk_mapping(filepath_rowlist_bgbk);
}

size_t ConflictCluster::get_typical_row_offset() {
  return typical_row_offset;
}

void ConflictCluster::load_conflict_cluster(const std::string &filename) {
  Logger::log_debug("Loading conflict cluster from '%s'", filename.c_str());

  std::unordered_map<uint64_t, size_t> offset_cnt;

  std::ifstream file(filename);
  if (!file.is_open())
    throw std::runtime_error("[-] could not open file " + filename);

  std::string last_bank_id;
  size_t row_id_cnt = 0;

  std::string bankid_vaddr_paddr;
  while (std::getline(file, bankid_vaddr_paddr, '\n')) {

    std::istringstream iss(bankid_vaddr_paddr);
    std::string item;
    std::vector<std::string> items;
    while (std::getline(iss, item, ',')) {
      items.push_back(item);
      item.clear();
    }

    auto cur_bank_id = items[0];
    auto cur_vaddr = items[1];
    auto cur_paddr = items[2];

    if (cur_bank_id != last_bank_id && !last_bank_id.empty())
      row_id_cnt = 0;

    SimpleDramAddress addr{};
    addr.cluster_id = (size_t) strtoll(cur_bank_id.c_str(), nullptr, 10);
    addr.row_id = row_id_cnt;
    addr.vaddr = (volatile char *) strtoull((const char *) cur_vaddr.c_str(), nullptr, 16);
    addr.paddr = (volatile char *) strtoull((const char *) cur_paddr.c_str(), nullptr, 16);

    clusters[addr.cluster_id][addr.row_id] = addr;

    // store a mapping from virtual address to SimpleDramAddress
    vaddr_map[addr.vaddr] = addr;

    if (last_bank_id == cur_bank_id && row_id_cnt > 0) {
      auto offt = (uint64_t)addr.vaddr-(uint64_t)clusters[addr.cluster_id][clusters[addr.cluster_id].size()-2].vaddr;
      offset_cnt[offt]++;
    }

#if (DEBUG==1)
    std::stringstream out;
    out << addr.cluster_id << " "
        << addr.row_id << " "
        << std::hex << "0x" << (uint64_t) addr.vaddr << " "
        << std::hex << "0x" << (uint64_t) addr.paddr
        << std::endl;
    Logger::log_debug(out.str());
#endif

    row_id_cnt++;
    last_bank_id = cur_bank_id;

    bankid_vaddr_paddr.clear();
  }

  // find the most common row offset
  using t = decltype(offset_cnt)::value_type;
  auto elem = std::max_element(offset_cnt.begin(), offset_cnt.end(),
                               [](const t &p1, const t &p2) { return p1.second < p2.second;
  });
  typical_row_offset = elem->second;
}

SimpleDramAddress ConflictCluster::get_next_row(const SimpleDramAddress &addr) {
  return get_nth_next_row(addr, 1);
}

SimpleDramAddress ConflictCluster::get_nth_next_row(const SimpleDramAddress &addr, size_t nth) {
  auto next_row = (addr.row_id + nth) % clusters[addr.cluster_id].size();
  return clusters[addr.cluster_id][next_row];
}

SimpleDramAddress ConflictCluster::get_simple_dram_address(volatile char *vaddr) {
  if (vaddr_map.find(vaddr) != vaddr_map.end()) {
    return vaddr_map[vaddr];
  } else {
    uint64_t lowest_dist = std::numeric_limits<uint64_t>::max();
    uint64_t last_dist = std::numeric_limits<uint64_t>::max();
    auto it = vaddr_map.begin();
    SimpleDramAddress *addr = &vaddr_map.begin()->second;
    // we assume here that the vaddr_map is sorted
    while (last_dist <= lowest_dist && it != vaddr_map.end()) {
      auto dist = (uint64_t) it->first - (uint64_t) vaddr;
      if (dist < last_dist) {
        lowest_dist = dist;
        addr = &it->second;
      } else {
        break;
      }
      last_dist = dist;
      it++;
    }
    return *addr;
  }
}

void ConflictCluster::load_bgbk_mapping(const std::string &filepath) {
  Logger::log_debug("Loading cluster->(bg,bk) mapping from '%s'", filepath.c_str());

  std::ifstream file(filepath);
  if (!file.is_open())
    throw std::runtime_error("[-] could not open file " + filepath);

  std::string clusterid_bg_bk;
  while (std::getline(file, clusterid_bg_bk, '\n')) {
    std::istringstream iss(clusterid_bg_bk);
    std::string item;
    std::vector<std::string> items;
    while (std::getline(iss, item, ',')) {
      items.push_back(item);
      item.clear();
    }

    // skip line if it starts with '#' (e.g., header or comment)
    if (items[0].rfind('#', 0) == 0) {
      continue;
    }

    auto cluster_id = strtoul(items[0].c_str(), nullptr, 10);
    auto bg_id = strtoul(items[1].c_str(), nullptr, 10);
    auto bk_id = strtoul(items[2].c_str(), nullptr, 10);
    clusterid2bgbk[cluster_id] = std::make_pair(bg_id, bk_id);;
  }

  file.close();
}

SimpleDramAddress ConflictCluster::get_simple_dram_address(size_t bank_id, size_t row_id) {
  return clusters[bank_id][row_id % clusters[bank_id].size()];
}
