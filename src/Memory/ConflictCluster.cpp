#include "Memory/ConflictCluster.hpp"
#include "Utilities/Logger.hpp"
#include "Utilities/CustomRandom.hpp"

#include <fstream>
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
#include <unordered_set>
#include <random>

std::string SimpleDramAddress::to_string_compact() const {
  char buff[1024];
  sprintf(buff, "(%2ld,%3ld,%2ld,%4ld,%p)",
          this->cluster_id, bg, bk, row_id, vaddr);
  return {buff};
}

std::string SimpleDramAddress::get_string_compact_desc() {
  return { "(cluster_id, bg, bk, row_id, vaddr)" };
}

ConflictCluster::ConflictCluster(std::string &filepath_rowlist,
                                 std::string &filepath_rowlist_bgbk) {
  cr = CustomRandom();
  load_bgbk_mapping(filepath_rowlist_bgbk);
  load_conflict_cluster(filepath_rowlist);
}

size_t ConflictCluster::get_typical_row_offset() {
  return typical_row_offset;
}

size_t ConflictCluster::get_min_num_rows() {
  return min_num_rows;
}

void ConflictCluster::load_conflict_cluster(const std::string &filename) {
  min_paddr = std::numeric_limits<uint64_t>::max();
  max_paddr = std::numeric_limits<uint64_t>::min();

  Logger::log_debug(format_string("Loading conflict cluster from '%s'", filename.c_str()));

  std::unordered_map<uint64_t, size_t> offset_cnt;
  size_t total = 0;

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
    min_paddr = (min_paddr < (uint64_t)addr.paddr) ? min_paddr : (uint64_t)addr.paddr;
    max_paddr = (max_paddr > (uint64_t)addr.paddr) ? max_paddr : (uint64_t)addr.paddr;

    if (!clusterid2bgbk.empty()) {
      // skip addresses where we
      if (clusterid2bgbk.find(addr.cluster_id) != clusterid2bgbk.end()) {
        auto bgbk = clusterid2bgbk[addr.cluster_id];
        addr.bg = bgbk.first;
        addr.bk = bgbk.second;
      } else {
//        Logger::log_debug(format_string("skipping vaddr=%p as cluster_id=%d not in clusterid2bgbk", addr.vaddr,
//                                        addr.cluster_id));
        continue;
      }
    }

    total++;
    clusters[addr.cluster_id][addr.row_id] = addr;

    // store a mapping from virtual address to SimpleDramAddress
    vaddr_map[addr.vaddr] = addr;

    if (last_bank_id == cur_bank_id && row_id_cnt > 0) {
      auto offt = (uint64_t)addr.vaddr-(uint64_t)clusters[addr.cluster_id][clusters[addr.cluster_id].size()-2].vaddr;
      offset_cnt[offt]++;
    }

//#if (DEBUG==1)
//    std::stringstream out;
//    out << addr.cluster_id << " "
//        << addr.row_id << " "
//        << std::hex << "0x" << (uint64_t) addr.vaddr << " "
//        << std::hex << "0x" << (uint64_t) addr.paddr
//        << std::endl;
//    Logger::log_debug(out.str());
//#endif

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

  // determine the minimum number of rows per bank (though all banks are supposed to have the same number of rows)
  min_num_rows = std::numeric_limits<std::size_t>::max();
  for (const auto &cluster : clusters) {
    min_num_rows = std::min(min_num_rows, cluster.second.size());
  }
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
  std::unordered_set<std::string> all_bg_bk;

  Logger::log_debug(format_string("Loading cluster->(bg,bk) mapping from '%s'", filepath.c_str()));

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
    auto bg_id = strtoul(items[1].c_str(), nullptr, 2);
    auto bk_id = strtoul(items[2].c_str(), nullptr, 2);

    std::stringstream ss;
    ss << bg_id << "_" << bk_id;
    if (all_bg_bk.find(ss.str())!= all_bg_bk.end()) {
      throw std::runtime_error("[-] cluster->(bg,bk) mapping is not unique");
    } else {
      all_bg_bk.insert(ss.str());
    }
    clusterid2bgbk[cluster_id] = std::make_pair(bg_id, bk_id);
  }

  file.close();
}

std::vector<SimpleDramAddress> ConflictCluster::get_simple_dram_addresses(size_t num_addresses, size_t row_distance,
                                                                          bool same_bg, bool same_bk) {
  auto cluster_ids = get_supported_cluster_ids();
  // shuffle order to make sure we not always pick the same when calling
  // this function multiple times in row
  std::shuffle(cluster_ids.begin(), cluster_ids.end(), cr.gen);

  auto dist = std::uniform_int_distribution<size_t>(0, get_min_num_rows()/4);
  auto row_no = dist(cr.gen);

  std::vector<SimpleDramAddress> addr_pair;

  for (const auto &a : cluster_ids) {
    auto a_bg = clusterid2bgbk[a].first;
    auto a_bk = clusterid2bgbk[a].second;

    for (const auto &b : cluster_ids) {
      auto b_bg = clusterid2bgbk[b].first;
      auto b_bk = clusterid2bgbk[b].second;

      if (((!same_bg && a_bg != b_bg) || (same_bg && a_bg == b_bg))
          && ((!same_bk && a_bk != b_bk) || (same_bk && a_bk == b_bk))) {  
            
        while (addr_pair.size() < num_addresses) {
          addr_pair.push_back(get_simple_dram_address(a, row_no));
          row_no += row_distance;
          // handle the edge case of an uneven no. of requested rows (e.g., 1)
          if (addr_pair.size() == num_addresses) break;
          addr_pair.push_back(get_simple_dram_address(b, row_no));
          row_no += row_distance;
        }
        goto get_simple_dram_addresses__end;

      }

    }

  }

  get_simple_dram_addresses__end:
  if (addr_pair.size() == 0) {
    std::cerr << "[-] Could not find any valid <bg,bk> combination satisfying requirements!" << std::endl;
    exit(EXIT_FAILURE);
  }
  
  return addr_pair;
}

std::vector<SimpleDramAddress> ConflictCluster::get_simple_dram_address_same_bgbk(size_t num_addresses,
                                                                                  size_t row_distance) {
  auto supported_cluster_ids = get_supported_cluster_ids();
  std::vector<size_t> selected_cluster_ids;
  std::sample(supported_cluster_ids.begin(), supported_cluster_ids.end(),
              std::back_inserter(selected_cluster_ids), 1,
              cr.gen);
  size_t cluster_id = selected_cluster_ids.back();

  std::vector<SimpleDramAddress> result;
  std::uniform_int_distribution<size_t> dist(0, min_num_rows-1);
  auto cur_row = dist(cr.gen);
  for (size_t i = 0; i < num_addresses; ++i) {
    result.push_back(clusters[cluster_id][cur_row]);
    cur_row = (cur_row + row_distance)%clusters[cluster_id].size();
  }
  Logger::log_debug(format_string("found %d addresses", result.size()));
  return result;
}

SimpleDramAddress ConflictCluster::get_simple_dram_address(size_t cluster_id, size_t row_id) {
  if (clusters.find(cluster_id) == clusters.end()) {
    Logger::log_error("Invalid bank_id given! Valid bank_ids are:");
    for (const auto &bk_id : get_supported_cluster_ids()) {
      Logger::log_data(format_string("%d", bk_id));
    }
    exit(EXIT_FAILURE);
  }
  return clusters[cluster_id][row_id % clusters[cluster_id].size()];
}

std::vector<size_t> ConflictCluster::get_supported_cluster_ids() {
  std::vector<size_t> supported_cluster_ids;
  supported_cluster_ids.reserve(clusters.size());
  for (const auto &entry : clusters)
    supported_cluster_ids.push_back(entry.first);
  return supported_cluster_ids;
}

std::vector<volatile char*> ConflictCluster::get_sync_rows(SimpleDramAddress &addr, size_t num_rows, bool verbose) {
  // build a list that alternates rows with <same bk, diff bg> and <diff bk, same bg> addresses relative to
  // the 'addr' passed to this function

  const size_t num_rows_per_subset = num_rows / 2;

  auto f_samebg_diffbk = [](size_t bg_target, size_t bg_candidate, size_t bk_target, size_t bk_candidate) {
    return (bg_target == bg_candidate) && (bk_target != bk_candidate);
  };
  auto f_diffbg_samebk = [](size_t bg_target, size_t bg_candidate, size_t bk_target, size_t bk_candidate) {
    return (bg_target != bg_candidate) && (bk_target == bk_candidate);
  };

  std::vector<SimpleDramAddress> samebg_diffbk = get_filtered_addresses(addr, num_rows_per_subset, f_samebg_diffbk);
  std::vector<SimpleDramAddress> diffbg_samebk = get_filtered_addresses(addr, num_rows_per_subset, f_diffbg_samebk);

  if ((samebg_diffbk.empty() || diffbg_samebk.empty())) {
      Logger::log_error("Cannot find suitable sync rows.. using same-bg/diff-bk or diff-bg/same-bk only.");
  }

  std::stringstream ss;
  std::vector<volatile char*> sync_rows;
  sync_rows.reserve(num_rows);
  for (size_t i = 0; i < num_rows_per_subset; i++) {
    if (i < samebg_diffbk.size()) {
      sync_rows.push_back(samebg_diffbk[i].vaddr);
      ss << samebg_diffbk[i].to_string_compact() << "\n";
    }
    if (i < diffbg_samebk.size()) {
      sync_rows.push_back(diffbg_samebk[i].vaddr);
      ss << diffbg_samebk[i].to_string_compact() << "\n";
    }
  }

  if (verbose) {
    Logger::log_info("Sync rows " + SimpleDramAddress::get_string_compact_desc() + " :");
    Logger::log_data(ss.str());
  }

  return sync_rows;
}


std::vector<SimpleDramAddress> ConflictCluster::get_filtered_addresses(SimpleDramAddress &addr, size_t max_num_rows,
                                                                       bool (*func)(size_t, size_t, size_t, size_t)) {
  for (const auto &cluster_id : clusterid2bgbk) {
    if (func(cluster_id.second.first, addr.bg, cluster_id.second.second, addr.bk)) {
      std::vector<SimpleDramAddress> result_cluster;
      for (const auto &a : clusters[cluster_id.first]) {
        result_cluster.push_back(a.second);
        if (result_cluster.size() == max_num_rows) {
          break;
        }
      }
      return result_cluster;
    }
  }

  Logger::log_error("get_samebg_diffbk_addresses could not find any <other bg, same bk> addresses!");
  return {};
}

uint64_t ConflictCluster::get_min_paddr() const {
  return min_paddr;
}

uint64_t ConflictCluster::get_max_paddr() const {
  return max_paddr;
}

void ConflictCluster::update_vaddr(uint64_t base_vaddr) {
  vaddr_map.clear();
  for (auto &clusterid_map : clusters) {
    for (auto &rowid_simpledramaddr : clusterid_map.second) {
      auto offt = (uint64_t)rowid_simpledramaddr.second.vaddr & ((1ULL << 31)-1);
      rowid_simpledramaddr.second.vaddr = (volatile char*)(base_vaddr + offt);
      vaddr_map[rowid_simpledramaddr.second.vaddr] = rowid_simpledramaddr.second;
    }
  }
}
