#ifndef BLACKSMITH_CONFLICTCLUSTER_H
#define BLACKSMITH_CONFLICTCLUSTER_H

#include <cstdlib>
#include <unordered_map>
#include <string>
#include <map>
#include <vector>
#include "Utilities/CustomRandom.hpp"

class Memory;

class SimpleDramAddress {
public:
  size_t cluster_id;
  size_t row_id;
  size_t bk;
  size_t bg;
  volatile char *vaddr;
  volatile char *paddr;

  SimpleDramAddress() = default;

  [[nodiscard]] std::string to_string_compact() const;

  static std::string get_string_compact_desc();
};

class ConflictCluster {
private:
  CustomRandom cr;

  size_t typical_row_offset;

  size_t min_num_rows;

  uint64_t min_paddr;

  uint64_t max_paddr;

  // cluster_id -> row_id -> SimpleDramAddress
  std::unordered_map<size_t, std::unordered_map<size_t, SimpleDramAddress>> clusters;

  // cluster_id -> (bg_id,bk_id)
  std::unordered_map<size_t,std::pair<size_t,size_t>> clusterid2bgbk;

  // vaddr -> SimpleDramAddress
  std::map<volatile char *, SimpleDramAddress> vaddr_map;

public:
  ConflictCluster(std::string &filepath_rowlist, std::string &filepath_rowlist_bgbk);

  void load_conflict_cluster(const std::string &filepath);

  void load_bgbk_mapping(const std::string &filepath);

  SimpleDramAddress get_next_row(const SimpleDramAddress &addr);

  SimpleDramAddress get_nth_next_row(const SimpleDramAddress &addr, size_t nth);

  SimpleDramAddress get_simple_dram_address(volatile char *vaddr);

  SimpleDramAddress get_simple_dram_address(size_t cluster_id, size_t row_id);

  size_t get_typical_row_offset();

  size_t get_min_num_rows();

  std::vector<size_t> get_supported_cluster_ids();

  std::vector<SimpleDramAddress> get_filtered_addresses(SimpleDramAddress &addr, size_t max_num_rows,
                                                        bool (*func)(size_t, size_t, size_t, size_t));

  std::vector<volatile char *> get_sync_rows(SimpleDramAddress &addr, size_t num_rows, bool verbose);

  std::vector<SimpleDramAddress> get_simple_dram_address_same_bgbk(size_t num_addresses,
                                                                   size_t row_distance);

  std::vector<SimpleDramAddress> get_simple_dram_addresses(size_t num_addresses,
                                                           size_t row_distance,
                                                           bool same_bg,
                                                           bool same_bk);
  [[nodiscard]] uint64_t get_min_paddr() const;

  [[nodiscard]] uint64_t get_max_paddr() const;

  void update_vaddr(uint64_t base_vaddr);
};

#endif //BLACKSMITH_CONFLICTCLUSTER_H
