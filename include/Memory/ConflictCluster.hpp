#ifndef BLACKSMITH_CONFLICTCLUSTER_H
#define BLACKSMITH_CONFLICTCLUSTER_H

#include <cstdlib>
#include <unordered_map>
#include <string>
#include <map>

class Memory;

class SimpleDramAddress {
public:
  size_t cluster_id;
  size_t row_id;
  volatile char *vaddr;
  volatile char *paddr;

  SimpleDramAddress(size_t bank_id, size_t row_id, volatile char *vaddr, volatile char *paddr)
      : cluster_id(bank_id), row_id(row_id), vaddr(vaddr), paddr(paddr) {};

  SimpleDramAddress() = default;

  [[nodiscard]] std::string to_string_compact() const;
};

class ConflictCluster {
private:
  size_t typical_row_offset;

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

  SimpleDramAddress get_simple_dram_address(size_t bank_id, size_t row_id);

  size_t get_typical_row_offset();
};

#endif //BLACKSMITH_CONFLICTCLUSTER_H
