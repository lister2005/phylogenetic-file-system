#pragma once
// The catalog: label -> current manifest filename, in a portable file
// (catalog.pfsc) instead of pickle. Separate state, not derivable from
// lineage: with several branch heads, it records which one plain
// reads/writes use (the most recently written).
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "crypto_utils.hpp"

namespace pfs_engine {

class Catalog {
public:
    Catalog(std::string storage_root, const Bytes32& kek);

    bool contains(const std::string& label) const { return entries_.count(label) > 0; }
    std::optional<std::string> get(const std::string& label) const;
    void set(const std::string& label, const std::string& manifest_filename);  // persists immediately
    void remove(const std::string& label);                                     // persists immediately
    // Removes and persists with the old catalog file overwritten first (for 'shred').
    void remove_scrubbed(const std::string& label);
    std::vector<std::string> labels() const;
    // Re-reads the file, for changes made by another program.
    void reload() { load(); }

private:
    std::string storage_root_;
    std::string path_;
    Bytes32 kek_;
    std::map<std::string, std::string> entries_;  // label -> manifest_filename

    void load();
    void save(bool scrub = false);
};

}  // namespace pfs_engine
