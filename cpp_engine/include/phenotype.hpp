#pragma once
// Port of gearhash/phenotype.py: same signature table and order, same
// text fallback.
#include <cstdint>
#include <string>

namespace pfs_engine {

struct Phenotype {
    uint32_t mask;
    std::string name;
};

// data: the first ~64 bytes. Never throws; unknown or empty -> UNKNOWN.
Phenotype detect_phenotype(const uint8_t* data, size_t size);

}  // namespace pfs_engine
