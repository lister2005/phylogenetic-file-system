#pragma once
// C++ port of gearhash/phenotype.py -- identifies a file's true format
// from its own content (magic bytes), not a filename extension. Same
// signature table, same order (first match wins), same text-heuristic
// fallback. See phenotype.py's own docstring for the design rationale;
// this is a byte-for-byte behavioral port, not a redesign.
#include <cstdint>
#include <string>

namespace pfs_engine {

struct Phenotype {
    uint32_t mask;
    std::string name;
};

// data should be the first ~64 bytes of the file. Never throws -- an
// unrecognized or empty sample is UNKNOWN, a legitimate outcome.
Phenotype detect_phenotype(const uint8_t* data, size_t size);

}  // namespace pfs_engine
