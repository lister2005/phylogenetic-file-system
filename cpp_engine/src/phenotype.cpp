#include "phenotype.hpp"

#include <cstring>
#include <vector>

namespace pfs_engine {

namespace {

struct Signature {
    const char* magic;
    size_t magic_len;
    size_t offset;
    uint32_t mask;
    const char* name;
};

// (magic bytes, offset, mask, name) -- checked in order, first match
// wins. Byte-for-byte the same table as phenotype.py's _SIGNATURES.
const Signature kSignatures[] = {
    {"%PDF-", 5, 0, 0x0001, "PDF Document"},
    {"\x89PNG\r\n\x1a\n", 8, 0, 0x0002, "PNG Image"},
    {"\xff\xd8\xff", 3, 0, 0x0003, "JPEG Image"},
    {"GIF87a", 6, 0, 0x0004, "GIF Image"},
    {"GIF89a", 6, 0, 0x0004, "GIF Image"},
    {"PK\x03\x04", 4, 0, 0x0005, "ZIP Archive (or ZIP-based format: docx/xlsx/jar/apk...)"},
    // "\x7f" "ELF", not "\x7fELF" -- C++ hex escapes are greedy and 'E'
    // is itself a valid hex digit, so \x7fELF would parse as the
    // (out-of-range, silently wrong) escape \x7fE followed by "LF".
    // Caught by phenotype_test.cpp's cross-check against real Python,
    // which is exactly the kind of bug that check exists to catch.
    {"\x7f" "ELF", 4, 0, 0x0006, "ELF Binary"},
    {"ID3", 3, 0, 0x0007, "MP3 Audio"},
    {"ftyp", 4, 4, 0x0008, "MP4/MOV Media"},
    {"RIFF", 4, 0, 0x0009, "RIFF Container (WAV/AVI/...)"},
    {"SQLite format 3\x00", 16, 0, 0x000A, "SQLite Database"},
    {"\x1f\x8b", 2, 0, 0x000B, "GZIP Compressed"},
    {"BM", 2, 0, 0x000C, "BMP Image"},
};

// Minimal UTF-8 well-formedness check -- close enough to what Python's
// bytes.decode("utf-8") accepts/rejects for this heuristic's purpose
// (leading-byte shape + continuation-byte shape), not a byte-exact
// port of Python's strict decoder (doesn't reject overlong encodings
// or surrogate code points) -- an acceptable divergence for a
// best-effort phenotype GUESS, not a security-relevant check.
bool is_valid_utf8(const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i < len) {
        uint8_t b = data[i];
        size_t extra;
        if (b < 0x80) extra = 0;
        else if ((b & 0xE0) == 0xC0) extra = 1;
        else if ((b & 0xF0) == 0xE0) extra = 2;
        else if ((b & 0xF8) == 0xF0) extra = 3;
        else return false;  // invalid leading byte

        if (i + extra >= len) return false;  // truncated multi-byte sequence
        for (size_t k = 1; k <= extra; k++) {
            if ((data[i + k] & 0xC0) != 0x80) return false;  // invalid continuation byte
        }
        i += extra + 1;
    }
    return true;
}

bool looks_like_text(const uint8_t* sample, size_t len) {
    if (len == 0) return false;
    if (!is_valid_utf8(sample, len)) return false;
    size_t printable = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = sample[i];
        if (b >= 0x20 || b == 0x09 || b == 0x0A || b == 0x0D) printable++;
    }
    return static_cast<double>(printable) / static_cast<double>(len) > 0.95;
}

}  // namespace

Phenotype detect_phenotype(const uint8_t* data, size_t size) {
    for (const auto& sig : kSignatures) {
        size_t end = sig.offset + sig.magic_len;
        if (size >= end && memcmp(data + sig.offset, sig.magic, sig.magic_len) == 0) {
            return {sig.mask, sig.name};
        }
    }
    size_t sample_len = size < 512 ? size : 512;
    if (looks_like_text(data, sample_len)) {
        return {0x00FF, "Plain Text"};
    }
    return {0x0000, "Unknown Binary"};
}

}  // namespace pfs_engine
