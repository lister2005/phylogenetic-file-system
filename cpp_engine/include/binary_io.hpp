#pragma once
// Small, explicit little-endian binary serialization helpers shared by
// every on-disk format in this engine (manifest, keyring, lineage).
// Explicit field-by-field writes/reads, not struct packing -- avoids
// compiler-padding/alignment differences ever becoming a silent format
// break across compilers or platforms. Factored out once the same
// put_u16/u32/string pattern was about to be written a third time.
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace pfs_engine {

class BinaryWriter {
public:
    void u8(uint8_t v) { buf_.push_back(v); }
    void u16(uint16_t v) { for (int i = 0; i < 2; i++) buf_.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF)); }
    void u32(uint32_t v) { for (int i = 0; i < 4; i++) buf_.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF)); }
    void u64(uint64_t v) { for (int i = 0; i < 8; i++) buf_.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF)); }
    void f64(double v) {
        uint64_t bits;
        memcpy(&bits, &v, 8);  // IEEE754 double, byte layout reinterpreted as u64 -- x86_64/ARM64 are both little-endian
        u64(bits);
    }
    void raw_bytes(const uint8_t* data, size_t len) { buf_.insert(buf_.end(), data, data + len); }
    template <size_t N>
    void fixed_bytes(const std::array<uint8_t, N>& arr) { raw_bytes(arr.data(), N); }
    // u16-length-prefixed UTF-8 string -- every string field in every
    // format here is short (filenames, tag keys/values, phenotype
    // names), so a u16 prefix (up to 64KB) is deliberately generous
    // without wasting space on a u32/u64 prefix nothing needs.
    void string16(const std::string& s) {
        if (s.size() > 0xFFFF) throw std::runtime_error("string field too long for a u16 length prefix");
        u16(static_cast<uint16_t>(s.size()));
        raw_bytes(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    const std::vector<uint8_t>& data() const { return buf_; }

private:
    std::vector<uint8_t> buf_;
};

class BinaryReader {
public:
    BinaryReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    void need(size_t n) const {
        if (pos_ + n > size_) throw std::runtime_error("binary record truncated/corrupt");
    }
    uint8_t u8() {
        need(1);
        return data_[pos_++];
    }
    uint16_t u16() {
        need(2);
        uint16_t v = static_cast<uint16_t>(data_[pos_]) | (static_cast<uint16_t>(data_[pos_ + 1]) << 8);
        pos_ += 2;
        return v;
    }
    uint32_t u32() {
        need(4);
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) v |= static_cast<uint32_t>(data_[pos_ + i]) << (8 * i);
        pos_ += 4;
        return v;
    }
    uint64_t u64() {
        need(8);
        uint64_t v = 0;
        for (int i = 0; i < 8; i++) v |= static_cast<uint64_t>(data_[pos_ + i]) << (8 * i);
        pos_ += 8;
        return v;
    }
    double f64() {
        uint64_t bits = u64();
        double v;
        memcpy(&v, &bits, 8);
        return v;
    }
    template <size_t N>
    std::array<uint8_t, N> fixed_bytes() {
        need(N);
        std::array<uint8_t, N> out{};
        memcpy(out.data(), data_ + pos_, N);
        pos_ += N;
        return out;
    }
    std::string string16() {
        uint16_t len = u16();
        need(len);
        std::string s(reinterpret_cast<const char*>(data_ + pos_), len);
        pos_ += len;
        return s;
    }
    size_t remaining() const { return size_ - pos_; }
    size_t pos() const { return pos_; }

private:
    const uint8_t* data_;
    size_t size_;
    size_t pos_ = 0;
};

}  // namespace pfs_engine
