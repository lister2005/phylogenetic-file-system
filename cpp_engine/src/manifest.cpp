#include "manifest.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <stdexcept>

#include <fcntl.h>
#include <unistd.h>

#include "binary_io.hpp"

namespace pfs_engine {

namespace {
constexpr char kMagic[4] = {'P', 'F', 'S', 'M'};
constexpr uint16_t kVersion = 1;
}  // namespace

Manifest::Manifest(ManifestMetadata metadata, std::vector<Bytes32> block_hashes)
    : metadata_(std::move(metadata)), block_hashes_(std::move(block_hashes)) {
    if (block_hashes_.size() != metadata_.total_blocks) {
        throw std::runtime_error("block_hashes.size() must equal metadata.total_blocks");
    }
    // Sorted, so the same fingerprint always serializes identically.
    if (metadata_.similarity_fingerprint) {
        std::sort(metadata_.similarity_fingerprint->begin(), metadata_.similarity_fingerprint->end());
    }
}

std::vector<uint8_t> Manifest::serialize() const {
    BinaryWriter w;
    w.raw_bytes(reinterpret_cast<const uint8_t*>(kMagic), 4);
    w.u16(kVersion);

    w.string16(metadata_.original_filename);
    w.fixed_bytes(metadata_.content_sha256);
    w.u64(metadata_.total_blocks);
    w.u64(metadata_.original_size);
    w.u64(metadata_.new_chunks_written);
    w.u64(metadata_.duplicate_chunks_found);
    w.u32(metadata_.phenotype_mask);
    w.string16(metadata_.phenotype_name);

    if (metadata_.similarity_fingerprint) {
        w.u8(1);
        w.u32(static_cast<uint32_t>(metadata_.similarity_fingerprint->size()));
        for (const auto& h : *metadata_.similarity_fingerprint) w.fixed_bytes(h);
    } else {
        w.u8(0);
    }

    for (const auto& h : block_hashes_) w.fixed_bytes(h);

    return w.data();
}

Manifest Manifest::deserialize(const std::vector<uint8_t>& raw) {
    BinaryReader r(raw.data(), raw.size());
    r.need(4);
    if (memcmp(raw.data(), kMagic, 4) != 0) throw std::runtime_error("bad manifest magic");
    r.fixed_bytes<4>();  // the magic
    uint16_t version = r.u16();
    if (version != kVersion) throw std::runtime_error("unsupported manifest version");

    ManifestMetadata meta;
    meta.original_filename = r.string16();
    meta.content_sha256 = r.fixed_bytes<32>();
    meta.total_blocks = r.u64();
    meta.original_size = r.u64();
    meta.new_chunks_written = r.u64();
    meta.duplicate_chunks_found = r.u64();
    meta.phenotype_mask = r.u32();
    meta.phenotype_name = r.string16();

    uint8_t has_fp = r.u8();
    if (has_fp) {
        uint32_t count = r.u32();
        std::vector<Bytes32> fp;
        fp.reserve(count);
        for (uint32_t i = 0; i < count; i++) fp.push_back(r.fixed_bytes<32>());
        meta.similarity_fingerprint = std::move(fp);
    }

    std::vector<Bytes32> block_hashes;
    block_hashes.reserve(meta.total_blocks);
    for (uint64_t i = 0; i < meta.total_blocks; i++) block_hashes.push_back(r.fixed_bytes<32>());

    Manifest m;
    m.metadata_ = std::move(meta);
    m.block_hashes_ = std::move(block_hashes);
    return m;
}

std::optional<Bytes32> Manifest::lookup(uint64_t block_index) const {
    if (block_index >= block_hashes_.size()) return std::nullopt;
    return block_hashes_[block_index];
}

std::string manifest_filename_for(const Bytes32& content_sha256) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (uint8_t b : content_sha256) {
        out.push_back(hex_chars[b >> 4]);
        out.push_back(hex_chars[b & 0xF]);
    }
    out += ".manifest.pfsm";
    return out;
}

void write_manifest_file(const std::string& path, const std::string& manifest_filename,
                          const Manifest& manifest, const Bytes32& kek) {
    std::vector<uint8_t> raw = manifest.serialize();
    std::vector<uint8_t> encrypted = aead_encrypt(
        kek, raw.data(), raw.size(),
        reinterpret_cast<const uint8_t*>(manifest_filename.data()), manifest_filename.size());

    // Temp file + rename + fsync: never a partial manifest.
    std::string tmp_path = path + ".tmp";
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("failed to open manifest temp file: " + tmp_path);
        out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
        out.flush();
        if (!out) throw std::runtime_error("failed writing manifest temp file: " + tmp_path);
    }
    int fd = open(tmp_path.c_str(), O_WRONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
    if (rename(tmp_path.c_str(), path.c_str()) != 0) {
        throw std::runtime_error("failed to rename manifest into place: " + path);
    }
}

Manifest read_manifest_file(const std::string& path, const std::string& manifest_filename,
                             const Bytes32& kek) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("manifest not found: " + path);
    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    std::vector<uint8_t> raw = aead_decrypt(
        kek, encrypted.data(), encrypted.size(),
        reinterpret_cast<const uint8_t*>(manifest_filename.data()), manifest_filename.size());
    return Manifest::deserialize(raw);
}

}  // namespace pfs_engine
