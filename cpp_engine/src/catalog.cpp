#include "catalog.hpp"

#include <cstring>
#include <fstream>
#include <stdexcept>

#include <fcntl.h>
#include <unistd.h>

#include "binary_io.hpp"
#include "immutability.hpp"

namespace pfs_engine {

namespace {
constexpr char kMagic[4] = {'P', 'F', 'S', 'C'};
constexpr uint16_t kVersion = 1;
constexpr const char* kAad = "catalog";

// True if a file exists and can be opened.
bool file_exists(const std::string& path) {
    std::ifstream f(path);
    return f.good();
}
}  // namespace

// Opens the catalog (file name -> recipe filename) of a vault and loads it.
Catalog::Catalog(std::string storage_root, const Bytes32& kek)
    : storage_root_(std::move(storage_root)), kek_(kek) {
    path_ = storage_root_ + "/catalog.pfsc";
    load();
}

// Decrypts and reads the catalog file; an absent file means an empty catalog.
void Catalog::load() {
    entries_.clear();
    if (!file_exists(path_)) return;

    std::ifstream in(path_, std::ios::binary);
    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::vector<uint8_t> raw = aead_decrypt(kek_, encrypted.data(), encrypted.size(),
                                             reinterpret_cast<const uint8_t*>(kAad), strlen(kAad));

    BinaryReader r(raw.data(), raw.size());
    r.need(4);
    if (memcmp(raw.data(), kMagic, 4) != 0) throw std::runtime_error("bad catalog magic: " + path_);
    r.fixed_bytes<4>();
    uint16_t version = r.u16();
    if (version != kVersion) throw std::runtime_error("unsupported catalog version: " + path_);
    uint32_t count = r.u32();
    for (uint32_t i = 0; i < count; i++) {
        std::string label = r.string16();
        std::string manifest_filename = r.string16();
        entries_[label] = manifest_filename;
    }
}

// Encrypts the catalog and replaces the file atomically.
void Catalog::save(bool scrub) {
    BinaryWriter w;
    w.raw_bytes(reinterpret_cast<const uint8_t*>(kMagic), 4);
    w.u16(kVersion);
    w.u32(static_cast<uint32_t>(entries_.size()));
    for (const auto& [label, manifest_filename] : entries_) {
        w.string16(label);
        w.string16(manifest_filename);
    }
    std::vector<uint8_t> encrypted = aead_encrypt(kek_, w.data().data(), w.data().size(),
                                                   reinterpret_cast<const uint8_t*>(kAad), strlen(kAad));

    bool was_present = file_exists(path_);
    if (was_present) set_immutable(path_, false);

    std::string tmp = path_ + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("failed to open catalog temp file: " + tmp);
        out.write(reinterpret_cast<const char*>(encrypted.data()), static_cast<std::streamsize>(encrypted.size()));
    }
    int fd = open(tmp.c_str(), O_WRONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
    if (scrub) {
        scrub_then_replace(tmp, path_);
    } else if (rename(tmp.c_str(), path_.c_str()) != 0) {
        throw std::runtime_error("failed to rename catalog into place: " + path_);
    }
    set_immutable(path_, true);
}

// Returns the recipe filename for a file name, if the file exists.
std::optional<std::string> Catalog::get(const std::string& label) const {
    auto it = entries_.find(label);
    if (it == entries_.end()) return std::nullopt;
    return it->second;
}

// Adds or updates a file's entry and saves.
void Catalog::set(const std::string& label, const std::string& manifest_filename) {
    entries_[label] = manifest_filename;
    save();
}

// Removes a file's entry and saves.
void Catalog::remove(const std::string& label) {
    entries_.erase(label);
    save();
}

// Removes a file's entry and saves, overwriting the old catalog file first.
void Catalog::remove_scrubbed(const std::string& label) {
    entries_.erase(label);
    save(true);
}

// Returns every file name in the catalog.
std::vector<std::string> Catalog::labels() const {
    std::vector<std::string> out;
    out.reserve(entries_.size());
    for (const auto& [label, _] : entries_) out.push_back(label);
    return out;
}

}  // namespace pfs_engine
