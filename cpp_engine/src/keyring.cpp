#include "keyring.hpp"

#include <cstring>
#include <fstream>
#include <stdexcept>

#include <fcntl.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <unistd.h>

#include "immutability.hpp"

namespace pfs_engine {

namespace {

constexpr char kMagic[4] = {'P', 'F', 'S', 'K'};
constexpr uint16_t kVersion = 1;
constexpr size_t kWrappedDekSize = 12 + 32 + 16;  // IV + DEK + GCM tag

// The associated data that binds a wrapped key to its epoch number.
std::string aad_for_epoch(uint32_t epoch_id) {
    return "epoch:" + std::to_string(epoch_id);
}

// Encrypts one data key with the passphrase-derived key, bound to its epoch.
std::vector<uint8_t> wrap_dek(const Bytes32& kek, uint32_t epoch_id, const Bytes32& dek) {
    std::string aad = aad_for_epoch(epoch_id);
    return aead_encrypt(kek, dek.data(), dek.size(),
                         reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
}

// Decrypts one wrapped data key, checking its epoch and size.
Bytes32 unwrap_dek(const Bytes32& kek, uint32_t epoch_id, const uint8_t* wrapped, size_t len) {
    std::string aad = aad_for_epoch(epoch_id);
    std::vector<uint8_t> raw = aead_decrypt(kek, wrapped, len,
                                             reinterpret_cast<const uint8_t*>(aad.data()), aad.size());
    if (raw.size() != 32) throw std::runtime_error("unwrapped DEK has unexpected size");
    Bytes32 out{};
    memcpy(out.data(), raw.data(), 32);
    return out;
}

// True if a file exists.
bool file_exists(const std::string& path) {
    struct stat st{};
    return stat(path.c_str(), &st) == 0;
}

}  // namespace

// Opens the keyring of a vault and loads it.
KeyRing::KeyRing(std::string storage_root, const Bytes32& kek)
    : storage_root_(std::move(storage_root)), kek_(kek) {
    path_ = storage_root_ + "/keyring.pfsk";
    load();
}

// Reads the keyring file and unwraps every data key; the newest epoch becomes current.
void KeyRing::load() {
    if (!file_exists(path_)) return;

    std::ifstream in(path_, std::ios::binary);
    if (!in) throw std::runtime_error("failed to open keyring: " + path_);
    std::vector<uint8_t> raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    if (raw.size() < 10 || memcmp(raw.data(), kMagic, 4) != 0) {
        throw std::runtime_error("bad keyring magic/truncated file: " + path_);
    }
    uint16_t version;
    memcpy(&version, raw.data() + 4, 2);
    if (version != kVersion) throw std::runtime_error("unsupported keyring version");
    uint32_t count;
    memcpy(&count, raw.data() + 6, 4);

    size_t pos = 10;
    constexpr size_t kEntrySize = 4 + kWrappedDekSize;
    if (raw.size() != pos + static_cast<size_t>(count) * kEntrySize) {
        throw std::runtime_error("keyring size doesn't match declared entry count");
    }

    uint32_t max_epoch = 0;
    bool any = false;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t epoch_id;
        memcpy(&epoch_id, raw.data() + pos, 4);
        pos += 4;
        Bytes32 dek = unwrap_dek(kek_, epoch_id, raw.data() + pos, kWrappedDekSize);
        pos += kWrappedDekSize;
        deks_[epoch_id] = dek;
        if (!any || epoch_id > max_epoch) max_epoch = epoch_id;
        any = true;
    }
    if (any) current_epoch_ = static_cast<int64_t>(max_epoch);
}

// Wraps every data key and rewrites the keyring file in the PFSK format.
void KeyRing::save() {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), kMagic, kMagic + 4);
    buf.push_back(static_cast<uint8_t>(kVersion & 0xFF));
    buf.push_back(static_cast<uint8_t>((kVersion >> 8) & 0xFF));
    uint32_t count = static_cast<uint32_t>(deks_.size());
    for (int i = 0; i < 4; i++) buf.push_back(static_cast<uint8_t>((count >> (8 * i)) & 0xFF));

    for (const auto& [epoch_id, dek] : deks_) {
        for (int i = 0; i < 4; i++) buf.push_back(static_cast<uint8_t>((epoch_id >> (8 * i)) & 0xFF));
        std::vector<uint8_t> wrapped = wrap_dek(kek_, epoch_id, dek);
        if (wrapped.size() != kWrappedDekSize) throw std::runtime_error("unexpected wrapped DEK size");
        buf.insert(buf.end(), wrapped.begin(), wrapped.end());
    }

    // Temp file + rename + fsync, clearing +i before and restoring it after.
    bool was_immutable = file_exists(path_);
    if (was_immutable) set_immutable(path_, false);

    std::string tmp_path = path_ + ".tmp";
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) throw std::runtime_error("failed to open keyring temp file: " + tmp_path);
        out.write(reinterpret_cast<const char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
    }
    int fd = open(tmp_path.c_str(), O_WRONLY);
    if (fd >= 0) { fsync(fd); close(fd); }
    if (rename(tmp_path.c_str(), path_.c_str()) != 0) {
        throw std::runtime_error("failed to rename keyring into place: " + path_);
    }
    set_immutable(path_, true);
}

// Returns the current epoch and its data key, creating the first one if needed.
std::pair<uint32_t, Bytes32> KeyRing::get_current_dek() {
    if (current_epoch_ == -1) rotate();
    uint32_t epoch = static_cast<uint32_t>(current_epoch_);
    return {epoch, deks_.at(epoch)};
}

// Returns the data key for an epoch, throwing if the keyring lacks it.
Bytes32 KeyRing::get_dek(uint32_t epoch_id) const {
    auto it = deks_.find(epoch_id);
    if (it == deks_.end()) {
        throw std::out_of_range(
            "no DEK found for epoch " + std::to_string(epoch_id) +
            " -- keyring is missing an entry that existing data depends on");
    }
    return it->second;
}

// Creates a new random data key as the next epoch, saves, and returns its number.
uint32_t KeyRing::rotate() {
    uint32_t new_epoch = static_cast<uint32_t>(current_epoch_ + 1);
    Bytes32 dek{};
    RAND_bytes(dek.data(), static_cast<int>(dek.size()));
    deks_[new_epoch] = dek;
    current_epoch_ = new_epoch;
    save();
    return new_epoch;
}

// Re-wraps every data key under a new passphrase-derived key (for a passphrase change).
void KeyRing::rewrap_under_new_kek(const Bytes32& new_kek) {
    kek_ = new_kek;
    save();
}

}  // namespace pfs_engine
