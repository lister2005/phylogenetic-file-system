#pragma once
// Shared cryptographic primitives used across the engine (dedup index,
// manifest, container encryption) -- factored out once these were about
// to be written a third time. All of this replicates gearhash/crypto.py
// and gearhash/dedup_index.py's schemes exactly (verified byte-for-byte
// against the Python reference -- see cpp_engine/bench/hkdf_check.cpp
// and the dedup index cross-compatibility test), not reinvented.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace pfs_engine {

using Bytes32 = std::array<uint8_t, 32>;

// SHA-256, one-shot.
Bytes32 sha256(const uint8_t* data, size_t len);

// HMAC-SHA256, one-shot.
Bytes32 hmac_sha256(const Bytes32& key, const uint8_t* data, size_t len);

// RFC 5869 HKDF-SHA256 with salt=None -- Python cryptography's HKDF
// treats a None salt as a zero-filled salt of the hash's output length
// (32 bytes), not an empty salt. `info` is a plain UTF-8 string.
Bytes32 hkdf_sha256(const Bytes32& ikm, const std::string& info);

// AES-256-GCM encrypt. Output layout: 12-byte random IV || ciphertext ||
// 16-byte tag -- the EXACT layout gearhash/crypto.py's encrypt_block
// produces (AESGCM.encrypt() appends its own tag to the ciphertext).
// `aad` may be empty (nullptr/0) to match a call with associated_data=None.
std::vector<uint8_t> aead_encrypt(const Bytes32& key, const uint8_t* plaintext, size_t len,
                                   const uint8_t* aad, size_t aad_len);

// Inverse of aead_encrypt. Throws std::runtime_error on authentication
// failure (tampered ciphertext, wrong key, or mismatched AAD) -- the
// same failure mode Python's AESGCM.decrypt raising InvalidTag maps to.
std::vector<uint8_t> aead_decrypt(const Bytes32& key, const uint8_t* payload, size_t payload_len,
                                   const uint8_t* aad, size_t aad_len);

}  // namespace pfs_engine
