#pragma once
// Crypto primitives shared by the engine, matching gearhash/crypto.py and
// dedup_index.py byte for byte (see bench/hkdf_check.cpp).

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

// HKDF-SHA256 with salt=None, which Python's cryptography treats as 32 zero
// bytes (not an empty salt). `info` is UTF-8.
Bytes32 hkdf_sha256(const Bytes32& ikm, const std::string& info);

// AES-256-GCM: IV(12) || ciphertext || tag(16), as crypto.py's
// encrypt_block. Empty `aad` matches associated_data=None.
std::vector<uint8_t> aead_encrypt(const Bytes32& key, const uint8_t* plaintext, size_t len,
                                   const uint8_t* aad, size_t aad_len);

// Throws std::runtime_error on authentication failure.
std::vector<uint8_t> aead_decrypt(const Bytes32& key, const uint8_t* payload, size_t payload_len,
                                   const uint8_t* aad, size_t aad_len);

}  // namespace pfs_engine
