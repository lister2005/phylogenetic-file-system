#include "crypto_utils.hpp"

#include <cstring>
#include <stdexcept>
#include <string>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>

namespace pfs_engine {

// SHA-256 of a buffer.
Bytes32 sha256(const uint8_t* data, size_t len) {
    Bytes32 out{};
    unsigned int out_len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out.data(), &out_len);
    EVP_MD_CTX_free(ctx);
    return out;
}

// HMAC-SHA-256 of a buffer under a key.
Bytes32 hmac_sha256(const Bytes32& key, const uint8_t* data, size_t len) {
    Bytes32 out{};
    unsigned int out_len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data, len, out.data(), &out_len);
    return out;
}

// Derives a 32-byte subkey from a key and a purpose label (HKDF-SHA-256).
Bytes32 hkdf_sha256(const Bytes32& ikm, const std::string& info) {
    Bytes32 out{};
    uint8_t zero_salt[32] = {0};

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* ctx = EVP_KDF_CTX_new(kdf);

    OSSL_PARAM params[5];
    int p = 0;
    params[p++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char*)"SHA256", 0);
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (void*)ikm.data(), ikm.size());
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, zero_salt, sizeof(zero_salt));
    params[p++] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, (void*)info.data(), info.size());
    params[p++] = OSSL_PARAM_construct_end();

    bool ok = EVP_KDF_derive(ctx, out.data(), out.size(), params) > 0;
    EVP_KDF_CTX_free(ctx);
    EVP_KDF_free(kdf);
    if (!ok) throw std::runtime_error("HKDF derive failed");
    return out;
}

// AES-256-GCM encrypts under a fresh random IV; returns IV + ciphertext + tag.
std::vector<uint8_t> aead_encrypt(const Bytes32& key, const uint8_t* plaintext, size_t len,
                                   const uint8_t* aad, size_t aad_len) {
    std::vector<uint8_t> out(12 + len + 16);
    RAND_bytes(out.data(), 12);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), out.data());

    int outl = 0;
    if (aad_len > 0) EVP_EncryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len));

    int ct_len = 0;
    EVP_EncryptUpdate(ctx, out.data() + 12, &ct_len, plaintext, static_cast<int>(len));
    int final_len = 0;
    EVP_EncryptFinal_ex(ctx, out.data() + 12 + ct_len, &final_len);
    ct_len += final_len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.data() + 12 + ct_len);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

// Decrypts IV + ciphertext + tag, throwing if anything was tampered with.
std::vector<uint8_t> aead_decrypt(const Bytes32& key, const uint8_t* payload, size_t payload_len,
                                   const uint8_t* aad, size_t aad_len) {
    if (payload_len < 12 + 16) throw std::runtime_error("ciphertext too short");
    const uint8_t* iv = payload;
    const uint8_t* ct = payload + 12;
    size_t ct_len = payload_len - 12 - 16;
    const uint8_t* tag = payload + 12 + ct_len;

    std::vector<uint8_t> out(ct_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv);

    int outl = 0;
    if (aad_len > 0) EVP_DecryptUpdate(ctx, nullptr, &outl, aad, static_cast<int>(aad_len));

    int pt_len = 0;
    EVP_DecryptUpdate(ctx, out.data(), &pt_len, ct, static_cast<int>(ct_len));
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag));
    int final_len = 0;
    int ok = EVP_DecryptFinal_ex(ctx, out.data() + pt_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    if (ok <= 0) throw std::runtime_error("AES-GCM authentication failed (tampered or wrong key)");
    out.resize(pt_len + final_len);
    return out;
}

}  // namespace pfs_engine
