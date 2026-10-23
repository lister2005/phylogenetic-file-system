import os
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoEngine:
    """self.key is the KEK. File content is encrypted under a per-epoch DEK
    passed as `key`; manifests and index metadata use self.key directly.
    """
    def __init__(self, master_key: bytes = None) -> None:
        self.key = master_key if master_key else AESGCM.generate_key(bit_length=256)
        self.aead = AESGCM(self.key)  # direct .aead users
        self.total_encryption_time = 0.0

    def encrypt_block(self, plaintext: bytes, key: bytes = None, associated_data: bytes = None) -> bytes:
        start = time.perf_counter()
        aead = self.aead if key is None else AESGCM(key)
        iv = os.urandom(12)
        encrypted_payload = aead.encrypt(iv, plaintext, associated_data)
        self.total_encryption_time += (time.perf_counter() - start)
        return iv + encrypted_payload

    def decrypt_block(self, secured_payload: bytes, key: bytes = None, associated_data: bytes = None) -> bytes:
        aead = self.aead if key is None else AESGCM(key)
        iv = secured_payload[:12]
        ciphertext_with_tag = secured_payload[12:]
        return aead.decrypt(iv, ciphertext_with_tag, associated_data)