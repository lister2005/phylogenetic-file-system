import os
import time  # Add this
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class CryptoEngine:
    """
    self.key holds the master Key-Encryption-Key (KEK). It's kept as a
    plain attribute (not renamed) so anything already reading
    crypto.key -- e.g. code that persists master.key to disk -- keeps
    working unchanged.

    Actual file content should be encrypted under a per-epoch Data
    Encryption Key (DEK) from a KeyRing, passed explicitly via the `key`
    argument below -- never under self.key directly. Manifest and
    global-index metadata still use self.key directly (no `key` passed),
    which is fine: metadata blast radius is inherently small, and the
    KeyRing itself has to be unwrapped by the KEK regardless, so there's
    no further hierarchy to gain by rotating metadata encryption too.
    """
    def __init__(self, master_key: bytes = None) -> None:
        self.key = master_key if master_key else AESGCM.generate_key(bit_length=256)
        self.aead = AESGCM(self.key)  # kept for backward compatibility with direct .aead use
        self.total_encryption_time = 0.0  # New: Internal accumulator

    def encrypt_block(self, plaintext: bytes, key: bytes = None, associated_data: bytes = None) -> bytes:
        start = time.perf_counter()  # Start timer
        aead = self.aead if key is None else AESGCM(key)
        iv = os.urandom(12)
        encrypted_payload = aead.encrypt(iv, plaintext, associated_data)
        self.total_encryption_time += (time.perf_counter() - start)  # Add to total
        return iv + encrypted_payload

    def decrypt_block(self, secured_payload: bytes, key: bytes = None, associated_data: bytes = None) -> bytes:
        aead = self.aead if key is None else AESGCM(key)
        iv = secured_payload[:12]
        ciphertext_with_tag = secured_payload[12:]
        return aead.decrypt(iv, ciphertext_with_tag, associated_data)