"""
Key hierarchy: envelope encryption with rotating Data Encryption Keys.

The master key (what's in master.key) becomes a Key-Encryption-Key (KEK).
It is NEVER used to encrypt file content directly -- its only job is to
wrap and unwrap per-epoch Data Encryption Keys (DEKs). File content is
always encrypted under the CURRENT epoch's DEK.

Why this matters:
- Blast radius: if a single DEK is ever compromised (leaked from memory,
  logged by accident, whatever), only the data written during that one
  epoch is exposed -- not the entire historical vault.
- Cheap rotation: rotating means generating one new 32-byte DEK and
  wrapping it. It does NOT mean re-encrypting existing data. A vault
  holding terabytes can rotate in microseconds.
- Cheap KEK rotation too: if the master key itself is ever suspected
  compromised, you can generate a new KEK and re-wrap every existing DEK
  under it (still just re-wrapping small keys, not touching bulk data),
  then discard the old KEK.

What this does NOT give you: true forward secrecy. An attacker who gets
the CURRENT master key can unwrap every DEK ever created, past and
present, because old DEKs must stay recoverable in order to read old
files. Deletion-based forward secrecy (where compromising today's key
can't expose yesterday's data) would require actively destroying old
DEKs, which would make the files encrypted under them permanently
unreadable -- not what a file store that needs to keep reading its own
history wants. This module gives you rotation and blast-radius
reduction, which is the achievable, honest version of "fixing" a single
static key -- not an unlimited security upgrade.
"""

import os
import pickle
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .immutability import set_immutable

KEYRING_FILENAME = "keyring.enc"


class KeyRing:
    def __init__(self, storage_root: str, kek: bytes):
        self.storage_root = storage_root
        self.kek = kek
        self.path = os.path.join(storage_root, KEYRING_FILENAME)

        self.deks: Dict[int, bytes] = {}  # epoch_id -> raw DEK (in memory only)
        self.current_epoch = -1

        self._load()

    def _wrap(self, epoch_id: int, dek: bytes) -> bytes:
        aead = AESGCM(self.kek)
        iv = os.urandom(12)
        aad = f"epoch:{epoch_id}".encode()
        return iv + aead.encrypt(iv, dek, aad)

    def _unwrap(self, epoch_id: int, wrapped: bytes) -> bytes:
        aead = AESGCM(self.kek)
        iv = wrapped[:12]
        ciphertext = wrapped[12:]
        aad = f"epoch:{epoch_id}".encode()
        return aead.decrypt(iv, ciphertext, aad)

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        with open(self.path, "rb") as f:
            wrapped_entries: Dict[int, bytes] = pickle.load(f)
        for epoch_id, wrapped_dek in wrapped_entries.items():
            self.deks[epoch_id] = self._unwrap(epoch_id, wrapped_dek)
        if wrapped_entries:
            self.current_epoch = max(wrapped_entries.keys())

    def _save(self) -> None:
        wrapped_entries = {
            epoch_id: self._wrap(epoch_id, dek) for epoch_id, dek in self.deks.items()
        }
        if os.path.exists(self.path):
            set_immutable(self.path, False)  # nothing to unset on first-ever write
        with open(self.path, "wb") as f:
            pickle.dump(wrapped_entries, f)
        set_immutable(self.path, True)

    def get_current_dek(self) -> Tuple[int, bytes]:
        """Returns (epoch_id, dek) for the active epoch. Creates epoch 0
        automatically if this is a brand new vault."""
        if self.current_epoch == -1:
            self.rotate()
        return self.current_epoch, self.deks[self.current_epoch]

    def get_dek(self, epoch_id: int) -> bytes:
        """Returns the DEK for a specific (possibly older) epoch --
        needed to decrypt a chunk that was written before the most
        recent rotation."""
        if epoch_id not in self.deks:
            raise KeyError(
                f"No DEK found for epoch {epoch_id} -- keyring is missing "
                f"an entry that existing data depends on."
            )
        return self.deks[epoch_id]

    def rotate(self) -> int:
        """Generates a fresh DEK for a new epoch and makes it current.
        Cheap: only wraps a new 32-byte key, never touches existing
        ciphertext. Returns the new epoch_id."""
        new_epoch = self.current_epoch + 1
        self.deks[new_epoch] = AESGCM.generate_key(bit_length=256)
        self.current_epoch = new_epoch
        self._save()
        return new_epoch

    def rewrap_under_new_kek(self, new_kek: bytes) -> None:
        """KEK rotation: re-wraps every existing DEK under a new master
        key. Still cheap -- only touches the small wrapped-DEK entries,
        never the bulk data those DEKs protect. Call this, then start
        using the new KEK for all future CryptoEngine/KeyRing instances."""
        self.kek = new_kek
        self._save()
