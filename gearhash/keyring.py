"""
Envelope encryption: the master key is a KEK that only wraps per-epoch
DEKs; content is encrypted under the current epoch's DEK.

Rotation creates and wraps a new DEK without re-encrypting anything, and
limits what one leaked DEK exposes. KEK rotation re-wraps the DEKs. Not
forward secrecy: the current KEK unwraps every DEK, since old data must
stay readable.
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

        self.deks: Dict[int, bytes] = {}  # epoch_id -> raw DEK, in memory only
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
            set_immutable(self.path, False)
        with open(self.path, "wb") as f:
            pickle.dump(wrapped_entries, f)
        set_immutable(self.path, True)

    def get_current_dek(self) -> Tuple[int, bytes]:
        """(epoch_id, dek) for the current epoch; creates epoch 0 in a new vault."""
        if self.current_epoch == -1:
            self.rotate()
        return self.current_epoch, self.deks[self.current_epoch]

    def get_dek(self, epoch_id: int) -> bytes:
        """The DEK for an older epoch."""
        if epoch_id not in self.deks:
            raise KeyError(
                f"No DEK found for epoch {epoch_id} -- keyring is missing "
                f"an entry that existing data depends on."
            )
        return self.deks[epoch_id]

    def rotate(self) -> int:
        """Makes a fresh DEK current. Returns the new epoch_id."""
        new_epoch = self.current_epoch + 1
        self.deks[new_epoch] = AESGCM.generate_key(bit_length=256)
        self.current_epoch = new_epoch
        self._save()
        return new_epoch

    def rewrap_under_new_kek(self, new_kek: bytes) -> None:
        """Re-wraps every DEK under a new KEK; bulk data is untouched."""
        self.kek = new_kek
        self._save()
