"""
Restricted files: content only chosen users can read.

Every user of a vault can unlock it, so ordinary content is readable by all
of them. A restricted file's content is sealed before the engine stores it:

  a fresh random file key encrypts the content (AES-256-GCM), and the file
  key is wrapped once per chosen user, to that user's X25519 public key
  (an ephemeral key exchange, HKDF-SHA256 and AES-256-GCM).

The engine then stores the sealed bytes like any other file (encrypted again
with the vault's keys). Users not on the list see only sealed bytes, even
with their own passphrase. The list of users is readable by everyone who can
open the vault, so they know whom to ask.

Format: b"PFSR" + version byte + 4-byte header length + header (pickled
dict: recipients -> wrapped file key) + 12-byte nonce + ciphertext. The
header is the ciphertext's associated data, so it can't be altered.
"""

import os
import pickle
import struct
from typing import Dict, Iterable, List

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

MAGIC = b"PFSR"
VERSION = 1
RESTRICTED_TAG = "restricted"  # informational tag listing the users; the sealed content is what counts


class NotARecipientError(PermissionError):
    """The file is restricted to other users."""

    def __init__(self, recipients: List[str]):
        """Keeps the list of users who can read it."""
        self.recipients = list(recipients)
        super().__init__(f"This file is restricted to: {', '.join(self.recipients)}.")


def is_sealed(data: bytes) -> bool:
    """True if the content is a sealed (restricted) file."""
    return data[:5] == MAGIC + bytes([VERSION])


def _wrap_key(name: str, recipient_public: bytes, ephemeral_public: bytes) -> bytes:
    """The key that wraps a file key for one user, from the shared secret's inputs."""
    return name.encode() + b"\x00" + ephemeral_public + recipient_public


def _derive(shared: bytes, info: bytes) -> bytes:
    """HKDF-SHA256 of an X25519 shared secret."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"pfs-restricted-v1\x00" + info).derive(shared)


def _parse(data: bytes):
    """(header dict, header bytes, nonce, ciphertext) of sealed content."""
    if not is_sealed(data):
        raise ValueError("not a restricted file")
    (header_len,) = struct.unpack(">I", data[5:9])
    header_bytes = data[9:9 + header_len]
    rest = data[9 + header_len:]
    return pickle.loads(header_bytes), header_bytes, rest[:12], rest[12:]


def seal(content: bytes, recipients: Dict[str, bytes]) -> bytes:
    """Seals content so only these users ({name: raw public key}) can read it."""
    if not recipients:
        raise ValueError("A restricted file needs at least one user who can read it.")
    file_key = AESGCM.generate_key(bit_length=256)
    wrapped = {}
    for name, public in sorted(recipients.items()):
        ephemeral = X25519PrivateKey.generate()
        ephemeral_public = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(public))
        nonce = os.urandom(12)
        key = _derive(shared, _wrap_key(name, public, ephemeral_public))
        wrapped[name] = (ephemeral_public, nonce, AESGCM(key).encrypt(nonce, file_key, name.encode()))
    header_bytes = pickle.dumps({"recipients": wrapped})
    nonce = os.urandom(12)
    ciphertext = AESGCM(file_key).encrypt(nonce, content, header_bytes)
    return MAGIC + bytes([VERSION]) + struct.pack(">I", len(header_bytes)) + header_bytes + nonce + ciphertext


def recipients_of(data: bytes) -> List[str]:
    """The users a sealed file is restricted to."""
    return sorted(_parse(data)[0]["recipients"])


def unseal(data: bytes, name: str, private_key: bytes) -> bytes:
    """The content of a sealed file, for user `name`. NotARecipientError if
    they aren't on its list; ValueError if it was altered."""
    header, header_bytes, nonce, ciphertext = _parse(data)
    recipients = header["recipients"]
    if name not in recipients or private_key is None:
        raise NotARecipientError(sorted(recipients))
    ephemeral_public, wrap_nonce, wrapped_key = recipients[name]
    private = X25519PrivateKey.from_private_bytes(private_key)
    own_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    key = _derive(private.exchange(X25519PublicKey.from_public_bytes(ephemeral_public)),
                  _wrap_key(name, own_public, ephemeral_public))
    try:
        file_key = AESGCM(key).decrypt(wrap_nonce, wrapped_key, name.encode())
        return AESGCM(file_key).decrypt(nonce, ciphertext, header_bytes)
    except Exception:
        raise ValueError("This restricted file has been altered or damaged.")


def open_content(data: bytes, user) -> bytes:
    """Content as the user can read it: unsealed if restricted to them,
    unchanged if not restricted. user: master_key_store.UserKeys or None."""
    if not is_sealed(data):
        return data
    if user is None:
        raise NotARecipientError(recipients_of(data))
    return unseal(data, user.name, user.private_key)


def reseal_like(previous: bytes, content: bytes, all_public_keys: Dict[str, bytes]) -> bytes:
    """content sealed for the same users as `previous` (if it was sealed and
    they still exist); content unchanged if previous wasn't sealed."""
    if not is_sealed(previous):
        return content
    keep = {n: all_public_keys[n] for n in recipients_of(previous) if n in all_public_keys}
    if not keep:
        raise ValueError("None of the users this file was restricted to still exist.")
    return seal(content, keep)


def recipients_for(names: Iterable[str], all_public_keys: Dict[str, bytes], current_user: str) -> Dict[str, bytes]:
    """{name: public key} for a restriction, always including the current
    user (or they would lock themselves out). ValueError for unknown users."""
    chosen = set(names) | {current_user}
    unknown = sorted(chosen - set(all_public_keys))
    if unknown:
        raise ValueError(f"No such user: {', '.join(unknown)}.")
    return {name: all_public_keys[name] for name in chosen}
