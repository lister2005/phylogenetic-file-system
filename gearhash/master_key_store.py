"""
Passphrase-protected master key (KEK) file, with one slot per user.

Each user has their own passphrase:
  passphrase --scrypt--> wrapping key --AES-256-GCM--> the vault's KEK
so every user unlocks the same vault. Each user also has an X25519 key
pair: the public key is stored openly, the private key wrapped by the same
wrapping key. Other users seal restricted files to that public key
(restricted.py). The list of users and their public keys is authenticated
with an HMAC keyed by the KEK, so someone with only filesystem access can't
slip in a key of their own.

Older vaults have a single unnamed slot (format 1). Unlocking one with
unlock_user() upgrades it to format 2 with one user, "owner".

The file holds names, salts and wrapped keys only, so filesystem access
alone can't decrypt the vault.
"""

import hashlib
import hmac
import os
import pickle
from typing import Dict, List, NamedTuple, Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from .immutability import set_immutable

MASTER_KEY_FILENAME = "master.key"
DEFAULT_USER = "owner"
FORMAT_VERSION = 2

# Scrypt cost: n=2**15 is roughly 200-400 ms, slow to brute-force but fine once per session.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
KEK_SIZE = 32


class WrongPassphraseError(Exception):
    """The passphrase doesn't unwrap the stored KEK (for that user, or any user)."""


class UserError(ValueError):
    """A user can't be added or removed (duplicate, unknown, last user, bad name)."""


class UserKeys(NamedTuple):
    """Who unlocked the vault, the vault's KEK, and that user's private key (raw 32 bytes)."""
    name: str
    kek: bytes
    private_key: bytes


def _derive_wrapping_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    """Turns the passphrase into a 32-byte key with scrypt (deliberately slow, to resist guessing)."""
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def _path(storage_root: str) -> str:
    """The key file's path."""
    return os.path.join(storage_root, MASTER_KEY_FILENAME)


def _read_state(storage_root: str) -> dict:
    """The key file's contents; FileNotFoundError if there is none."""
    path = _path(storage_root)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No key file at {path}. Use create_new_vault_key() to make one.")
    with open(path, "rb") as f:
        return pickle.load(f)


def _check_name(name: str) -> str:
    """A user name: 1-32 letters, digits, '.', '_' or '-'."""
    name = (name or "").strip()
    if not name or len(name) > 32 or not all(c.isalnum() or c in "._-" for c in name):
        raise UserError("A user name must be 1-32 letters, digits, '.', '_' or '-'.")
    return name


def _make_slot(name: str, passphrase: str, kek: bytes) -> dict:
    """A user's slot: the KEK and a new private key, both wrapped under their passphrase."""
    salt = os.urandom(SALT_SIZE)
    wrapping = AESGCM(_derive_wrapping_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P))
    private = X25519PrivateKey.generate()
    private_raw = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    iv, priv_iv = os.urandom(12), os.urandom(12)
    return {
        "salt": salt, "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "iv": iv, "wrapped_kek": wrapping.encrypt(iv, kek, b"master-kek-wrap"),
        "priv_iv": priv_iv,
        "wrapped_private": wrapping.encrypt(priv_iv, private_raw, b"user-private-key:" + name.encode()),
        "public_key": private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw),
    }


def _users_mac(kek: bytes, users: dict) -> bytes:
    """HMAC over every user's name and public key, keyed by the KEK."""
    message = b"".join(name.encode() + b"\x00" + users[name]["public_key"] for name in sorted(users))
    return hmac.new(kek, b"pfs-users-v2\x00" + message, hashlib.sha256).digest()


def _write_users(storage_root: str, kek: bytes, users: dict) -> None:
    """Writes a format-2 key file with these slots."""
    state = {"version": FORMAT_VERSION, "users": users, "users_mac": _users_mac(kek, users)}
    _atomic_write(_path(storage_root), pickle.dumps(state))


def _try_slot(slot: dict, passphrase: str, name: Optional[str]):
    """(kek, private key raw or None) if the passphrase opens this slot, else None."""
    wrapping = AESGCM(_derive_wrapping_key(passphrase, slot["salt"], slot["n"], slot["r"], slot["p"]))
    try:
        kek = wrapping.decrypt(slot["iv"], slot["wrapped_kek"], b"master-kek-wrap")
    except Exception:
        return None
    private = None
    if name is not None and "wrapped_private" in slot:
        private = wrapping.decrypt(slot["priv_iv"], slot["wrapped_private"], b"user-private-key:" + name.encode())
    return kek, private


def create_new_vault_key(storage_root: str, passphrase: str, user: str = DEFAULT_USER) -> bytes:
    """Creates a random KEK and a key file with one user; returns the KEK. Won't overwrite."""
    if os.path.exists(_path(storage_root)):
        raise FileExistsError(
            f"{_path(storage_root)} already exists. Load it with load_vault_key(), or "
            f"remove it explicitly if you really mean to start over."
        )
    name = _check_name(user)
    kek = AESGCM.generate_key(bit_length=256)
    _write_users(storage_root, kek, {name: _make_slot(name, passphrase, kek)})
    return kek


def unlock_user(storage_root: str, passphrase: str, user: Optional[str] = None) -> UserKeys:
    """Unlocks the vault as the user whose passphrase this is (or as `user`,
    trying only that slot). Upgrades a format-1 file to one user, "owner".
    Raises WrongPassphraseError if no slot opens."""
    state = _read_state(storage_root)
    if state.get("version") != FORMAT_VERSION:
        opened = _try_slot(state, passphrase, None)
        if opened is None or (user is not None and user != DEFAULT_USER):
            raise WrongPassphraseError("Passphrase does not unwrap this key file.")
        kek = opened[0]
        _write_users(storage_root, kek, {DEFAULT_USER: _make_slot(DEFAULT_USER, passphrase, kek)})
        state = _read_state(storage_root)
    users = state["users"]
    names = [user] if user is not None else list(users)
    for name in names:
        if name not in users:
            continue
        opened = _try_slot(users[name], passphrase, name)
        if opened is not None:
            kek, private = opened
            if not hmac.compare_digest(state["users_mac"], _users_mac(kek, users)):
                raise WrongPassphraseError("The key file's list of users has been tampered with.")
            return UserKeys(name, kek, private)
    raise WrongPassphraseError("Passphrase does not unwrap this key file.")


def load_vault_key(storage_root: str, passphrase: str, user: Optional[str] = None) -> bytes:
    """Unwraps the KEK with any user's passphrase (or `user`'s). Raises WrongPassphraseError."""
    return unlock_user(storage_root, passphrase, user).kek


def list_users(storage_root: str) -> List[str]:
    """The vault's user names (stored openly in the key file)."""
    state = _read_state(storage_root)
    if state.get("version") != FORMAT_VERSION:
        return [DEFAULT_USER]
    return sorted(state["users"])


def public_keys(storage_root: str, kek: bytes) -> Dict[str, bytes]:
    """{user name: raw X25519 public key}, after checking the list wasn't tampered with."""
    state = _read_state(storage_root)
    if state.get("version") != FORMAT_VERSION:
        return {}
    users = state["users"]
    if not hmac.compare_digest(state["users_mac"], _users_mac(kek, users)):
        raise UserError("The key file's list of users has been tampered with.")
    return {name: slot["public_key"] for name, slot in users.items()}


def add_user(storage_root: str, kek: bytes, name: str, passphrase: str) -> None:
    """Adds a user with their own passphrase (the caller has unlocked the vault)."""
    name = _check_name(name)
    state = _read_state(storage_root)
    public_keys(storage_root, kek)  # refuses a tampered list
    users = dict(state["users"])
    if name in users:
        raise UserError(f"There is already a user called '{name}'.")
    users[name] = _make_slot(name, passphrase, kek)
    _write_users(storage_root, kek, users)


def remove_user(storage_root: str, kek: bytes, name: str) -> None:
    """Removes a user's slot, so their passphrase no longer opens the vault. Refuses the last user."""
    state = _read_state(storage_root)
    public_keys(storage_root, kek)
    users = dict(state["users"])
    if name not in users:
        raise UserError(f"There is no user called '{name}'.")
    if len(users) == 1:
        raise UserError("That is the only user; a vault needs at least one.")
    del users[name]
    _write_users(storage_root, kek, users)


def change_passphrase(storage_root: str, old_passphrase: str, new_passphrase: str,
                      user: Optional[str] = None) -> None:
    """Re-wraps the KEK and private key of the user whose old passphrase this
    is, under a new passphrase. Their key pair and the vault data are untouched."""
    keys = unlock_user(storage_root, old_passphrase, user)
    state = _read_state(storage_root)
    users = dict(state["users"])
    slot = dict(users[keys.name])
    salt = os.urandom(SALT_SIZE)
    wrapping = AESGCM(_derive_wrapping_key(new_passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P))
    iv, priv_iv = os.urandom(12), os.urandom(12)
    slot.update({
        "salt": salt, "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "iv": iv, "wrapped_kek": wrapping.encrypt(iv, keys.kek, b"master-kek-wrap"),
        "priv_iv": priv_iv,
        "wrapped_private": wrapping.encrypt(priv_iv, keys.private_key, b"user-private-key:" + keys.name.encode()),
    })
    users[keys.name] = slot
    _write_users(storage_root, keys.kek, users)


def _atomic_write(path: str, data: bytes) -> None:
    """Temp file + rename: never a partially written key file."""
    if os.path.exists(path):
        set_immutable(path, False)
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
    set_immutable(path, True)
