"""
Passphrase-protected master key (KEK) file.

passphrase --scrypt--> wrapping key --AES-256-GCM--> wrapped KEK. The file
holds the salt, scrypt parameters and wrapped KEK, so filesystem access
alone can't decrypt the vault.
"""

import os
import pickle
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .immutability import set_immutable

MASTER_KEY_FILENAME = "master.key"

# Scrypt cost: n=2**15 is roughly 200-400 ms, slow to brute-force but fine once per session.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
KEK_SIZE = 32


class WrongPassphraseError(Exception):
    """The passphrase doesn't unwrap the stored KEK."""


def _derive_wrapping_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def create_new_vault_key(storage_root: str, passphrase: str) -> bytes:
    """Creates a random KEK, writes it wrapped under `passphrase`, returns it. Won't overwrite."""
    path = os.path.join(storage_root, MASTER_KEY_FILENAME)
    if os.path.exists(path):
        raise FileExistsError(
            f"{path} already exists. Load it with load_vault_key(), or "
            f"remove it explicitly if you really mean to start over."
        )

    kek = AESGCM.generate_key(bit_length=256)
    salt = os.urandom(SALT_SIZE)
    wrapping_key = _derive_wrapping_key(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    aead = AESGCM(wrapping_key)
    iv = os.urandom(12)
    wrapped_kek = aead.encrypt(iv, kek, b"master-kek-wrap")

    state = {
        "salt": salt,
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "iv": iv,
        "wrapped_kek": wrapped_kek,
    }
    _atomic_write(path, pickle.dumps(state))

    return kek


def load_vault_key(storage_root: str, passphrase: str) -> bytes:
    """Unwraps the KEK. Raises WrongPassphraseError on a wrong passphrase."""
    path = os.path.join(storage_root, MASTER_KEY_FILENAME)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No key file at {path}. Use create_new_vault_key() to make one."
        )

    with open(path, "rb") as f:
        state = pickle.load(f)

    wrapping_key = _derive_wrapping_key(passphrase, state["salt"], state["n"], state["r"], state["p"])
    aead = AESGCM(wrapping_key)
    try:
        kek = aead.decrypt(state["iv"], state["wrapped_kek"], b"master-kek-wrap")
    except Exception:
        raise WrongPassphraseError("Passphrase does not unwrap this key file.")

    return kek


def change_passphrase(storage_root: str, old_passphrase: str, new_passphrase: str) -> None:
    """Re-wraps the same KEK under a new passphrase; vault data is untouched."""
    kek = load_vault_key(storage_root, old_passphrase)

    path = os.path.join(storage_root, MASTER_KEY_FILENAME)
    salt = os.urandom(SALT_SIZE)
    wrapping_key = _derive_wrapping_key(new_passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    aead = AESGCM(wrapping_key)
    iv = os.urandom(12)
    wrapped_kek = aead.encrypt(iv, kek, b"master-kek-wrap")

    state = {
        "salt": salt,
        "n": SCRYPT_N,
        "r": SCRYPT_R,
        "p": SCRYPT_P,
        "iv": iv,
        "wrapped_kek": wrapped_kek,
    }
    _atomic_write(path, pickle.dumps(state))


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
