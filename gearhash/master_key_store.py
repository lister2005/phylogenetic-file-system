"""
Passphrase-protected master key storage.

The previous design stored the raw 32-byte KEK directly on disk with no
protection at all -- anyone with filesystem access could read it and
decrypt everything. This replaces that with standard envelope-around-a-
passphrase practice (the same idea LUKS, VeraCrypt, and age all use):

    passphrase --[Scrypt, slow+memory-hard]--> wrapping key
    wrapping key --[AES-256-GCM]--> wraps the real KEK

The file on disk holds: a random salt, the Scrypt parameters, and the
KEK ciphertext. None of that is useful to an attacker without the
passphrase -- Scrypt is deliberately expensive to brute-force, unlike
a fast hash.

This does NOT protect against a keylogger, a weak/guessable passphrase,
or someone who has both the file AND the passphrase. It protects against
exactly what the previous design failed at: filesystem access alone
being enough to decrypt the vault.
"""

import os
import pickle
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .immutability import set_immutable

MASTER_KEY_FILENAME = "master.key"

# Scrypt cost parameters. n=2**15 takes ~200-400ms on typical hardware --
# deliberately slow enough to make brute-forcing a stolen file expensive,
# fast enough not to be annoying for one passphrase entry per session.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SALT_SIZE = 16
KEK_SIZE = 32


class WrongPassphraseError(Exception):
    """Raised when the supplied passphrase doesn't unwrap the stored KEK."""


def _derive_wrapping_key(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


def create_new_vault_key(storage_root: str, passphrase: str) -> bytes:
    """Generates a brand new random KEK, wraps it under the given
    passphrase, and writes the wrapped form to disk. Returns the raw KEK
    for immediate use. Refuses to overwrite an existing key file --
    call load_vault_key or explicitly delete the old file first."""
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
    """Reads the wrapped key file and unwraps the KEK using the given
    passphrase. Raises WrongPassphraseError on a wrong passphrase --
    never silently returns garbage key material."""
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
    """Re-wraps the existing KEK under a new passphrase. Cheap -- only
    re-wraps 32 bytes, never touches any vault data. The actual KEK
    (and therefore every DEK and every byte of content) is completely
    unchanged; only what protects the key file changes."""
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
    """Write-temp-then-rename: the target path either has its old
    complete contents or the new complete contents, never a partial
    write, even if the process dies mid-write."""
    if os.path.exists(path):
        set_immutable(path, False)  # nothing to unset on a brand new file
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
    set_immutable(path, True)
