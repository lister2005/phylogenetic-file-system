#!/usr/bin/env python3
"""
Passphrase launcher for the C++ FUSE driver, which takes its KEK in
PFS_KEK_HEX. The passphrase -> KEK step (scrypt) stays in Python
(master_key_store), as everywhere else; this derives the KEK and
os.execv()s the binary, so the key is never on disk or in argv.

Usage:
  python3 mount_pfs_cpp.py <storage_root> <mountpoint> [fuse options...]

Foreground only. Unmount with fusermount3 -u <mountpoint>.
"""
import getpass
import os
import sys

from gearhash.master_key_store import (
    create_new_vault_key, load_vault_key, WrongPassphraseError, MASTER_KEY_FILENAME,
)

_CPP_BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "cpp_engine", "build", "pfs_fuse_cpp")

# The engines' marker files (as in pfs_cli.py), without importing the whole shell.
_CPP_CATALOG_FILENAME = "catalog.pfsc"
_CPP_KEYRING_FILENAME = "keyring.pfsk"
_PY_CATALOG_FILENAME = "catalog.enc"
_PY_KEYRING_FILENAME = "keyring.enc"


def _existing_vault_engine(storage_root: str):
    """Returns 'python', 'cpp', or None (nothing here yet)."""
    is_python = os.path.exists(os.path.join(storage_root, _PY_CATALOG_FILENAME)) or \
        os.path.exists(os.path.join(storage_root, _PY_KEYRING_FILENAME))
    is_cpp = os.path.exists(os.path.join(storage_root, _CPP_CATALOG_FILENAME)) or \
        os.path.exists(os.path.join(storage_root, _CPP_KEYRING_FILENAME))
    if is_python:
        return "python"
    if is_cpp:
        return "cpp"
    return None


def unlock_or_create(storage_root: str) -> bytes:
    """Prompts on the terminal and returns the 32-byte KEK."""
    os.makedirs(storage_root, exist_ok=True)

    engine = _existing_vault_engine(storage_root)
    if engine == "python":
        print(f"'{storage_root}' is a PYTHON-engine vault (catalog.enc/keyring.enc present). "
              f"The C++ FUSE driver uses different, incompatible file formats and would corrupt "
              f"it. Point this at a different, empty directory, or mount the existing vault with "
              f"pfs_fuse.py instead.")
        sys.exit(1)

    key_path = os.path.join(storage_root, MASTER_KEY_FILENAME)
    vault_existed = os.path.exists(key_path)
    if not vault_existed:
        print(f"No vault found at '{storage_root}'. Creating a new C++-engine vault.")
        pw1 = getpass.getpass("Set a new vault passphrase: ")
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw1 != pw2:
            print("Passphrases didn't match. Nothing created.")
            sys.exit(1)
        kek = create_new_vault_key(storage_root, pw1)
        print("New C++ vault created.")
    else:
        pw = getpass.getpass("Enter vault passphrase: ")
        try:
            kek = load_vault_key(storage_root, pw)
        except WrongPassphraseError:
            print("Wrong passphrase.")
            sys.exit(1)
        print("C++ vault unlocked.")
    return kek


def main():
    """Asks for the passphrase, derives the key and starts the C++ mount driver in the foreground."""
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <storage_root> <mountpoint> [fuse options...]")
        print("(prompts for the vault passphrase, derives the real KEK the same way "
              "pfs_cli.py --engine cpp does, then mounts the compiled C++ FUSE driver "
              "in the foreground -- unmount with: fusermount3 -u <mountpoint>)")
        sys.exit(1)

    storage_root = os.path.abspath(os.path.expanduser(sys.argv[1]))
    mountpoint = sys.argv[2]
    extra_args = sys.argv[3:]

    if not os.path.isfile(_CPP_BINARY) or not os.access(_CPP_BINARY, os.X_OK):
        print(f"Compiled binary not found (or not executable) at {_CPP_BINARY}.\n"
              f"Build it first: cd cpp_engine/build && cmake --build . -j4")
        sys.exit(1)

    kek = unlock_or_create(storage_root)

    # execv keeps the environment, so PFS_KEK_HEX reaches the binary without argv or disk.
    os.environ["PFS_KEK_HEX"] = kek.hex()

    print(f"Mounting at {mountpoint} (foreground). Unmount with: fusermount3 -u {mountpoint}")
    sys.stdout.flush()
    sys.stderr.flush()

    os.execv(_CPP_BINARY, [_CPP_BINARY, storage_root, mountpoint] + extra_args)


if __name__ == "__main__":
    main()
