#!/usr/bin/env python3
"""
Interactive-passphrase launcher for the compiled C++ FUSE driver
(cpp_engine/build/pfs_fuse_cpp).

WHY THIS EXISTS: pfs_fuse_cpp.cpp takes its 32-byte KEK directly via the
PFS_KEK_HEX environment variable (see its own top-of-file comment) --
master_key_store.py's scrypt-based passphrase -> KEK derivation was
deliberately never ported to C++. This project's established split
(cpp_port_plan.txt's binding section, and c_api.h's own docstring):
Python keeps owning "passphrase -> KEK"; C++ owns "given a key, do fast
storage operations". Reimplementing scrypt natively in C++ would mean
maintaining a second, independent copy of security-critical KDF code
with no real benefit -- this script instead reuses the EXISTING,
ALREADY-CORRECT create_new_vault_key()/load_vault_key() (the same two
functions pfs_cli.py's CppPFSShell already calls to unlock a C++-engine
vault interactively), derives the real KEK, and then execs the compiled
binary with it -- no new crypto, just wiring the proven code up to the
FUSE entry point that was missing it.

Usage:
  python3 mount_pfs_cpp.py <storage_root> <mountpoint> [fuse options...]

Prompts for the vault passphrase on a real TTY (new vault: set +
confirm; existing vault: enter once), derives the KEK, sets
PFS_KEK_HEX in this process's environment, then os.execv()s the
compiled pfs_fuse_cpp binary -- replacing this process outright rather
than forking, so the KEK never sits around in a Python process that
then has to remember to clean it up, and never touches disk or a
command-line argument (visible to other users via `ps`).

Scope, deliberately matching pfs_fuse_cpp.cpp's own: foreground mount
only -- that binary doesn't daemonize itself (see its top-of-file
comment), so neither does this launcher. Unmount with
`fusermount3 -u <mountpoint>`, same as any other FUSE mount.
"""
import getpass
import os
import sys

from gearhash.master_key_store import (
    create_new_vault_key, load_vault_key, WrongPassphraseError, MASTER_KEY_FILENAME,
)

_CPP_BINARY = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "cpp_engine", "build", "pfs_fuse_cpp")

# The same marker files pfs_cli.py's _existing_vault_engine() checks --
# duplicated narrowly here (two filenames each) rather than importing
# pfs_cli.py itself, which would pull in the entire Python-engine
# interactive shell just to reuse a helper function.
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
    """Prompts on the controlling terminal and returns the real 32-byte
    KEK -- same create_new_vault_key()/load_vault_key() calls
    pfs_cli.py's CppPFSShell already makes, so a vault created/unlocked
    through one is fully interoperable with the other."""
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

    # Set in THIS process's environment, then exec (not fork+exec) --
    # execv replaces the process image in place but keeps the current
    # environment, so PFS_KEK_HEX carries straight over to the
    # replacement without ever being written to disk or passed as a
    # visible argv entry.
    os.environ["PFS_KEK_HEX"] = kek.hex()

    print(f"Mounting at {mountpoint} (foreground). Unmount with: fusermount3 -u {mountpoint}")
    sys.stdout.flush()
    sys.stderr.flush()

    os.execv(_CPP_BINARY, [_CPP_BINARY, storage_root, mountpoint] + extra_args)


if __name__ == "__main__":
    main()
