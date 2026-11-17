#!/usr/bin/env python3
"""
One-time, non-destructive migration of a Python-engine vault to the C++
engine's formats: .manifest.fks -> .manifest.pfsm, keyring.enc ->
keyring.pfsk, lineage.enc -> lineage.pfsl, catalog.enc -> catalog.pfsc
(each format is described in its header under cpp_engine/include/).
New files are written alongside the originals, which are never touched.

Python, because the old formats are pickle. Lineage is loaded with
lineage.py's own LineageStore (which handles every older format).
Wrapped DEKs (IV + ciphertext + tag, 60 bytes) are copied as-is -- the
wrapping scheme is the same in both engines; manifests are decrypted and
re-encoded.
"""
import os
import sys
import struct
import pickle
import getpass
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gearhash.fks_index import FKSLookupEngine
from gearhash.pipeline import read_similarity_fingerprint
from gearhash.crypto import CryptoEngine
from gearhash.master_key_store import load_vault_key, WrongPassphraseError
from lineage import LineageStore

KEYRING_WRAPPED_ENTRY_SIZE = 12 + 32 + 16  # IV + ciphertext + GCM tag


def _atomic_write(path: str, data: bytes) -> None:
    """Writes data to a temporary file, syncs it, then renames it over path, so a crash never leaves half a file."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def migrate_manifest(old_path: str, crypto: CryptoEngine) -> str:
    """Returns the new manifest's path."""
    old_filename = os.path.basename(old_path)
    with open(old_path, "rb") as f:
        encrypted = f.read()
    raw = crypto.decrypt_block(encrypted, associated_data=old_filename.encode())
    engine = FKSLookupEngine(raw_bytes=raw)
    meta = engine.metadata

    total_blocks = meta["total_blocks"]
    block_hashes = []
    for i in range(total_blocks):
        h = engine.lookup(i)
        if h is None:
            raise ValueError(f"{old_path}: manifest declares {total_blocks} blocks but block {i} is missing")
        block_hashes.append(h)

    content_sha256_hex = meta["content_sha256"]
    content_sha256 = bytes.fromhex(content_sha256_hex)

    buf = bytearray()
    buf += b"PFSM"
    buf += struct.pack("<H", 1)  # version

    filename_bytes = meta["original_filename"].encode("utf-8")
    buf += struct.pack("<H", len(filename_bytes)) + filename_bytes
    buf += content_sha256
    buf += struct.pack(
        "<QQQQ",
        total_blocks,
        meta["original_size"],
        meta["new_chunks_written"],
        meta["duplicate_chunks_found"],
    )
    buf += struct.pack("<I", meta.get("phenotype_mask", 0))
    phenotype_bytes = meta.get("phenotype_name", "Unknown Binary").encode("utf-8")
    buf += struct.pack("<H", len(phenotype_bytes)) + phenotype_bytes

    fingerprint = read_similarity_fingerprint(old_path, crypto, meta)
    if fingerprint:
        # Sorted, as pfs_engine::Manifest normalizes them.
        sorted_fp = sorted(fingerprint)
        buf += struct.pack("<B", 1)
        buf += struct.pack("<I", len(sorted_fp))
        for h in sorted_fp:
            buf += h
    else:
        buf += struct.pack("<B", 0)

    for h in block_hashes:
        buf += h

    new_filename = f"{content_sha256_hex}.manifest.pfsm"
    new_path = os.path.join(os.path.dirname(old_path), new_filename)
    encrypted_new = crypto.encrypt_block(bytes(buf), associated_data=new_filename.encode())
    _atomic_write(new_path, encrypted_new)
    return new_path


def migrate_keyring(old_path: str) -> str:
    """Converts a Python-engine keyring (pickled) into the C++ engine's PFSK format and returns the new path."""
    with open(old_path, "rb") as f:
        wrapped_entries = pickle.load(f)  # Dict[int, bytes]

    buf = bytearray()
    buf += b"PFSK"
    buf += struct.pack("<H", 1)
    buf += struct.pack("<I", len(wrapped_entries))
    for epoch_id in sorted(wrapped_entries.keys()):
        wrapped = wrapped_entries[epoch_id]
        if len(wrapped) != KEYRING_WRAPPED_ENTRY_SIZE:
            raise ValueError(
                f"epoch {epoch_id}: wrapped DEK is {len(wrapped)} bytes, "
                f"expected exactly {KEYRING_WRAPPED_ENTRY_SIZE} -- unexpected keyring.py format?"
            )
        buf += struct.pack("<I", epoch_id)
        buf += wrapped

    new_path = os.path.join(os.path.dirname(old_path), "keyring.pfsk")
    _atomic_write(new_path, bytes(buf))
    return new_path


def _encode_lineage_node(node) -> bytes:
    """Same fields as lineage_store.cpp's write_node(), little-endian (the
    outer record framing stays big-endian, as in Python).
    """
    buf = bytearray()
    buf += bytes.fromhex(node.node_uuid)
    if node.parent_uuid is not None:
        buf += struct.pack("<B", 1)
        buf += bytes.fromhex(node.parent_uuid)
    else:
        buf += struct.pack("<B", 0)

    buf += struct.pack("<I", len(node.lateral_parent_uuids))
    for uuid_hex in node.lateral_parent_uuids:
        buf += bytes.fromhex(uuid_hex)

    label_bytes = node.label.encode("utf-8")
    buf += struct.pack("<H", len(label_bytes)) + label_bytes

    if node.manifest_filename is not None:
        buf += struct.pack("<B", 1)
        mf_bytes = node.manifest_filename.encode("utf-8")
        buf += struct.pack("<H", len(mf_bytes)) + mf_bytes
    else:
        buf += struct.pack("<B", 0)

    buf += struct.pack("<QdQQ", node.generation_index, node.birth_timestamp, node.new_chunks, node.total_chunks)
    buf += struct.pack("<B", 1 if node.pruned else 0)

    buf += struct.pack("<I", len(node.epigenetic_tags))
    for key, value in node.epigenetic_tags.items():
        key_bytes = key.encode("utf-8")
        buf += struct.pack("<H", len(key_bytes)) + key_bytes
        if isinstance(value, bool):
            buf += struct.pack("<B", 0)  # type 0 = bool
            buf += struct.pack("<B", 1 if value else 0)
        else:
            buf += struct.pack("<B", 1)  # type 1 = string
            value_bytes = str(value).encode("utf-8")
            buf += struct.pack("<H", len(value_bytes)) + value_bytes

    return bytes(buf)


def migrate_lineage(storage_root: str, crypto: CryptoEngine) -> str:
    """Loads lineage.enc with lineage.py's LineageStore and writes one snapshot
    record in the new format, keeping every node field.
    """
    store = LineageStore(storage_root, crypto)  # also migrates the oldest format

    all_nodes = []
    for label in store.all_labels():
        all_nodes.extend(store.get_history(label))

    # Little-endian node count (the snapshot body), unlike the big-endian
    # outer frame length below.
    body = bytearray()
    body += struct.pack("<I", len(all_nodes))
    for node in all_nodes:
        body += _encode_lineage_node(node)

    encrypted = crypto.encrypt_block(bytes(body), associated_data=b"lineage_snapshot")

    framed = bytearray()
    framed += b"PFSLIN01"
    framed += b"S"
    framed += struct.pack(">I", len(encrypted))
    framed += encrypted

    new_path = os.path.join(storage_root, "lineage.pfsl")
    _atomic_write(new_path, bytes(framed))
    return new_path, len(all_nodes)


def migrate_catalog(storage_root: str, crypto: CryptoEngine) -> str:
    """catalog.enc is a pickled {label: manifest_filename}."""
    old_path = os.path.join(storage_root, "catalog.enc")
    with open(old_path, "rb") as f:
        encrypted = f.read()
    raw = crypto.decrypt_block(encrypted, associated_data=b"catalog")
    catalog = pickle.loads(raw)  # Dict[str, str]

    buf = bytearray()
    buf += b"PFSC"
    buf += struct.pack("<H", 1)
    buf += struct.pack("<I", len(catalog))
    for label, manifest_filename in catalog.items():
        label_bytes = label.encode("utf-8")
        mf_bytes = manifest_filename.encode("utf-8")
        buf += struct.pack("<H", len(label_bytes)) + label_bytes
        buf += struct.pack("<H", len(mf_bytes)) + mf_bytes

    new_path = os.path.join(storage_root, "catalog.pfsc")
    encrypted_new = crypto.encrypt_block(bytes(buf), associated_data=b"catalog")
    _atomic_write(new_path, encrypted_new)
    return new_path, len(catalog)


def main():
    """Command-line entry point: converts the Python vault at storage_root to the C++ engine's format."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("storage_root", help="Path to the vault's storage root")
    args = parser.parse_args()

    storage_root = args.storage_root
    if not os.path.isdir(storage_root):
        print(f"Not a directory: {storage_root}")
        sys.exit(1)

    passphrase = getpass.getpass("Vault passphrase: ")
    try:
        kek = load_vault_key(storage_root, passphrase)
    except WrongPassphraseError:
        print("Wrong passphrase.")
        sys.exit(1)
    crypto = CryptoEngine(kek)

    keyring_path = os.path.join(storage_root, "keyring.enc")
    if os.path.exists(keyring_path):
        new_path = migrate_keyring(keyring_path)
        print(f"Migrated keyring -> {os.path.basename(new_path)}")
    else:
        print("No keyring.enc found -- nothing to migrate for the keyring.")

    lineage_path = os.path.join(storage_root, "lineage.enc")
    if os.path.exists(lineage_path):
        new_path, node_count = migrate_lineage(storage_root, crypto)
        print(f"Migrated lineage store ({node_count} generation(s) across all labels) -> "
              f"{os.path.basename(new_path)}")
    else:
        print("No lineage.enc found -- nothing to migrate for the lineage store.")

    catalog_path = os.path.join(storage_root, "catalog.enc")
    if os.path.exists(catalog_path):
        new_path, entry_count = migrate_catalog(storage_root, crypto)
        print(f"Migrated catalog ({entry_count} label(s)) -> {os.path.basename(new_path)}")
    else:
        print("No catalog.enc found -- nothing to migrate for the catalog.")

    manifest_files = [f for f in os.listdir(storage_root) if f.endswith(".manifest.fks")]
    migrated = 0
    failed = 0
    for fname in manifest_files:
        old_path = os.path.join(storage_root, fname)
        try:
            new_path = migrate_manifest(old_path, crypto)
            print(f"Migrated {fname} -> {os.path.basename(new_path)}")
            migrated += 1
        except Exception as e:
            print(f"FAILED to migrate {fname}: {e}")
            failed += 1

    print(f"\n{migrated} manifest(s) migrated, {failed} failed, out of {len(manifest_files)} found.")
    print("Original files were left untouched -- this vault still works normally with the Python engine.")


if __name__ == "__main__":
    main()
