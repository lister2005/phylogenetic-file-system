import os
import hashlib
from gearhash.crypto import CryptoEngine
from gearhash.fks_index import FKSLookupEngine
from gearhash.dedup_index import GlobalBlockIndex
from gearhash.keyring import KeyRing
from gearhash.pipeline import MIRROR_CONTAINER_FILENAME


class ReconstructionError(Exception):
    """Raised when reconstruction can't be verified as complete and correct."""


def reconstruct(manifest_path: str, container_path: str, output_path: str, master_key: bytes):
    if not os.path.exists(manifest_path) or not os.path.exists(container_path):
        raise FileNotFoundError("Manifest or Container missing. Did the pipeline finish?")

    storage_root = os.path.dirname(container_path)
    crypto = CryptoEngine(master_key)
    keyring = KeyRing(storage_root, crypto.key)  # crypto.key is the KEK here

    manifest_filename = os.path.basename(manifest_path)
    with open(manifest_path, "rb") as f:
        encrypted_manifest = f.read()
    # Must match the AAD used when the manifest was written. Wrong key or
    # a swapped-in manifest file both fail loudly here.
    raw_manifest = crypto.decrypt_block(encrypted_manifest, associated_data=manifest_filename.encode())
    engine = FKSLookupEngine(raw_bytes=raw_manifest)

    global_index = GlobalBlockIndex(storage_root, crypto)

    expected_blocks = engine.metadata.get("total_blocks")
    expected_size = engine.metadata.get("original_size")
    expected_hash = engine.metadata.get("content_sha256")

    if expected_blocks is None:
        raise ReconstructionError(
            "Manifest is missing block-count metadata (older pipeline "
            "version?) -- can't verify reconstruction completeness."
        )

    mirror_container_path = os.path.join(storage_root, MIRROR_CONTAINER_FILENAME)

    hasher = hashlib.sha256()
    bytes_written = 0

    with open(container_path, "rb") as container, open(output_path, "wb") as out_file:
        mirror_container = None
        try:
            for idx in range(expected_blocks):
                content_hash = engine.lookup(idx)
                if content_hash is None:
                    raise ReconstructionError(
                        f"Manifest declares {expected_blocks} blocks but block "
                        f"{idx} is missing -- aborting instead of silently "
                        f"writing a truncated file."
                    )

                location = global_index.lookup(content_hash)
                if location is None:
                    raise ReconstructionError(
                        f"Block {idx} (hash {content_hash.hex()[:16]}...) is "
                        f"referenced by this file's manifest but missing from "
                        f"the global block index -- container/index desync."
                    )
                offset, length, _ref_count, epoch_id = location
                dek = keyring.get_dek(epoch_id)

                # Try the primary copy first. Must match the AAD used at
                # encryption time -- if this physical block was substituted
                # or corrupted, decryption raises or the hash won't match,
                # instead of silently returning the wrong plaintext.
                plaintext = None
                primary_error = None
                try:
                    container.seek(offset)
                    payload = container.read(length)
                    candidate = crypto.decrypt_block(payload, key=dek, associated_data=content_hash)
                    if hashlib.sha256(candidate).digest() == content_hash:
                        plaintext = candidate
                    else:
                        primary_error = "decrypted content hash doesn't match the manifest's record"
                except Exception as e:
                    primary_error = f"{type(e).__name__}: {e}"

                if plaintext is None:
                    # Ancestral Hardening fallback: this chunk may have a
                    # redundant copy (see StoragePipeline.MIRROR_REF_THRESHOLD)
                    # if it was shared widely enough to warrant one. Try it
                    # before giving up -- but always SURFACE that the primary
                    # was bad, never silently paper over real corruption.
                    mirror_location = global_index.get_mirror(content_hash)
                    if mirror_location is not None and os.path.exists(mirror_container_path):
                        if mirror_container is None:
                            mirror_container = open(mirror_container_path, "rb")
                        mirror_offset, mirror_length = mirror_location
                        try:
                            mirror_container.seek(mirror_offset)
                            mirror_payload = mirror_container.read(mirror_length)
                            candidate = crypto.decrypt_block(mirror_payload, key=dek, associated_data=content_hash)
                            if hashlib.sha256(candidate).digest() == content_hash:
                                plaintext = candidate
                                print(f"WARNING: block {idx} (hash {content_hash.hex()[:16]}...) failed "
                                      f"on its primary copy ({primary_error}) -- recovered from its "
                                      f"Ancestral Hardening mirror instead. The primary copy is damaged; "
                                      f"run 'verify' to repair it.")
                        except Exception:
                            pass  # mirror also failed -- plaintext stays None, handled below

                if plaintext is None:
                    raise ReconstructionError(
                        f"Block {idx} (hash {content_hash.hex()[:16]}...) failed integrity "
                        f"verification on its primary copy ({primary_error}), and either has no "
                        f"Ancestral Hardening mirror or the mirror also failed -- this data is "
                        f"genuinely unrecoverable."
                    )

                out_file.write(plaintext)
                hasher.update(plaintext)
                bytes_written += len(plaintext)
        finally:
            if mirror_container is not None:
                mirror_container.close()

    if expected_size is not None and bytes_written != expected_size:
        raise ReconstructionError(
            f"Reconstructed {bytes_written} bytes, expected {expected_size}. "
            f"File is incomplete or corrupt."
        )

    if expected_hash is not None and hasher.hexdigest() != expected_hash:
        raise ReconstructionError(
            "Reconstructed content hash does not match the manifest's "
            "recorded hash -- possible block substitution or corruption."
        )

    print(f"Reconstruction complete and verified: {output_path}")