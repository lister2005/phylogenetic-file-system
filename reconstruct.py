import os
import bisect
import hashlib
from collections import OrderedDict
from gearhash.crypto import CryptoEngine
from gearhash.fks_index import FKSLookupEngine
from gearhash.dedup_index import GlobalBlockIndex
from gearhash.keyring import KeyRing
from gearhash.pipeline import MIRROR_CONTAINER_FILENAME

# AES-GCM bytes added per chunk: 12-byte IV + 16-byte tag. A chunk's
# plaintext length is its stored length minus this, which is how
# ManifestReader maps offsets to chunks.
AEAD_OVERHEAD = 28


class ReconstructionError(Exception):
    """Reconstruction can't be verified as complete and correct."""


def _open_manifest(manifest_path: str, crypto: CryptoEngine) -> FKSLookupEngine:
    manifest_filename = os.path.basename(manifest_path)
    with open(manifest_path, "rb") as f:
        encrypted_manifest = f.read()
    # AAD is the filename: a wrong key or a swapped manifest fails here.
    raw_manifest = crypto.decrypt_block(encrypted_manifest, associated_data=manifest_filename.encode())
    engine = FKSLookupEngine(raw_bytes=raw_manifest)
    if engine.metadata.get("total_blocks") is None:
        raise ReconstructionError(
            "Manifest is missing block-count metadata (older pipeline "
            "version?) -- can't verify reconstruction completeness."
        )
    return engine


def _manifest_block_hashes(engine: FKSLookupEngine) -> list:
    expected_blocks = engine.metadata["total_blocks"]
    hashes = []
    for idx in range(expected_blocks):
        content_hash = engine.lookup(idx)
        if content_hash is None:
            raise ReconstructionError(
                f"Manifest declares {expected_blocks} blocks but block "
                f"{idx} is missing -- aborting instead of silently "
                f"writing a truncated file."
            )
        hashes.append(content_hash)
    return hashes


def _missing_from_index(idx: int, content_hash: bytes) -> ReconstructionError:
    return ReconstructionError(
        f"Block {idx} (hash {content_hash.hex()[:16]}...) is "
        f"referenced by this file's manifest but missing from "
        f"the global block index -- container/index desync."
    )


class _BlockFetcher:
    """One chunk's verified plaintext: primary copy, then its Ancestral
    Hardening mirror. Shared by reconstruct() and ManifestReader.
    """

    def __init__(self, storage_root: str, container_path: str, crypto: CryptoEngine,
                 keyring: KeyRing, global_index: GlobalBlockIndex):
        self._crypto = crypto
        self._keyring = keyring
        self._global_index = global_index
        self._mirror_container_path = os.path.join(storage_root, MIRROR_CONTAINER_FILENAME)
        self._container = open(container_path, "rb")
        self._mirror_container = None

    def fetch(self, idx: int, content_hash: bytes, location) -> bytes:
        offset, length, _ref_count, epoch_id = location
        dek = self._keyring.get_dek(epoch_id)

        # Primary copy: AAD and SHA-256 must both match.
        plaintext = None
        primary_error = None
        try:
            self._container.seek(offset)
            payload = self._container.read(length)
            candidate = self._crypto.decrypt_block(payload, key=dek, associated_data=content_hash)
            if hashlib.sha256(candidate).digest() == content_hash:
                plaintext = candidate
            else:
                primary_error = "decrypted content hash doesn't match the manifest's record"
        except Exception as e:
            primary_error = f"{type(e).__name__}: {e}"

        if plaintext is None:
            # Mirror fallback, always reported -- never hide a damaged primary.
            mirror_location = self._global_index.get_mirror(content_hash)
            if mirror_location is not None and os.path.exists(self._mirror_container_path):
                if self._mirror_container is None:
                    self._mirror_container = open(self._mirror_container_path, "rb")
                mirror_offset, mirror_length = mirror_location
                try:
                    self._mirror_container.seek(mirror_offset)
                    mirror_payload = self._mirror_container.read(mirror_length)
                    candidate = self._crypto.decrypt_block(mirror_payload, key=dek, associated_data=content_hash)
                    if hashlib.sha256(candidate).digest() == content_hash:
                        plaintext = candidate
                        print(f"WARNING: block {idx} (hash {content_hash.hex()[:16]}...) failed "
                              f"on its primary copy ({primary_error}) -- recovered from its "
                              f"Ancestral Hardening mirror instead. The primary copy is damaged; "
                              f"run 'verify' to repair it.")
                except Exception:
                    pass  # mirror failed too

        if plaintext is None:
            raise ReconstructionError(
                f"Block {idx} (hash {content_hash.hex()[:16]}...) failed integrity "
                f"verification on its primary copy ({primary_error}), and either has no "
                f"Ancestral Hardening mirror or the mirror also failed -- this data is "
                f"genuinely unrecoverable."
            )
        return plaintext

    def close(self) -> None:
        self._container.close()
        if self._mirror_container is not None:
            self._mirror_container.close()


def reconstruct(manifest_path: str, container_path: str, output_path: str, master_key: bytes):
    if not os.path.exists(manifest_path) or not os.path.exists(container_path):
        raise FileNotFoundError("Manifest or Container missing. Did the pipeline finish?")

    storage_root = os.path.dirname(container_path)
    crypto = CryptoEngine(master_key)
    keyring = KeyRing(storage_root, crypto.key)  # the KEK

    engine = _open_manifest(manifest_path, crypto)
    global_index = GlobalBlockIndex(storage_root, crypto)

    expected_blocks = engine.metadata["total_blocks"]
    expected_size = engine.metadata.get("original_size")
    expected_hash = engine.metadata.get("content_sha256")

    hasher = hashlib.sha256()
    bytes_written = 0

    fetcher = _BlockFetcher(storage_root, container_path, crypto, keyring, global_index)
    try:
        with open(output_path, "wb") as out_file:
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
                    raise _missing_from_index(idx, content_hash)

                plaintext = fetcher.fetch(idx, content_hash, location)
                out_file.write(plaintext)
                hasher.update(plaintext)
                bytes_written += len(plaintext)
    finally:
        fetcher.close()

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


class ManifestReader:
    """Read-only, random-access view of one stored version: a read decrypts
    only the chunks it overlaps.

    The constructor resolves the whole chunk table in one batched query, so
    the reader keeps returning this version after later commits. Each chunk
    is authenticated as in reconstruct(), mirror fallback included; a partial
    read can't check the whole-file hash, so the total size is checked up
    front instead.
    """

    CACHE_CHUNKS = 8  # recent chunks, for small sequential reads

    def __init__(self, manifest_path: str, container_path: str, master_key: bytes):
        if not os.path.exists(manifest_path) or not os.path.exists(container_path):
            raise FileNotFoundError("Manifest or Container missing. Did the pipeline finish?")
        storage_root = os.path.dirname(container_path)
        crypto = CryptoEngine(master_key)
        keyring = KeyRing(storage_root, crypto.key)
        engine = _open_manifest(manifest_path, crypto)
        hashes = _manifest_block_hashes(engine)

        self._global_index = GlobalBlockIndex(storage_root, crypto)
        try:
            found = self._global_index.lookup_many(hashes)
            self._blocks = []
            self._starts = []
            position = 0
            for idx, content_hash in enumerate(hashes):
                location = found.get(content_hash)
                if location is None:
                    raise _missing_from_index(idx, content_hash)
                self._blocks.append((content_hash, location))
                self._starts.append(position)
                position += location[1] - AEAD_OVERHEAD
            expected_size = engine.metadata.get("original_size")
            if expected_size is not None and position != expected_size:
                raise ReconstructionError(
                    f"Chunk table adds up to {position} bytes, manifest records "
                    f"{expected_size}. File is incomplete or corrupt."
                )
            self.size = position
            self._fetcher = _BlockFetcher(storage_root, container_path, crypto, keyring, self._global_index)
        except Exception:
            self._global_index.close()
            raise
        self._cache = OrderedDict()

    def _chunk(self, idx: int) -> bytes:
        plaintext = self._cache.get(idx)
        if plaintext is not None:
            self._cache.move_to_end(idx)
            return plaintext
        content_hash, location = self._blocks[idx]
        plaintext = self._fetcher.fetch(idx, content_hash, location)
        if len(plaintext) != location[1] - AEAD_OVERHEAD:
            raise ReconstructionError(f"Block {idx} decrypted to an unexpected length.")
        self._cache[idx] = plaintext
        if len(self._cache) > self.CACHE_CHUNKS:
            self._cache.popitem(last=False)
        return plaintext

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        end = min(offset + size, self.size)
        if offset >= end:
            return b""
        idx = bisect.bisect_right(self._starts, offset) - 1
        parts = []
        position = offset
        while position < end:
            chunk = self._chunk(idx)
            start = self._starts[idx]
            take_from = position - start
            take_to = min(len(chunk), end - start)
            parts.append(chunk[take_from:take_to])
            position = start + take_to
            idx += 1
        return b"".join(parts)

    def close(self) -> None:
        self._fetcher.close()
        self._global_index.close()
        self._cache.clear()
