import os
import ctypes
import hashlib
import pickle
from typing import Any, Optional
from gearhash.fks_index import FKSIndexBuilder, FKSLookupEngine
from gearhash import fingerprint as stored_fingerprint
from gearhash.hasher import Hasher
from gearhash.dedup_index import GlobalBlockIndex, DB_FILENAME, _lookup_key
from gearhash.keyring import KeyRing, KEYRING_FILENAME
from gearhash.immutability import set_immutable, with_mutable
from gearhash.phenotype import detect_from_file

# Storage chunking profile: 8 KiB average (mask 0x1FFF), 4-16 KiB bounds.
STORAGE_MIN_SIZE = 4096
STORAGE_MAX_SIZE = 16384

# Read-ahead for streaming chunking; bounds peak memory independent of file size.
STORAGE_READ_AHEAD = 8 * 1024 * 1024

# Ancestral Hardening: a chunk referenced by this many manifests gets a
# redundant copy in a separate mirror container when it crosses the
# threshold, so one bad sector can't take out every file sharing it.
MIRROR_REF_THRESHOLD = 3
# Per-vault settings (encrypted). "mirror_all": every chunk gets a mirror copy,
# not only chunks shared by MIRROR_REF_THRESHOLD manifests.
SETTINGS_FILENAME = "settings.enc"

MIRROR_CONTAINER_FILENAME = "data_container_mirror.bin"

# Chunks per dedup-index batch: one batched lookup and one upsert per
# window instead of two round trips per chunk. Keeps bound parameters
# (up to 600) under SQLite's limit (999 before 3.32).
DEDUP_INDEX_BATCH_SIZE = 300

MANIFEST_SUFFIX = ".manifest.fks"
# A manifest's similarity fingerprint lives in a sibling file, so reading a
# manifest costs only its chunk list, however large the fingerprint is.
TRAITS_SUFFIX = ".traits.fks"
_AEAD_OVERHEAD = 28  # IV + GCM tag added by encrypt_block


def release_free_memory() -> None:
    """Returns memory freed by a large commit or fingerprint to the OS; call
    it once the fingerprint set is dropped. glibc keeps freed heap otherwise,
    and a long-running mount or GUI holds it (a 32 MB write through the
    Python mount: 39.6 MB held without this, 24.0 MB with it).
    """
    try:
        _libc().malloc_trim(0)
    except (OSError, AttributeError):
        pass  # not glibc


_libc_handle = None


def _libc():
    """Loads the C library once and returns it (used for posix_fadvise / malloc_trim)."""
    global _libc_handle
    if _libc_handle is None:
        _libc_handle = ctypes.CDLL("libc.so.6")
    return _libc_handle


def traits_path_for(manifest_path: str) -> str:
    """The fingerprint file belonging to a manifest."""
    if not manifest_path.endswith(MANIFEST_SUFFIX):
        raise ValueError(f"not a manifest path: {manifest_path}")
    return manifest_path[: -len(MANIFEST_SUFFIX)] + TRAITS_SUFFIX


def _read_manifest_metadata(manifest_path: str, crypto) -> dict:
    """Decrypts a manifest file and returns its metadata dictionary."""
    with open(manifest_path, "rb") as f:
        encrypted = f.read()
    raw = crypto.decrypt_block(encrypted, associated_data=os.path.basename(manifest_path).encode())
    return FKSLookupEngine(raw_bytes=raw).metadata


def read_similarity_fingerprint(manifest_path: str, crypto, metadata: Optional[dict] = None) -> Optional[set]:
    """A manifest's similarity fingerprint (set of 32-byte traits), or None.
    Read from its fingerprint file; manifests written before those existed
    carry it inside (`metadata`, read here if not given).
    """
    traits_path = traits_path_for(manifest_path)
    try:
        with open(traits_path, "rb") as f:
            encrypted = f.read()
    except FileNotFoundError:
        if metadata is None:
            try:
                metadata = _read_manifest_metadata(manifest_path, crypto)
            except FileNotFoundError:
                return None
        return stored_fingerprint.unpack(metadata.get("similarity_fingerprint"))
    packed = crypto.decrypt_block(encrypted, associated_data=os.path.basename(traits_path).encode())
    return stored_fingerprint.unpack(packed)


def similarity_fingerprint_count(manifest_path: str, crypto, metadata: Optional[dict] = None) -> Optional[int]:
    """Number of traits in a manifest's fingerprint, or None if it has none.
    A fingerprint file's size gives the count without decrypting it.
    """
    traits_path = traits_path_for(manifest_path)
    if os.path.exists(traits_path):
        return (os.path.getsize(traits_path) - _AEAD_OVERHEAD) // stored_fingerprint.TRAIT_BYTES
    if metadata is None:
        try:
            metadata = _read_manifest_metadata(manifest_path, crypto)
        except FileNotFoundError:
            return None
    stored = metadata.get("similarity_fingerprint")
    return None if stored is None else stored_fingerprint.count(stored)


def _atomic_write(path: str, data: bytes) -> None:
    """Writes via temp file + rename + fsync, so `path` holds either the old
    or the new complete contents, never a partial write.
    """
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
    # The rename is only durable once the directory is fsynced too.
    dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class StoragePipeline:
    """Stores files in the vault: chunks them, deduplicates, encrypts, and writes recipes and spare copies."""
    def __init__(self, storage_root: str, crypto_engine: Any):
        """Sets up the container paths and the index for a vault; encryption is required."""
        if crypto_engine is None:
            raise ValueError("Encryption is mandatory.")

        self.storage_root = storage_root
        self.crypto = crypto_engine
        self.container_path = os.path.join(self.storage_root, "data_container.bin")
        self.mirror_container_path = os.path.join(self.storage_root, MIRROR_CONTAINER_FILENAME)

        if not os.path.exists(self.storage_root):
            os.makedirs(self.storage_root)

        # crypto.key is the KEK: it wraps DEKs and never encrypts content.
        self.keyring = KeyRing(self.storage_root, self.crypto.key)
        self.settings = self.load_settings()

    def load_settings(self) -> dict:
        """Reads the vault's encrypted settings (such as mirror_all), with defaults if there are none."""
        path = os.path.join(self.storage_root, SETTINGS_FILENAME)
        if not os.path.exists(path):
            return {"mirror_all": False}
        with open(path, "rb") as f:
            return pickle.loads(self.crypto.decrypt_block(f.read(), associated_data=b"settings"))

    def save_settings(self) -> None:
        """Encrypts and saves the vault's settings."""
        path = os.path.join(self.storage_root, SETTINGS_FILENAME)
        _atomic_write(path, self.crypto.encrypt_block(pickle.dumps(self.settings), associated_data=b"settings"))

    def mirror_existing_chunks(self) -> int:
        """Gives every live chunk without a mirror one (for mirror_all).
        Returns how many were mirrored.
        """
        if not os.path.exists(self.container_path):
            return 0
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        added = 0
        try:
            todo = [(h, off, length) for h, off, length, rc, _ep in global_index.iter_all()
                    if rc > 0 and global_index.get_mirror(h) is None]
            if not todo:
                return 0
            if os.path.exists(self.mirror_container_path):
                set_immutable(self.mirror_container_path, False)
            mirror_offset = os.path.getsize(self.mirror_container_path) \
                if os.path.exists(self.mirror_container_path) else 0
            global_index.begin()
            try:
                with open(self.container_path, "rb") as src, open(self.mirror_container_path, "ab") as dst:
                    for content_hash, offset, length in todo:
                        src.seek(offset)
                        data = src.read(length)
                        dst.write(data)
                        global_index.set_mirror(content_hash, mirror_offset, len(data))
                        mirror_offset += len(data)
                        added += 1
                    dst.flush()
                    os.fsync(dst.fileno())
            except Exception:
                global_index.rollback()
                raise
            global_index.commit()
            set_immutable(self.mirror_container_path, True)
        finally:
            global_index.close()
        return added

    def rotate_keys(self) -> int:
        """Starts a new epoch with a fresh DEK for future writes; existing data
        stays under its epoch's DEK. Returns the new epoch_id.
        """
        return self.keyring.rotate()

    def _manifest_filename(self, content_hash: str) -> str:
        """Manifest filename: the content hash only, never the original name, so
        a directory listing leaks nothing.
        """
        return f"{content_hash}{MANIFEST_SUFFIX}"

    def reset_vault(self) -> None:
        """Wipes the container, manifests, dedup index and keyring."""
        if os.path.exists(self.container_path):
            set_immutable(self.container_path, False)
            os.remove(self.container_path)
        if os.path.exists(self.mirror_container_path):
            set_immutable(self.mirror_container_path, False)
            os.remove(self.mirror_container_path)
        for fname in (DB_FILENAME, DB_FILENAME + "-wal", DB_FILENAME + "-shm", KEYRING_FILENAME):
            path = os.path.join(self.storage_root, fname)
            if os.path.exists(path):
                set_immutable(path, False)
                os.remove(path)
        if os.path.exists(self.storage_root):
            for fname in os.listdir(self.storage_root):
                if fname.endswith((MANIFEST_SUFFIX, TRAITS_SUFFIX)):
                    path = os.path.join(self.storage_root, fname)
                    set_immutable(path, False)
                    os.remove(path)
        self.keyring = KeyRing(self.storage_root, self.crypto.key)

    def secure_and_persist_file(self, file_path: str, chunk_mask: int = 0x1FFF, similarity_fingerprint: Optional[set] = None) -> str:
        """Chunks a file, stores only the chunks not already in the vault, and writes its recipe; returns the recipe path."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The source file '{file_path}' does not exist.")

        # Duplicate content is detected after the loop from the streaming
        # whole-file hash, and its index changes are rolled back -- a full
        # duplicate hits only existing chunks, so nothing is appended to the
        # container and nothing is left orphaned. One read of the file instead of
        # two, at the cost of a full scan for a (rare) no-op resave.
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        try:
            current_offset = os.path.getsize(self.container_path) if os.path.exists(self.container_path) else 0

            # New chunks use the current epoch's DEK, fetched once per call.
            epoch_id, dek = self.keyring.get_current_dek()

            pairs = []  # (block_index, content_hash) for this file
            file_hasher = hashlib.sha256()  # whole-file hash
            original_size = 0
            block_index = 0
            new_chunks_written = 0
            duplicate_chunks_found = 0

            global_index.begin()  # this file's index changes commit or roll back together
            # Opened only if a chunk crosses MIRROR_REF_THRESHOLD.
            primary_reader = None
            mirror_writer = None
            mirror_offset = 0
            try:
                hasher = Hasher()

                # Chunks are batched into bounded windows: one lookup_many() per window,
                # then applied in order against local_state, then one upsert_many(). A
                # hash repeated within a window collapses into one final row. Same final
                # state as chunk-at-a-time, with memory bounded by the window size.
                window = []  # (content_hash, chunk_data), in order
                mirror_all = bool(self.settings.get("mirror_all"))

                def open_mirror_writer():
                    """Opens the spare-copy container for appending and returns it with its current size."""
                    if os.path.exists(self.mirror_container_path):
                        set_immutable(self.mirror_container_path, False)
                    offset = os.path.getsize(self.mirror_container_path) \
                        if os.path.exists(self.mirror_container_path) else 0
                    return open(self.mirror_container_path, "ab"), offset

                def flush_window():
                    """Processes a batch of chunks: stores new ones, counts references to existing ones, and writes spares."""
                    nonlocal current_offset, mirror_offset, primary_reader, mirror_writer
                    nonlocal new_chunks_written, duplicate_chunks_found
                    if not window:
                        return
                    db_state = global_index.lookup_many(ch for ch, _ in window)

                    local_state = {}  # content_hash -> [offset, length, ref_count, epoch_id]
                    for content_hash, chunk_data in window:
                        entry = local_state.get(content_hash)
                        if entry is not None:
                            entry[2] += 1
                            duplicate_chunks_found += 1
                            ref_count_before = entry[2] - 1
                        elif content_hash in db_state:
                            offset, length, ref_count, epoch = db_state[content_hash]
                            entry = [offset, length, ref_count + 1, epoch]
                            local_state[content_hash] = entry
                            duplicate_chunks_found += 1
                            ref_count_before = ref_count
                        else:
                            # New content: encrypt under the current DEK with the chunk's own hash
                            # as AAD (it may be shared by many files), and append it.
                            encrypted_chunk = self.crypto.encrypt_block(
                                chunk_data, key=dek, associated_data=content_hash
                            )
                            container.write(encrypted_chunk)
                            entry = [current_offset, len(encrypted_chunk), 1, epoch_id]
                            local_state[content_hash] = entry
                            current_offset += len(encrypted_chunk)
                            new_chunks_written += 1
                            ref_count_before = None  # ref_count 1 can't equal the threshold on arrival
                            if mirror_all:
                                if mirror_writer is None:
                                    mirror_writer, mirror_offset = open_mirror_writer()
                                mirror_writer.write(encrypted_chunk)
                                global_index.set_mirror(content_hash, mirror_offset, len(encrypted_chunk))
                                mirror_offset += len(encrypted_chunk)
                                continue

                        # Crossing the threshold (or any unmirrored chunk with mirror_all):
                        # copy the ciphertext as-is into the mirror container.
                        if ref_count_before is not None \
                                and (mirror_all or ref_count_before + 1 == MIRROR_REF_THRESHOLD) \
                                and global_index.get_mirror(content_hash) is None:
                            m_offset, m_length, _rc, _ep = entry
                            container.flush()  # it may have been written moments ago through our buffered handle
                            if primary_reader is None:
                                primary_reader = open(self.container_path, "rb")
                            if mirror_writer is None:
                                mirror_writer, mirror_offset = open_mirror_writer()
                            primary_reader.seek(m_offset)
                            mirrored_bytes = primary_reader.read(m_length)
                            mirror_writer.write(mirrored_bytes)
                            global_index.set_mirror(content_hash, mirror_offset, len(mirrored_bytes))
                            mirror_offset += len(mirrored_bytes)

                    global_index.upsert_many(
                        (ch, e[0], e[1], e[2], e[3]) for ch, e in local_state.items()
                    )
                    window.clear()

                if os.path.exists(self.container_path):
                    set_immutable(self.container_path, False)
                with open(file_path, "rb") as f, open(self.container_path, "ab") as container:
                    for chunk in hasher.stream_chunks(
                        chunk_mask, f,
                        min_size=STORAGE_MIN_SIZE, max_size=STORAGE_MAX_SIZE,
                        read_ahead=STORAGE_READ_AHEAD,
                    ):
                        chunk_data = chunk.data
                        file_hasher.update(chunk_data)
                        original_size += len(chunk_data)

                        content_hash = hashlib.sha256(chunk_data).digest()
                        window.append((content_hash, chunk_data))
                        pairs.append((block_index, content_hash))
                        block_index += 1

                        if len(window) >= DEDUP_INDEX_BATCH_SIZE:
                            flush_window()

                    flush_window()

                    container.flush()
                    os.fsync(container.fileno())
                set_immutable(self.container_path, True)

                if mirror_writer is not None:
                    mirror_writer.flush()
                    os.fsync(mirror_writer.fileno())
                    mirror_writer.close()
                    mirror_writer = None
                    set_immutable(self.mirror_container_path, True)
            except Exception:
                global_index.rollback()
                raise
            finally:
                if primary_reader is not None:
                    primary_reader.close()
                if mirror_writer is not None and not mirror_writer.closed:
                    mirror_writer.close()

            # Full duplicate (see top of method): undo the ref-count changes.
            overall_content_hash = file_hasher.hexdigest()
            manifest_filename = self._manifest_filename(overall_content_hash)
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            already_exists = os.path.exists(manifest_path)

            if already_exists:
                global_index.rollback()
            else:
                # Container bytes are fsynced before the index commit that claims them:
                # a crash leaves harmless orphaned bytes, never an index entry without data.
                global_index.commit()
        finally:
            global_index.close()

        if already_exists:
            return manifest_path

        # Type is detected from the first 64 bytes of content, never the name.
        phenotype = detect_from_file(file_path)

        fks_builder = FKSIndexBuilder(
            pairs,
            metadata={
                "original_filename": os.path.basename(file_path),
                "content_sha256": overall_content_hash,
                "total_blocks": block_index,
                "original_size": original_size,
                "new_chunks_written": new_chunks_written,
                "duplicate_chunks_found": duplicate_chunks_found,
                # The similarity fingerprint goes in its own file (see TRAITS_SUFFIX).
                "similarity_fingerprint": None,
                "phenotype_mask": phenotype.mask,
                "phenotype_name": phenotype.name,
            },
        )
        fks_builder.build()

        # The manifest is encrypted too, with its own filename as AAD.
        raw_manifest = fks_builder.serialize()
        encrypted_manifest = self.crypto.encrypt_block(
            raw_manifest, associated_data=manifest_filename.encode()
        )
        _atomic_write(manifest_path, encrypted_manifest)
        set_immutable(manifest_path, True)
        if similarity_fingerprint is not None:
            self._write_traits(manifest_path, similarity_fingerprint)
        release_free_memory()

        return manifest_path

    def _write_traits(self, manifest_path: str, similarity_fingerprint) -> None:
        """Encrypts and saves a file's similarity fingerprints next to its recipe."""
        traits_path = traits_path_for(manifest_path)
        encrypted = self.crypto.encrypt_block(
            stored_fingerprint.pack(similarity_fingerprint),
            associated_data=os.path.basename(traits_path).encode(),
        )
        if os.path.exists(traits_path):
            set_immutable(traits_path, False)
        _atomic_write(traits_path, encrypted)
        set_immutable(traits_path, True)

    def read_similarity_fingerprint(self, manifest_path: str, metadata: Optional[dict] = None) -> Optional[set]:
        """Returns the similarity fingerprints stored for a recipe, or None."""
        return read_similarity_fingerprint(manifest_path, self.crypto, metadata)

    def attach_similarity_fingerprint(self, manifest_path: str, similarity_fingerprint: set) -> None:
        """Stores (or replaces) a manifest's similarity fingerprint. Writes only
        the fingerprint file; the manifest is untouched.
        """
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(manifest_path)
        self._write_traits(manifest_path, similarity_fingerprint)

    def delete_file(self, manifest_path: str) -> None:
        """Decrements the ref count of every chunk the manifest references and
        removes the manifest. Space is reclaimed later by vacuum().
        """
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(manifest_path)

        manifest_filename = os.path.basename(manifest_path)
        with open(manifest_path, "rb") as f:
            encrypted_manifest = f.read()
        raw_manifest = self.crypto.decrypt_block(encrypted_manifest, associated_data=manifest_filename.encode())
        engine = FKSLookupEngine(raw_bytes=raw_manifest)

        total_blocks = engine.metadata.get("total_blocks", 0)

        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        try:
            global_index.begin()
            try:
                for idx in range(total_blocks):
                    content_hash = engine.lookup(idx)
                    if content_hash is not None:
                        global_index.decrement_ref(content_hash)
            except Exception:
                global_index.rollback()
                raise
            global_index.commit()
        finally:
            global_index.close()

        set_immutable(manifest_path, False)
        os.remove(manifest_path)
        traits_path = traits_path_for(manifest_path)
        if os.path.exists(traits_path):
            set_immutable(traits_path, False)
            os.remove(traits_path)

    def rebuild_ref_counts(self, live_manifest_filenames) -> dict:
        """Recomputes every chunk's ref_count from the manifests that are still
        referenced (catalog tips and lineage), instead of trusting the stored
        counters. Repairs drift; vacuum runs it first.

        Returns {"chunks_checked": int, "chunks_corrected": int}.
        """
        true_counts = {}
        for manifest_filename in live_manifest_filenames:
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            if not os.path.exists(manifest_path):
                continue
            with open(manifest_path, "rb") as f:
                encrypted = f.read()
            raw = self.crypto.decrypt_block(encrypted, associated_data=manifest_filename.encode())
            engine = FKSLookupEngine(raw_bytes=raw)
            total_blocks = engine.metadata.get("total_blocks", 0)
            for idx in range(total_blocks):
                content_hash = engine.lookup(idx)
                if content_hash is not None:
                    true_counts[content_hash] = true_counts.get(content_hash, 0) + 1

        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        checked = 0
        corrected = 0
        try:
            global_index.begin()
            try:
                for content_hash, _offset, _length, ref_count, _epoch_id in list(global_index.iter_all()):
                    checked += 1
                    true_count = true_counts.get(content_hash, 0)
                    if true_count != ref_count:
                        global_index.set_ref_count(content_hash, true_count)
                        corrected += 1
            except Exception:
                global_index.rollback()
                raise
            global_index.commit()
        finally:
            global_index.close()

        return {"chunks_checked": checked, "chunks_corrected": corrected}

    def sweep_orphaned_manifests(self, live_manifest_filenames) -> dict:
        """Removes manifests nothing references (with their fingerprint files),
        fingerprint files whose manifest isn't live, and leftover .tmp files
        from interrupted atomic writes.

        Returns {"removed": int, "tmp_removed": int}; "removed" counts manifests.
        """
        removed = 0
        tmp_removed = 0
        if not os.path.exists(self.storage_root):
            return {"removed": removed, "tmp_removed": tmp_removed}
        live = set(live_manifest_filenames)
        for fname in os.listdir(self.storage_root):
            path = os.path.join(self.storage_root, fname)
            if fname.endswith((MANIFEST_SUFFIX + ".tmp", TRAITS_SUFFIX + ".tmp")):
                set_immutable(path, False)
                os.remove(path)
                tmp_removed += 1
            elif fname.endswith(MANIFEST_SUFFIX) and fname not in live:
                set_immutable(path, False)
                os.remove(path)
                removed += 1
            elif fname.endswith(TRAITS_SUFFIX) and fname[: -len(TRAITS_SUFFIX)] + MANIFEST_SUFFIX not in live:
                set_immutable(path, False)
                os.remove(path)
        return {"removed": removed, "tmp_removed": tmp_removed}

    def vacuum(self) -> dict:
        """Reclaims space from chunks with ref_count == 0: rewrites the container
        with live chunks only, updates index offsets, and swaps it in atomically
        (a crash leaves the original intact). The mirror container is compacted
        the same way, but only when a mirrored chunk died. Manifests store
        hashes, not offsets, so they never change.

        Returns before/after sizes for both containers.
        """
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        try:
            old_size = os.path.getsize(self.container_path) if os.path.exists(self.container_path) else 0
            tmp_container_path = self.container_path + ".vacuum_tmp"

            # Materialize the scan before mutating the table.
            live_entries = []
            dead_hashes = []
            for content_hash, offset, length, ref_count, epoch_id in global_index.iter_all():
                if ref_count > 0:
                    live_entries.append((content_hash, offset, length, ref_count, epoch_id))
                else:
                    dead_hashes.append(content_hash)

            if not os.path.exists(self.container_path) and not live_entries and not dead_hashes:
                # Nothing has ever been stored: nothing to reclaim.
                return {"old_size": 0, "new_size": 0, "bytes_reclaimed": 0, "live_chunks": 0,
                        "mirror_old_size": 0, "mirror_new_size": 0, "mirror_bytes_reclaimed": 0,
                        "live_mirrors": 0}

            with open(self.container_path, "rb") as src, open(tmp_container_path, "wb") as dst:
                new_offset = 0
                global_index.begin()
                try:
                    for content_hash, offset, length, ref_count, epoch_id in live_entries:
                        src.seek(offset)
                        data = src.read(length)
                        dst.write(data)
                        if new_offset != offset:
                            global_index.update_offset(content_hash, new_offset)
                        new_offset += length

                    # Drop dead entries, and their mirror rows, in the same transaction as
                    # the offset updates. dead_mirrors counts mirror rows actually deleted.
                    dead_mirrors = 0
                    for content_hash in dead_hashes:
                        lookup_key = _lookup_key(global_index.hmac_key, content_hash)
                        global_index.conn.execute("DELETE FROM blocks WHERE lookup_key = ?", (lookup_key,))
                        cur = global_index.conn.execute("DELETE FROM mirrors WHERE lookup_key = ?", (lookup_key,))
                        if cur.rowcount > 0:
                            dead_mirrors += 1
                except Exception:
                    global_index.rollback()
                    raise
                dst.flush()
                os.fsync(dst.fileno())
                global_index.commit()
        finally:
            global_index.close()

        set_immutable(self.container_path, False)
        os.replace(tmp_container_path, self.container_path)
        set_immutable(self.container_path, True)
        dir_fd = os.open(os.path.abspath(self.storage_root), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        new_size = os.path.getsize(self.container_path)
        bytes_reclaimed = old_size - new_size

        # Compact the mirror container too, only if a mirrored chunk died.
        mirror_old_size = 0
        mirror_new_size = 0
        live_mirrors_count = 0
        if dead_mirrors and os.path.exists(self.mirror_container_path):
            mirror_old_size = os.path.getsize(self.mirror_container_path)
            tmp_mirror_path = self.mirror_container_path + ".vacuum_tmp"

            mirror_index = GlobalBlockIndex(self.storage_root, self.crypto)
            try:
                live_mirrors = list(mirror_index.iter_all_mirrors())
                live_mirrors_count = len(live_mirrors)

                set_immutable(self.mirror_container_path, False)
                try:
                    with open(self.mirror_container_path, "rb") as src, open(tmp_mirror_path, "wb") as dst:
                        new_mirror_offset = 0
                        mirror_index.begin()
                        try:
                            for content_hash, offset, length in live_mirrors:
                                src.seek(offset)
                                data = src.read(length)
                                dst.write(data)
                                if new_mirror_offset != offset:
                                    mirror_index.set_mirror(content_hash, new_mirror_offset, length)
                                new_mirror_offset += length
                        except Exception:
                            mirror_index.rollback()
                            raise
                        dst.flush()
                        os.fsync(dst.fileno())
                        mirror_index.commit()
                    os.replace(tmp_mirror_path, self.mirror_container_path)
                finally:
                    set_immutable(self.mirror_container_path, True)
            finally:
                mirror_index.close()

            mirror_dir_fd = os.open(os.path.abspath(self.storage_root), os.O_RDONLY)
            try:
                os.fsync(mirror_dir_fd)
            finally:
                os.close(mirror_dir_fd)

            mirror_new_size = os.path.getsize(self.mirror_container_path)

        mirror_bytes_reclaimed = mirror_old_size - mirror_new_size

        if dead_hashes:
            # VACUUM the index only if rows were deleted, on a fresh connection (not in a transaction).
            compactor = GlobalBlockIndex(self.storage_root, self.crypto)
            try:
                compactor.compact()
            finally:
                compactor.close()

        return {
            "old_size": old_size,
            "new_size": new_size,
            "bytes_reclaimed": bytes_reclaimed,
            "live_chunks": len(live_entries),
            "mirror_old_size": mirror_old_size,
            "mirror_new_size": mirror_new_size,
            "mirror_bytes_reclaimed": mirror_bytes_reclaimed,
            "live_mirrors": live_mirrors_count,
        }

    def verify_and_repair(self) -> dict:
        """Verifies every live chunk's primary copy and repairs it in place from
        its mirror when that works (same length: AES-GCM overhead is fixed).
        Chunks with no working copy are reported.

        Returns {"scanned": int, "healthy": int, "healed": int,
        "unrecoverable": [content_hash_hex, ...]}.
        """
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        report = {"scanned": 0, "healthy": 0, "healed": 0, "unrecoverable": []}
        try:
            entries = [e for e in global_index.iter_all() if e[3] > 0]

            for content_hash, offset, length, _ref_count, epoch_id in entries:
                report["scanned"] += 1
                dek = self.keyring.get_dek(epoch_id)

                primary_ok = False
                if os.path.exists(self.container_path):
                    try:
                        with open(self.container_path, "rb") as f:
                            f.seek(offset)
                            payload = f.read(length)
                        plaintext = self.crypto.decrypt_block(payload, key=dek, associated_data=content_hash)
                        primary_ok = hashlib.sha256(plaintext).digest() == content_hash
                    except Exception:
                        primary_ok = False

                if primary_ok:
                    report["healthy"] += 1
                    continue

                mirror_location = global_index.get_mirror(content_hash)
                mirror_ok = False
                mirror_payload = None
                if mirror_location is not None and os.path.exists(self.mirror_container_path):
                    mirror_offset, mirror_length = mirror_location
                    try:
                        with open(self.mirror_container_path, "rb") as f:
                            f.seek(mirror_offset)
                            mirror_payload = f.read(mirror_length)
                        mirror_plaintext = self.crypto.decrypt_block(mirror_payload, key=dek, associated_data=content_hash)
                        mirror_ok = hashlib.sha256(mirror_plaintext).digest() == content_hash
                    except Exception:
                        mirror_ok = False

                if not mirror_ok or mirror_payload is None or len(mirror_payload) != length:
                    report["unrecoverable"].append(content_hash.hex())
                    continue

                set_immutable(self.container_path, False)
                with open(self.container_path, "r+b") as f:
                    f.seek(offset)
                    f.write(mirror_payload)
                    f.flush()
                    os.fsync(f.fileno())
                set_immutable(self.container_path, True)
                report["healed"] += 1
        finally:
            global_index.close()

        return report
