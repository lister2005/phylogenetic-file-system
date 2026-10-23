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

# Storage chunking profile -- non-negotiable per design doc. Paired
# min=avg/2, max=avg*2 with avg=8KB (mask 0x1FFF = 13 low bits).
# Kept as constants here (mirrors chunk.py's own MIN_SIZE/MAX_SIZE
# defaults) so the storage engine's granularity is explicit, not implicit.
STORAGE_MIN_SIZE = 4096
STORAGE_MAX_SIZE = 16384

# Read-ahead buffer for streaming chunking. Peak memory during ingestion
# is bounded by this (+ max_size), independent of file size -- this is
# what makes multi-GB files safe to process.
STORAGE_READ_AHEAD = 8 * 1024 * 1024

# Ancestral Hardening: a chunk shared by this many manifests (or more) gets
# a redundant copy in a separate mirror container, so a single bad sector
# under the PRIMARY copy doesn't take down every manifest that references
# it. The more valuable dedup makes a chunk (the more it's shared), the
# more catastrophic its loss becomes -- this targets exactly that risk,
# not the design doc's "root node" framing, which doesn't map to a system
# where sharing happens at the chunk level across completely unrelated
# files. Mirroring triggers the moment a chunk CROSSES this threshold
# (not preemptively for every chunk) -- most chunks in a real vault are
# only referenced once or twice and never need it.
MIRROR_REF_THRESHOLD = 3

MIRROR_CONTAINER_FILENAME = "data_container_mirror.bin"

# PART 8 item #1 (see cpp_port_plan.txt's 1.5GB-benchmark profiling --
# dedup index lookup+register was ~19% of the core write loop, one SELECT
# + one INSERT per chunk): chunks are grouped into windows of this many
# before touching the dedup index, resolved with one batched `IN (...)`
# SELECT and one multi-row upsert per window instead of two round trips
# per chunk. Bounded (not the whole file) so this keeps the streaming
# write path's memory bound intact -- peak extra memory is O(this many
# chunks), not O(file size). 300 keeps bound-parameter counts (up to 300
# for the SELECT, up to 600 for the upsert) safely under SQLite's
# variable-count ceiling on every version this project might run against
# (999 pre-3.32, 32766 after).
DEDUP_INDEX_BATCH_SIZE = 300


def _atomic_write(path: str, data: bytes) -> None:
    """Write-temp-then-rename-then-fsync: the target path either has its
    old complete contents or the new complete contents, never a partial
    write, even across a crash. Used for anything that must not be left
    half-written: manifests, and (during vacuum) the container itself."""
    tmp_path = path + ".tmp"
    with open(tmp_path, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_path, path)
    # fsync the containing directory too -- on POSIX, the rename itself
    # needs a directory fsync to be durable against a crash, not just the
    # file's own fsync.
    dir_fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


class StoragePipeline:
    def __init__(self, storage_root: str, crypto_engine: Any):
        if crypto_engine is None:
            raise ValueError("Encryption is mandatory.")

        self.storage_root = storage_root
        self.crypto = crypto_engine
        self.container_path = os.path.join(self.storage_root, "data_container.bin")
        self.mirror_container_path = os.path.join(self.storage_root, MIRROR_CONTAINER_FILENAME)

        # Ensure the vault directory exists
        if not os.path.exists(self.storage_root):
            os.makedirs(self.storage_root)

        # crypto.key is the KEK -- wraps DEKs, never encrypts content directly.
        self.keyring = KeyRing(self.storage_root, self.crypto.key)

    def rotate_keys(self) -> int:
        """Starts a new epoch with a fresh DEK. All content encrypted
        from this point on uses the new key; everything already written
        stays readable under its original epoch's DEK. Cheap -- only
        wraps a new 32-byte key, doesn't touch existing data. Returns
        the new epoch_id."""
        return self.keyring.rotate()

    def _manifest_filename(self, content_hash: str) -> str:
        """Per-file manifest name: the full content hash, and NOTHING
        derived from the original filename. Encrypting the manifest's
        CONTENTS doesn't help if its own filename on disk still spells
        out what the file was -- `ls` shouldn't be a confidentiality
        leak. The caller keeps track of which manifest_path corresponds
        to which of their files; that mapping lives in their own
        records, not in a human-readable filename here."""
        return f"{content_hash}.manifest.fks"

    def reset_vault(self) -> None:
        """Wipes the container, all per-file manifests, the global dedup
        index, and the keyring, starting the vault fully fresh."""
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
                if fname.endswith(".manifest.fks"):
                    path = os.path.join(self.storage_root, fname)
                    set_immutable(path, False)
                    os.remove(path)
        self.keyring = KeyRing(self.storage_root, self.crypto.key)

    def secure_and_persist_file(self, file_path: str, chunk_mask: int = 0x1FFF, similarity_fingerprint: Optional[set] = None) -> str:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"The source file '{file_path}' does not exist.")

        # No separate whole-file pre-hash pass here on purpose -- there
        # used to be one (read the whole file once just to hash it,
        # BEFORE the chunking pass below reads it a second time), added
        # to fix a real bug (2026-07-24): re-saving byte-identical
        # content used to run the full chunk-by-chunk pass regardless,
        # calling increment_ref/register_new for every chunk even though
        # the resulting manifest turned out to already exist -- inflating
        # ref counts with no way for the single surviving catalog/
        # lineage reference to ever decrement them back down. That fix
        # is preserved below (still exact, still tested), just without
        # paying for a whole extra sequential read of the file on every
        # write to get it: the chunking loop already computes a
        # streaming whole-file hash (file_hasher) as a side effect of
        # work it's doing anyway, so the "is this exact content already
        # stored" check now happens AFTER the loop using that hash,
        # and a detected duplicate rolls back the transaction instead of
        # committing it -- global_index.rollback() undoes every
        # increment_ref/register_new this pass made, the same mechanism
        # already used for a genuine mid-loop error. Provably clean, not
        # just assumed: if the file really is a full duplicate, EVERY
        # chunk in it hits the "existing" branch below (identical
        # content chunks identically), so nothing ever gets physically
        # appended to the container for a duplicate file -- there's
        # nothing left over for rollback to orphan.
        #
        # Trade-off, deliberately taken: a genuine no-op resave (rare)
        # now pays for real chunk-boundary scanning + dedup lookups
        # instead of an instant return -- bounded, still cheap per op
        # (chunking is native; SQLite lookups are ~10-30us each per
        # measurement). In exchange, the common case (content that's
        # actually new or changed) drops from two full reads to one.
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        try:
            current_offset = os.path.getsize(self.container_path) if os.path.exists(self.container_path) else 0

            # All NEW chunks written during this call use the current epoch's
            # DEK -- never the KEK directly. Fetched once per call, not per
            # chunk, so one ingestion doesn't straddle a mid-flight rotation.
            epoch_id, dek = self.keyring.get_current_dek()

            pairs = []  # (block_index, content_hash) -- THIS file's block sequence
            file_hasher = hashlib.sha256()  # whole-file hash, for end-to-end verification
            original_size = 0
            block_index = 0
            new_chunks_written = 0
            duplicate_chunks_found = 0

            global_index.begin()  # whole file's index changes commit atomically together
            # Opened lazily, only if some chunk in this file actually
            # crosses MIRROR_REF_THRESHOLD -- most writes never touch
            # either of these, so most writes never pay for them.
            primary_reader = None
            mirror_writer = None
            mirror_offset = 0
            try:
                hasher = Hasher()

                # Windowed batching (PART 8 item #1): chunks are still
                # streamed and chunked one at a time exactly as before
                # (peak memory still bounded by DEDUP_INDEX_BATCH_SIZE,
                # independent of file size) -- what changes is that the
                # dedup index is no longer consulted per chunk. Chunks are
                # buffered into a bounded window, resolved with ONE
                # batched lookup_many() covering the whole window, then
                # walked in original order to apply ref-count/mirroring
                # logic against an in-memory local_state dict before
                # flushing with ONE upsert_many() call. Repeat occurrences
                # of the same hash within one window (a self-duplicate
                # chunk inside this file) collapse into a single
                # final-state row instead of one lookup+upsert per
                # occurrence -- and, unlike the old per-chunk
                # increment_ref(), never re-queries the row a second time
                # internally, since the window's own batched result (or
                # an earlier occurrence's own local_state entry) already
                # has everything needed. Final DB state (ref counts,
                # exactly-once mirror-crossing point) is identical to what
                # the old one-chunk-at-a-time loop produced.
                window = []  # (content_hash, chunk_data), in original order

                def flush_window():
                    nonlocal current_offset, mirror_offset, primary_reader, mirror_writer
                    nonlocal new_chunks_written, duplicate_chunks_found
                    if not window:
                        return
                    db_state = global_index.lookup_many(ch for ch, _ in window)

                    local_state = {}  # content_hash -> [offset, length, ref_count, epoch_id]
                    for content_hash, chunk_data in window:
                        entry = local_state.get(content_hash)
                        if entry is not None:
                            entry[2] += 1  # ref_count
                            duplicate_chunks_found += 1
                            ref_count_before = entry[2] - 1
                        elif content_hash in db_state:
                            offset, length, ref_count, epoch = db_state[content_hash]
                            entry = [offset, length, ref_count + 1, epoch]
                            local_state[content_hash] = entry
                            duplicate_chunks_found += 1
                            ref_count_before = ref_count
                        else:
                            # New content: encrypt and physically append it. AAD is
                            # bound to the chunk's OWN content hash rather than a
                            # file/position, since this ciphertext can now be
                            # shared across many files' manifests. Encrypted under
                            # the current epoch's DEK, not the KEK.
                            encrypted_chunk = self.crypto.encrypt_block(
                                chunk_data, key=dek, associated_data=content_hash
                            )
                            container.write(encrypted_chunk)
                            entry = [current_offset, len(encrypted_chunk), 1, epoch_id]
                            local_state[content_hash] = entry
                            current_offset += len(encrypted_chunk)
                            new_chunks_written += 1
                            ref_count_before = None  # ref_count 1 can never equal MIRROR_REF_THRESHOLD (3) on arrival

                        # Ancestral Hardening: the moment this chunk's ref
                        # count crosses the threshold, mirror it -- copy its
                        # already-encrypted bytes as-is (no re-encryption
                        # needed) into the separate mirror container.
                        if ref_count_before is not None and ref_count_before + 1 == MIRROR_REF_THRESHOLD \
                                and global_index.get_mirror(content_hash) is None:
                            m_offset, m_length, _rc, _ep = entry
                            if primary_reader is None:
                                primary_reader = open(self.container_path, "rb")
                            if mirror_writer is None:
                                if os.path.exists(self.mirror_container_path):
                                    set_immutable(self.mirror_container_path, False)
                                mirror_writer = open(self.mirror_container_path, "ab")
                                mirror_offset = os.path.getsize(self.mirror_container_path) \
                                    if os.path.exists(self.mirror_container_path) else 0
                            primary_reader.seek(m_offset)
                            mirrored_bytes = primary_reader.read(m_length)
                            mirror_writer.write(mirrored_bytes)
                            global_index.set_mirror(content_hash, mirror_offset, len(mirrored_bytes))
                            mirror_offset += len(mirrored_bytes)

                    global_index.upsert_many(
                        (ch, e[0], e[1], e[2], e[3]) for ch, e in local_state.items()
                    )
                    window.clear()

                # Streaming: reads the file in STORAGE_READ_AHEAD-sized increments
                # instead of loading it whole. Peak memory no longer scales with
                # file size.
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
                set_immutable(self.container_path, True)  # re-protect after this file's writes land

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

            # Now that the whole file's been read exactly once, the
            # streaming file_hasher has its final value -- this is the
            # check that used to require a separate upfront read (see
            # the comment at the top of this method). A hit here means
            # every chunk above landed in the "existing" branch (true
            # duplicates chunk identically), so nothing new was
            # physically written -- rollback() cleanly undoes only the
            # ref-count bookkeeping, with nothing left over to orphan.
            overall_content_hash = file_hasher.hexdigest()
            manifest_filename = self._manifest_filename(overall_content_hash)
            manifest_path = os.path.join(self.storage_root, manifest_filename)
            already_exists = os.path.exists(manifest_path)

            if already_exists:
                global_index.rollback()
            else:
                # Durability ordering: the container's new bytes are fsynced
                # BEFORE the index transaction that claims they exist is
                # committed. If a crash happens between these two lines, the
                # container has orphaned (harmless, reclaimable) bytes and the
                # index has no record of them -- never the reverse, which
                # would be an index pointing at data that was never actually
                # made durable.
                global_index.commit()
        finally:
            global_index.close()  # also re-applies immutable protection to the index files

        if already_exists:
            return manifest_path

        # Identity comes from the file's own bytes, not its name -- no
        # extensions anywhere in this system. Cheap: only reads the
        # first 64 bytes, independent of how large the file actually is.
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
                # Precomputed SIMILARITY_PROFILE trait set, if the caller
                # provided one -- lets the clade clustering tree be built
                # later WITHOUT re-reading or re-chunking the original
                # file. Entirely optional and decoupled from the storage
                # chunking above; None if the caller didn't ask for it.
                # Stored packed -- see gearhash/fingerprint.py for why.
                "similarity_fingerprint": None if similarity_fingerprint is None else stored_fingerprint.pack(similarity_fingerprint),
                "phenotype_mask": phenotype.mask,
                "phenotype_name": phenotype.name,
            },
        )
        fks_builder.build()

        # Encrypt the manifest itself before it touches disk -- filenames,
        # sizes, and content hashes are real metadata and deserve the same
        # protection as file content. AAD is bound to the manifest's own
        # filename so it can't be silently swapped for a different one.
        raw_manifest = fks_builder.serialize()
        encrypted_manifest = self.crypto.encrypt_block(
            raw_manifest, associated_data=manifest_filename.encode()
        )
        _atomic_write(manifest_path, encrypted_manifest)
        set_immutable(manifest_path, True)

        return manifest_path

    def attach_similarity_fingerprint(self, manifest_path: str, similarity_fingerprint: set) -> None:
        """Updates an already-written manifest's stored similarity
        fingerprint after the fact. Exists so SIMILARITY_PROFILE
        fingerprinting (a separate full pass over the file, at a much
        finer chunk granularity than storage) can run on a background
        thread, fully decoupled from secure_and_persist_file's
        synchronous, security-critical path -- matching the design
        doc's "background clustering daemon" instead of paying this
        cost inline on every write.

        Only rewrites the manifest's metadata dict; the perfect-hash
        block-lookup structure itself (m1/a1/secondary_tables/...) is
        carried over unchanged, since only the caller-supplied
        similarity_fingerprint changes here."""
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(manifest_path)

        manifest_filename = os.path.basename(manifest_path)
        with open(manifest_path, "rb") as f:
            encrypted_manifest = f.read()
        raw_manifest = self.crypto.decrypt_block(encrypted_manifest, associated_data=manifest_filename.encode())
        engine = FKSLookupEngine(raw_bytes=raw_manifest)

        state = {
            "m1": engine.m1,
            "a1": engine.a1,
            "a2_multipliers": engine.a2_multipliers,
            "m2_sizes": engine.m2_sizes,
            "secondary_tables": engine.secondary_tables,
            "n_total": engine.n_total,
            "metadata": {**engine.metadata, "similarity_fingerprint": stored_fingerprint.pack(similarity_fingerprint)},
        }
        new_raw_manifest = pickle.dumps(state)
        new_encrypted_manifest = self.crypto.encrypt_block(new_raw_manifest, associated_data=manifest_filename.encode())

        # Same pattern as everywhere else that rewrites an
        # immutable-protected path: clear +i (os.replace can't unlink an
        # immutable destination), atomic write-temp-then-rename, re-set +i.
        set_immutable(manifest_path, False)
        _atomic_write(manifest_path, new_encrypted_manifest)
        set_immutable(manifest_path, True)

    def delete_file(self, manifest_path: str) -> None:
        """Removes a file from the vault: decrements the ref count on
        every chunk it referenced, and removes the manifest itself. This
        does NOT reclaim disk space immediately -- chunks that drop to
        ref_count=0 are marked reclaimable but their bytes stay in the
        container until vacuum() runs. Space reclamation is a separate,
        deliberate operation because rewriting the container is not
        cheap and shouldn't happen as a side effect of every delete."""
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

    def rebuild_ref_counts(self, live_manifest_filenames) -> dict:
        """Recomputes every chunk's ref_count from scratch by reading the
        block list of every manifest the caller says is actually still
        referenced -- VaultSession's catalog entries plus its full
        lineage history across every label, the same authoritative
        source delete_label/prune_generation already use for their own
        manifest-level reference counting -- rather than trusting the
        incrementally-maintained counter in the index.

        Exists to repair a real bug (found 2026-07-24, since fixed at
        the source in secure_and_persist_file): re-saving byte-identical
        content used to still run the full chunk-registration pass
        before checking whether the resulting manifest already existed,
        inflating every one of that content's chunks' ref counts by one
        more than any surviving reference could ever decrement back
        down. That left chunks permanently "live" (vacuum() correctly
        refuses to drop anything with ref_count > 0) even after every
        label that ever pointed at them was deleted. The fix at the
        write path stops this from happening going forward; this method
        is what repairs a vault that already has drift from before that
        fix existed. Called automatically by VaultSession.vacuum()
        before the dead-chunk sweep, so running 'vacuum' alone is
        enough -- no separate repair step for the user to remember.

        Returns {"chunks_checked": int, "chunks_corrected": int}."""
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
        """Removes manifest files on disk that nothing in the vault --
        no catalog entry, no lineage history record, across every label
        -- still references, plus any '.manifest.fks.tmp' file: the
        write-temp half of _atomic_write's write-temp-then-rename
        pattern, left behind only when a write was interrupted before
        the rename into place completed, so nothing could ever have
        referenced it either (the rename is the one step that makes an
        atomic write "real"). Ordinary deletion (delete_label /
        prune_generation) already frees a manifest the MOMENT its
        reference count hits zero; this exists for manifests that ended
        up unreferenced some other way -- e.g. state left over from
        before manifest-reference-counting existed at all -- so a vault
        doesn't have to be reset from scratch to recover that space.

        Returns {"removed": int, "tmp_removed": int}."""
        removed = 0
        tmp_removed = 0
        if not os.path.exists(self.storage_root):
            return {"removed": removed, "tmp_removed": tmp_removed}
        for fname in os.listdir(self.storage_root):
            path = os.path.join(self.storage_root, fname)
            if fname.endswith(".manifest.fks.tmp"):
                set_immutable(path, False)
                os.remove(path)
                tmp_removed += 1
            elif fname.endswith(".manifest.fks") and fname not in live_manifest_filenames:
                set_immutable(path, False)
                os.remove(path)
                removed += 1
        return {"removed": removed, "tmp_removed": tmp_removed}

    def vacuum(self) -> dict:
        """Reclaims space from chunks no file references anymore
        (ref_count == 0). Rewrites the container with only live chunks,
        updates the index's offsets to match, and atomically swaps the
        new container into place -- the old container is never modified
        in place, so a crash mid-vacuum just leaves an incomplete temp
        file and the original container untouched and valid.

        Also compacts the Ancestral Hardening mirror container the same
        way, when there's actually something to reclaim there: any
        mirrored chunk that just died gets its dead bytes physically
        dropped from data_container_mirror.bin too (not just its
        `mirrors` DB row, which the dead-chunk sweep above already drops),
        and every remaining live mirror's index entry is updated to its
        new post-compaction offset. Skipped entirely (no file touched) if
        this vacuum() call didn't actually kill any mirrored chunk -- most
        calls never do, since most chunks are never mirrored in the first
        place.

        Per-file manifests never need to change: they only ever store
        content hashes, never physical offsets, so relocating chunks
        during vacuum is invisible to them.

        Returns a small report dict with before/after sizes (both
        containers)."""
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        try:
            old_size = os.path.getsize(self.container_path) if os.path.exists(self.container_path) else 0
            tmp_container_path = self.container_path + ".vacuum_tmp"

            # One full scan up front, outside any transaction, fully
            # materialized into lists -- avoids mutating the table while a
            # cursor is still iterating it later.
            live_entries = []
            dead_hashes = []
            for content_hash, offset, length, ref_count, epoch_id in global_index.iter_all():
                if ref_count > 0:
                    live_entries.append((content_hash, offset, length, ref_count, epoch_id))
                else:
                    dead_hashes.append(content_hash)

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

                    # Drop dead entries in the SAME transaction as the offset
                    # updates above -- either the whole vacuum's index changes
                    # land together, or none do. Also drops any mirrors
                    # table row for a dead chunk -- otherwise it would keep
                    # claiming a chunk is hardened after its primary (and
                    # the content it protects) is already gone. dead_mirrors
                    # counts how many of those DELETEs actually hit a row, so
                    # the mirror-container compaction pass below can skip
                    # entirely when none of this call's dead chunks were
                    # ever mirrored -- the common case.
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

        set_immutable(self.container_path, False)  # about to be replaced
        os.replace(tmp_container_path, self.container_path)
        set_immutable(self.container_path, True)
        dir_fd = os.open(os.path.abspath(self.storage_root), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)

        new_size = os.path.getsize(self.container_path)
        bytes_reclaimed = old_size - new_size

        # Ancestral Hardening's mirror container: the dead-hash sweep above
        # already pruned the mirrors DB table down to live-only rows -- this
        # physically compacts the mirror container FILE to match, the same
        # way the primary container was just compacted above. Gated on
        # dead_mirrors > 0 (not merely "does the file exist"), so a vacuum()
        # that dropped dead PRIMARY chunks but none of them were ever
        # mirrored -- the common case, since most chunks never cross
        # MIRROR_REF_THRESHOLD -- doesn't pay for a full mirror-container
        # rewrite for zero actual benefit.
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

                set_immutable(self.mirror_container_path, False)  # about to be rewritten
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
                    set_immutable(self.mirror_container_path, True)  # re-protect either way
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
            # Only worth it when rows actually got deleted above -- VACUUM
            # rewrites the whole index file regardless of how much freed
            # space there is to reclaim, so running it on every call
            # (including the common case of nothing to clean up) would be
            # pure waste. Opened as its own connection, after the one
            # above is fully closed -- SQLite refuses to VACUUM from
            # inside a transaction, and the index-mutating transaction
            # above has already committed by this point anyway.
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
        """Ancestral Hardening's proactive half: scans every LIVE chunk
        (ref_count > 0 -- dead ones are vacuum's job, not this one's),
        verifying its primary copy still decrypts and hashes correctly.
        A chunk that fails on primary but has a working Ancestral
        Hardening mirror gets REPAIRED in place -- the mirror's
        ciphertext is copied back over the bad primary bytes at the
        same offset. This is always a safe same-length overwrite:
        AES-256-GCM's overhead (12-byte IV + 16-byte tag) is fixed for
        a given plaintext size, so a mirror of the same chunk is always
        exactly as long as the primary it's replacing -- never a resize
        of a container other chunks' offsets still point into.

        A chunk that fails on primary with no working mirror is
        reported, not silently skipped -- there is nothing this method
        can do to recover it (that content is genuinely gone), but the
        caller needs to know, not be told "0 bytes reclaimed" and
        assume everything is fine.

        Returns {"scanned": int, "healthy": int, "healed": int,
        "unrecoverable": [content_hash_hex, ...]}."""
        global_index = GlobalBlockIndex(self.storage_root, self.crypto)
        report = {"scanned": 0, "healthy": 0, "healed": 0, "unrecoverable": []}
        try:
            entries = [e for e in global_index.iter_all() if e[3] > 0]  # ref_count > 0

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
