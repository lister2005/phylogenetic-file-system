"""
Global, cross-file content-addressed block index -- SQLite-backed.

Earlier versions of this used the same FKS perfect-hash structure as the
per-file manifests. That was the wrong tool for a structure that needs
to grow continuously: FKS is a STATIC structure (built once, no
incremental insert), so every write meant a full rebuild, and even
after a two-tier hot/cold amortization fix, every READ still paid a
full linear scan just to load the cold layer into memory before any
actual lookup could happen -- O(total corpus size) on every single
ingestion AND every single reconstruction, regardless of how small the
operation was.

SQLite is the right tool here: a real B-tree index gives O(log N)
lookups without loading anything but the relevant page, and its WAL
mode gives us actual ACID transactions -- crash-consistency we'd
otherwise have to hand-roll badly.

Confidentiality without leaking a searchable oracle:
A naive port would store content_hash directly as the indexed column,
which puts us right back where we started -- anyone with filesystem
access (no key needed) could hash a guessed file and query for it.
Instead, the searchable column is HMAC-SHA256(hmac_subkey, content_hash),
where hmac_subkey is derived from the KEK via HKDF. Computing a matching
lookup key requires the KEK; the stored row VALUES are themselves
AES-256-GCM encrypted under a second independent subkey, with AAD bound
to the row's own lookup key. Two independent subkeys (not the KEK
directly, not the same key for both purposes) so a compromise of one
derivation doesn't help with the other.
"""

import os
import sqlite3
import hmac
import hashlib
import struct
from typing import Iterator, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256

DB_FILENAME = "global_index.db"

# content_hash(32s) + offset(Q) + length(Q) + ref_count(I) + epoch_id(I)
_VALUE_FORMAT = "32sQQII"
_VALUE_SIZE = struct.calcsize(_VALUE_FORMAT)

# Ancestral Hardening (see StoragePipeline): mirror_offset(Q) + mirror_length(Q)
# for chunks referenced by enough manifests that losing them to a single bad
# sector would be disproportionately costly. Separate table from `blocks`
# rather than extra columns on it, so the existing blocks row format (and
# every vault that already has one on disk) never needs a migration.
_MIRROR_VALUE_FORMAT = "QQ"
_MIRROR_AAD_SUFFIX = b"|mirror"  # binds mirror rows to a distinct AAD from
# blocks rows even though both tables key off the same lookup_key -- a
# ciphertext from one table can't be replayed into the other.


def _derive_subkeys(kek: bytes) -> Tuple[bytes, bytes]:
    hmac_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"pfs-dedup-hmac-key").derive(kek)
    value_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"pfs-dedup-value-key").derive(kek)
    return hmac_key, value_key


def _lookup_key(hmac_key: bytes, content_hash: bytes) -> bytes:
    return hmac.new(hmac_key, content_hash, hashlib.sha256).digest()


def _pack_value(content_hash: bytes, offset: int, length: int, ref_count: int, epoch_id: int) -> bytes:
    return struct.pack(_VALUE_FORMAT, content_hash, offset, length, ref_count, epoch_id)


def _unpack_value(data: bytes):
    return struct.unpack(_VALUE_FORMAT, data)


def _pack_mirror_value(offset: int, length: int) -> bytes:
    return struct.pack(_MIRROR_VALUE_FORMAT, offset, length)


def _unpack_mirror_value(data: bytes):
    return struct.unpack(_MIRROR_VALUE_FORMAT, data)


class GlobalBlockIndex:
    def __init__(self, storage_root: str, crypto_engine):
        self.storage_root = storage_root
        self.crypto = crypto_engine
        self.hmac_key, self.value_key = _derive_subkeys(crypto_engine.key)
        self.db_path = os.path.join(storage_root, DB_FILENAME)

        self.conn = sqlite3.connect(self.db_path, isolation_level=None)  # autocommit off; we control transactions
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")  # durability over raw speed -- this is a vault, not a cache
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS blocks ("
            "  lookup_key BLOB PRIMARY KEY,"
            "  encrypted_value BLOB NOT NULL"
            ")"
        )
        self.conn.execute(
            "CREATE TABLE IF NOT EXISTS mirrors ("
            "  lookup_key BLOB PRIMARY KEY,"
            "  encrypted_value BLOB NOT NULL"
            ")"
        )
        self._in_transaction = False

    def begin(self) -> None:
        """Starts a transaction covering one file's worth of index
        changes. Either all of a file's new/updated chunk entries become
        visible together, or (on crash/rollback) none of them do."""
        if not self._in_transaction:
            self.conn.execute("BEGIN")
            self._in_transaction = True

    def commit(self) -> None:
        if self._in_transaction:
            self.conn.execute("COMMIT")
            self._in_transaction = False

    def rollback(self) -> None:
        if self._in_transaction:
            self.conn.execute("ROLLBACK")
            self._in_transaction = False

    def close(self) -> None:
        self.conn.close()

    def compact(self) -> None:
        """SQLite doesn't shrink its own file after DELETEs -- freed
        pages go on an internal free list for reuse, not back to the OS
        -- so a vault that's had a lot of churn (or was fully emptied)
        can have this file sitting at its historical peak size long
        after vacuum() has already reclaimed the actual chunk container.
        VACUUM (SQLite's own command, unrelated to StoragePipeline's own
        vacuum() despite the name collision) rebuilds the file with no
        free pages left in it. Not run on every commit -- it rewrites
        the whole file, so it belongs in the same explicit, infrequent
        maintenance operation as the container compaction it's paired
        with, not the per-write hot path."""
        self.conn.execute("VACUUM")

    def lookup(self, content_hash: bytes) -> Optional[Tuple[int, int, int, int]]:
        """O(log N) via SQLite's primary key B-tree index -- no full-table
        scan. Returns (offset, length, ref_count, epoch_id) or None."""
        key = _lookup_key(self.hmac_key, content_hash)
        row = self.conn.execute(
            "SELECT encrypted_value FROM blocks WHERE lookup_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        _content_hash, offset, length, ref_count, epoch_id = self._decrypt_row(key, row[0])
        return (offset, length, ref_count, epoch_id)

    def lookup_many(self, content_hashes) -> dict:
        """Batched form of lookup() (PART 8 item #1 -- see
        cpp_port_plan.txt's 1.5GB-benchmark profiling: one SELECT + one
        INSERT per chunk was ~19% of the core write loop). ONE
        `WHERE lookup_key IN (...)` query for N hashes at once instead of
        N individual point lookups. content_hashes may contain duplicates
        (harmless -- SQLite doesn't mind repeated IN-clause values, and
        the result dict naturally collapses them). Returns
        {content_hash: (offset, length, ref_count, epoch_id)}; a hash with
        no entry is simply absent, matching lookup()'s "None means not
        found" per-item."""
        content_hashes = list(content_hashes)
        if not content_hashes:
            return {}
        key_to_hash = {}
        keys = []
        for ch in content_hashes:
            key = _lookup_key(self.hmac_key, ch)
            key_to_hash[key] = ch
            keys.append(key)
        placeholders = ",".join("?" for _ in keys)
        rows = self.conn.execute(
            f"SELECT lookup_key, encrypted_value FROM blocks WHERE lookup_key IN ({placeholders})",
            keys,
        ).fetchall()
        result = {}
        for lookup_key, encrypted_value in rows:
            content_hash, offset, length, ref_count, epoch_id = self._decrypt_row(lookup_key, encrypted_value)
            result[content_hash] = (offset, length, ref_count, epoch_id)
        return result

    def upsert_many(self, entries) -> None:
        """Batched form of _upsert(): ONE multi-row
        `INSERT ... VALUES (?,?),(?,?),... ON CONFLICT DO UPDATE` for all
        given rows instead of one upsert statement execution per row.
        entries: iterable of (content_hash, offset, length, ref_count,
        epoch_id) -- the FINAL state to write for each hash (a caller
        collapsing repeat occurrences of the same hash within one window
        should pass only the final row, not one row per occurrence)."""
        entries = list(entries)
        if not entries:
            return
        self.begin()  # no-op if already in one
        value_placeholders = []
        params = []
        for content_hash, offset, length, ref_count, epoch_id in entries:
            key = _lookup_key(self.hmac_key, content_hash)
            raw = _pack_value(content_hash, offset, length, ref_count, epoch_id)
            aead = AESGCM(self.value_key)
            iv = os.urandom(12)
            encrypted_value = iv + aead.encrypt(iv, raw, key)
            value_placeholders.append("(?, ?)")
            params.append(key)
            params.append(encrypted_value)
        sql = (
            "INSERT INTO blocks (lookup_key, encrypted_value) VALUES "
            + ",".join(value_placeholders)
            + " ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value"
        )
        self.conn.execute(sql, params)

    def register_new(self, content_hash: bytes, offset: int, length: int, epoch_id: int) -> None:
        self._upsert(content_hash, offset, length, 1, epoch_id)

    def increment_ref(self, content_hash: bytes) -> None:
        offset, length, ref_count, epoch_id = self._require(content_hash)
        self._upsert(content_hash, offset, length, ref_count + 1, epoch_id)

    def decrement_ref(self, content_hash: bytes) -> int:
        """Used when a file is deleted. Returns the new ref_count so the
        caller (vacuum) knows whether this chunk is now reclaimable."""
        offset, length, ref_count, epoch_id = self._require(content_hash)
        new_ref = max(0, ref_count - 1)
        self._upsert(content_hash, offset, length, new_ref, epoch_id)
        return new_ref

    def set_ref_count(self, content_hash: bytes, ref_count: int) -> None:
        """Overwrites a chunk's ref_count directly, bypassing the normal
        increment/decrement-by-one lifecycle. Used only by
        StoragePipeline.rebuild_ref_counts() to correct drift by
        recomputing the true count from actual manifest contents --
        never called from the ordinary write/delete path."""
        offset, length, _old_ref_count, epoch_id = self._require(content_hash)
        self._upsert(content_hash, offset, length, ref_count, epoch_id)

    def update_offset(self, content_hash: bytes, new_offset: int) -> None:
        """Used by vacuum() after physically relocating a chunk's bytes
        to a new position in a compacted container."""
        offset, length, ref_count, epoch_id = self._require(content_hash)
        self._upsert(content_hash, new_offset, length, ref_count, epoch_id)

    def get_mirror(self, content_hash: bytes) -> Optional[Tuple[int, int]]:
        """(mirror_offset, mirror_length) if this chunk has been mirrored
        by Ancestral Hardening (see StoragePipeline), else None."""
        key = _lookup_key(self.hmac_key, content_hash)
        row = self.conn.execute(
            "SELECT encrypted_value FROM mirrors WHERE lookup_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        aead = AESGCM(self.value_key)
        iv = row[0][:12]
        ciphertext = row[0][12:]
        raw = aead.decrypt(iv, ciphertext, key + _MIRROR_AAD_SUFFIX)
        return _unpack_mirror_value(raw)

    def set_mirror(self, content_hash: bytes, offset: int, length: int) -> None:
        """Records where this chunk's redundant copy lives in the mirror
        container. Idempotent -- overwrites any existing mirror record
        for this hash (used when re-mirroring after a repair)."""
        key = _lookup_key(self.hmac_key, content_hash)
        raw = _pack_mirror_value(offset, length)
        aead = AESGCM(self.value_key)
        iv = os.urandom(12)
        encrypted_value = iv + aead.encrypt(iv, raw, key + _MIRROR_AAD_SUFFIX)

        self.begin()
        self.conn.execute(
            "INSERT INTO mirrors (lookup_key, encrypted_value) VALUES (?, ?) "
            "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
            (key, encrypted_value),
        )

    def iter_all(self) -> Iterator[Tuple[bytes, int, int, int, int]]:
        """Yields (content_hash, offset, length, ref_count, epoch_id) for
        every entry. O(N) by nature -- only for vacuum() and introspection,
        never on the per-file ingestion/reconstruction hot path."""
        for lookup_key, encrypted_value in self.conn.execute("SELECT lookup_key, encrypted_value FROM blocks"):
            yield self._decrypt_row(lookup_key, encrypted_value)

    def iter_all_mirrors(self) -> Iterator[Tuple[bytes, int, int]]:
        """Yields (content_hash, mirror_offset, mirror_length) for every
        entry in the mirrors table. O(N) by nature -- only for vacuum()'s
        mirror-container compaction pass, never the per-file hot path.

        Unlike iter_all(), the mirrors table's own encrypted payload
        doesn't contain content_hash -- set_mirror() only ever packs
        (offset, length) into it, using content_hash purely as part of
        the AAD, not as plaintext (see _pack_mirror_value /
        _MIRROR_AAD_SUFFIX). lookup_key is a one-way HMAC of
        content_hash, so it can't be reversed either. Instead, this
        JOINs against the blocks table on the shared lookup_key -- both
        tables key off HMAC(hmac_key, content_hash) for the SAME
        content_hash (see set_mirror/_upsert), and blocks' own payload
        DOES carry content_hash in plaintext (_VALUE_FORMAT) -- so the
        join recovers it without needing any on-disk format change to
        the mirrors table itself."""
        aead = AESGCM(self.value_key)
        rows = self.conn.execute(
            "SELECT m.lookup_key, m.encrypted_value, b.encrypted_value "
            "FROM mirrors m JOIN blocks b ON m.lookup_key = b.lookup_key"
        )
        for lookup_key, mirror_encrypted_value, block_encrypted_value in rows:
            content_hash, _offset, _length, _ref_count, _epoch_id = self._decrypt_row(
                lookup_key, block_encrypted_value
            )
            iv = mirror_encrypted_value[:12]
            ciphertext = mirror_encrypted_value[12:]
            raw = aead.decrypt(iv, ciphertext, lookup_key + _MIRROR_AAD_SUFFIX)
            mirror_offset, mirror_length = _unpack_mirror_value(raw)
            yield (content_hash, mirror_offset, mirror_length)

    @property
    def entries(self):
        """Convenience for tests/introspection: {content_hash: (offset, length, ref_count, epoch_id)}."""
        return {ch: (o, l, r, e) for ch, o, l, r, e in self.iter_all()}

    def _require(self, content_hash: bytes) -> Tuple[int, int, int, int]:
        existing = self.lookup(content_hash)
        if existing is None:
            raise KeyError(f"No index entry for content hash {content_hash.hex()[:16]}...")
        return existing

    def _decrypt_row(self, lookup_key: bytes, encrypted_value: bytes):
        aead = AESGCM(self.value_key)
        iv = encrypted_value[:12]
        ciphertext = encrypted_value[12:]
        raw = aead.decrypt(iv, ciphertext, lookup_key)  # AAD binds value to its own row
        return _unpack_value(raw)

    def _upsert(self, content_hash: bytes, offset: int, length: int, ref_count: int, epoch_id: int) -> None:
        key = _lookup_key(self.hmac_key, content_hash)
        raw = _pack_value(content_hash, offset, length, ref_count, epoch_id)
        aead = AESGCM(self.value_key)
        iv = os.urandom(12)
        encrypted_value = iv + aead.encrypt(iv, raw, key)

        self.begin()  # no-op if already in one
        self.conn.execute(
            "INSERT INTO blocks (lookup_key, encrypted_value) VALUES (?, ?) "
            "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
            (key, encrypted_value),
        )
