"""
Global, cross-file content-addressed block index, in SQLite (WAL,
synchronous=FULL): O(log N) lookups and real transactions.

The searchable column is HMAC-SHA256(hmac_subkey, content_hash), so
finding a chunk by hash needs the key -- filesystem access alone can't
confirm a file is present. Row values are AES-256-GCM encrypted under a
second subkey with the lookup key as AAD. Both subkeys come from the
KEK via HKDF.
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

_VALUE_FORMAT = "32sQQII"
_VALUE_SIZE = struct.calcsize(_VALUE_FORMAT)

# Ancestral Hardening mirror locations: mirror_offset(Q) + mirror_length(Q).
# A separate table, so `blocks` rows never needed a migration.
_MIRROR_VALUE_FORMAT = "QQ"
_MIRROR_AAD_SUFFIX = b"|mirror"  # distinct AAD, so a row can't be replayed
# between the two tables, which share lookup keys.


def _derive_subkeys(kek: bytes) -> Tuple[bytes, bytes]:
    """Derives two separate keys from the vault key: one for blinding lookups, one for encrypting rows."""
    hmac_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"pfs-dedup-hmac-key").derive(kek)
    value_key = HKDF(algorithm=SHA256(), length=32, salt=None, info=b"pfs-dedup-value-key").derive(kek)
    return hmac_key, value_key


def _lookup_key(hmac_key: bytes, content_hash: bytes) -> bytes:
    """Blinds a chunk's content hash with HMAC, so the index can't be searched for a known file."""
    return hmac.new(hmac_key, content_hash, hashlib.sha256).digest()


def _pack_value(content_hash: bytes, offset: int, length: int, ref_count: int, epoch_id: int) -> bytes:
    """Packs one index entry (hash, offset, length, reference count, key epoch) into bytes."""
    return struct.pack(_VALUE_FORMAT, content_hash, offset, length, ref_count, epoch_id)


def _unpack_value(data: bytes):
    """Unpacks an index entry packed by _pack_value."""
    return struct.unpack(_VALUE_FORMAT, data)


def _pack_mirror_value(offset: int, length: int) -> bytes:
    """Packs a spare (mirror) copy's location into bytes."""
    return struct.pack(_MIRROR_VALUE_FORMAT, offset, length)


def _unpack_mirror_value(data: bytes):
    """Unpacks a spare copy's location packed by _pack_mirror_value."""
    return struct.unpack(_MIRROR_VALUE_FORMAT, data)


class GlobalBlockIndex:
    """The vault-wide index of stored chunks, kept in SQLite with blinded keys and encrypted values."""
    def __init__(self, storage_root: str, crypto_engine):
        """Opens (or creates) the index database in the vault and derives its keys."""
        self.storage_root = storage_root
        self.crypto = crypto_engine
        self.hmac_key, self.value_key = _derive_subkeys(crypto_engine.key)
        self.db_path = os.path.join(storage_root, DB_FILENAME)

        self.conn = sqlite3.connect(self.db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
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
        """Starts one file's transaction: its index changes land together or not at all."""
        if not self._in_transaction:
            self.conn.execute("BEGIN")
            self._in_transaction = True

    def commit(self) -> None:
        """Commits the open transaction, if any."""
        if self._in_transaction:
            self.conn.execute("COMMIT")
            self._in_transaction = False

    def rollback(self) -> None:
        """Discards the open transaction, if any."""
        if self._in_transaction:
            self.conn.execute("ROLLBACK")
            self._in_transaction = False

    def close(self) -> None:
        """Closes the database connection."""
        self.conn.close()

    def compact(self) -> None:
        """SQLite VACUUM: returns free pages to the OS after deletions.
        Rewrites the whole file, so it only runs with an explicit vacuum.
        """
        self.conn.execute("VACUUM")

    def lookup(self, content_hash: bytes) -> Optional[Tuple[int, int, int, int]]:
        """(offset, length, ref_count, epoch_id) or None."""
        key = _lookup_key(self.hmac_key, content_hash)
        row = self.conn.execute(
            "SELECT encrypted_value FROM blocks WHERE lookup_key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        _content_hash, offset, length, ref_count, epoch_id = self._decrypt_row(key, row[0])
        return (offset, length, ref_count, epoch_id)

    def lookup_many(self, content_hashes) -> dict:
        """Batched lookup(): one IN (...) query. Duplicates are fine. Returns
        {content_hash: (offset, length, ref_count, epoch_id)}; missing hashes
        are absent.
        """
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
        """Batched _upsert(): one multi-row INSERT ... ON CONFLICT DO UPDATE.
        entries: (content_hash, offset, length, ref_count, epoch_id), one final
        row per hash.
        """
        entries = list(entries)
        if not entries:
            return
        self.begin()
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
        """Records a newly stored chunk with a reference count of 1."""
        self._upsert(content_hash, offset, length, 1, epoch_id)

    def increment_ref(self, content_hash: bytes) -> None:
        """Adds one to a stored chunk's reference count."""
        offset, length, ref_count, epoch_id = self._require(content_hash)
        self._upsert(content_hash, offset, length, ref_count + 1, epoch_id)

    def decrement_ref(self, content_hash: bytes) -> int:
        """Returns the new ref_count."""
        offset, length, ref_count, epoch_id = self._require(content_hash)
        new_ref = max(0, ref_count - 1)
        self._upsert(content_hash, offset, length, new_ref, epoch_id)
        return new_ref

    def set_ref_count(self, content_hash: bytes, ref_count: int) -> None:
        """Sets ref_count directly; only rebuild_ref_counts uses this."""
        offset, length, _old_ref_count, epoch_id = self._require(content_hash)
        self._upsert(content_hash, offset, length, ref_count, epoch_id)

    def update_offset(self, content_hash: bytes, new_offset: int) -> None:
        """Updates a chunk's offset after vacuum relocates it."""
        offset, length, ref_count, epoch_id = self._require(content_hash)
        self._upsert(content_hash, new_offset, length, ref_count, epoch_id)

    def get_mirror(self, content_hash: bytes) -> Optional[Tuple[int, int]]:
        """(mirror_offset, mirror_length), or None if not mirrored."""
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
        """Records (or replaces) a chunk's mirror location."""
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
        """Yields (content_hash, offset, length, ref_count, epoch_id) for every row. O(N)."""
        for lookup_key, encrypted_value in self.conn.execute("SELECT lookup_key, encrypted_value FROM blocks"):
            yield self._decrypt_row(lookup_key, encrypted_value)

    def iter_all_mirrors(self) -> Iterator[Tuple[bytes, int, int]]:
        """Yields (content_hash, mirror_offset, mirror_length) for every mirror. O(N).
        Mirror payloads don't hold the content hash, so it comes from a join
        with `blocks` on the shared lookup key.
        """
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
        """{content_hash: (offset, length, ref_count, epoch_id)}, for tests."""
        return {ch: (o, l, r, e) for ch, o, l, r, e in self.iter_all()}

    def _require(self, content_hash: bytes) -> Tuple[int, int, int, int]:
        """Returns a chunk's entry, raising KeyError if it isn't in the index."""
        existing = self.lookup(content_hash)
        if existing is None:
            raise KeyError(f"No index entry for content hash {content_hash.hex()[:16]}...")
        return existing

    def _decrypt_row(self, lookup_key: bytes, encrypted_value: bytes):
        """Decrypts one stored row, checking it belongs to this lookup key."""
        aead = AESGCM(self.value_key)
        iv = encrypted_value[:12]
        ciphertext = encrypted_value[12:]
        raw = aead.decrypt(iv, ciphertext, lookup_key)
        return _unpack_value(raw)

    def _upsert(self, content_hash: bytes, offset: int, length: int, ref_count: int, epoch_id: int) -> None:
        """Encrypts an entry and inserts or replaces its row."""
        key = _lookup_key(self.hmac_key, content_hash)
        raw = _pack_value(content_hash, offset, length, ref_count, epoch_id)
        aead = AESGCM(self.value_key)
        iv = os.urandom(12)
        encrypted_value = iv + aead.encrypt(iv, raw, key)

        self.begin()
        self.conn.execute(
            "INSERT INTO blocks (lookup_key, encrypted_value) VALUES (?, ?) "
            "ON CONFLICT(lookup_key) DO UPDATE SET encrypted_value = excluded.encrypted_value",
            (key, encrypted_value),
        )
