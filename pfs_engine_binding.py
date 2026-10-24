"""
ctypes binding to the C++ engine (cpp_engine/build/libpfs_engine_capi.so,
see c_api.h): CppVaultSession offers the same operations as VaultSession.
It takes the 32-byte KEK; passphrase unlocking stays in
gearhash.master_key_store.
"""
import ctypes
import functools
import os
import threading
from typing import Optional

_LIB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "cpp_engine", "build", "libpfs_engine_capi.so")


class PfsEngineError(Exception):
    """A C++ engine call failed; the message is pfs_last_error()."""


class PfsMergeConflictError(PfsEngineError):
    """A merge hit conflicts nobody resolved; `conflicting_positions` lists
    all of them. Nothing was committed.
    """

    def __init__(self, message, conflicting_positions):
        super().__init__(message)
        self.conflicting_positions = list(conflicting_positions)


class GenerationInfo:
    __slots__ = ("generation_index", "birth_timestamp", "new_chunks", "total_chunks",
                 "pruned", "has_parent", "node_uuid_hex", "parent_uuid_hex", "lateral_parent_count")

    def __init__(self, generation_index, birth_timestamp, new_chunks, total_chunks,
                 pruned, has_parent, node_uuid_hex, parent_uuid_hex, lateral_parent_count=0):
        self.generation_index = generation_index
        self.birth_timestamp = birth_timestamp
        self.new_chunks = new_chunks
        self.total_chunks = total_chunks
        self.pruned = pruned
        self.has_parent = has_parent
        self.node_uuid_hex = node_uuid_hex
        self.parent_uuid_hex = parent_uuid_hex if has_parent else None
        self.lateral_parent_count = lateral_parent_count

    def __repr__(self):
        return (f"GenerationInfo(gen={self.generation_index}, new_chunks={self.new_chunks}, "
                f"total_chunks={self.total_chunks}, pruned={self.pruned})")


class _CGenerationInfo(ctypes.Structure):
    _fields_ = [
        ("generation_index", ctypes.c_uint64),
        ("birth_timestamp", ctypes.c_double),
        ("new_chunks", ctypes.c_uint64),
        ("total_chunks", ctypes.c_uint64),
        ("pruned", ctypes.c_int),
        ("has_parent", ctypes.c_int),
        ("node_uuid_hex", ctypes.c_char * 33),
        ("parent_uuid_hex", ctypes.c_char * 33),
        ("lateral_parent_count", ctypes.c_uint64),
    ]


class _CManifestInfo(ctypes.Structure):
    _fields_ = [
        ("total_blocks", ctypes.c_uint64),
        ("original_size", ctypes.c_uint64),
        ("new_chunks_written", ctypes.c_uint64),
        ("duplicate_chunks_found", ctypes.c_uint64),
        ("has_similarity_fingerprint", ctypes.c_int),
        ("similarity_fingerprint_count", ctypes.c_uint64),
        ("phenotype_mask", ctypes.c_uint32),
        ("phenotype_name", ctypes.c_char * 64),
        ("manifest_filename", ctypes.c_char * 128),
    ]


class _CVacuumReport(ctypes.Structure):
    _fields_ = [
        ("old_size", ctypes.c_uint64),
        ("new_size", ctypes.c_uint64),
        ("bytes_reclaimed", ctypes.c_uint64),
        ("live_chunks", ctypes.c_uint64),
        ("chunks_corrected", ctypes.c_uint64),
        ("orphaned_manifests_removed", ctypes.c_uint64),
        ("orphaned_tmp_files_removed", ctypes.c_uint64),
        ("mirror_old_size", ctypes.c_uint64),
        ("mirror_new_size", ctypes.c_uint64),
        ("mirror_bytes_reclaimed", ctypes.c_uint64),
        ("live_mirrors", ctypes.c_uint64),
    ]


class _CFsckReport(ctypes.Structure):
    _fields_ = [
        ("scanned", ctypes.c_uint64),
        ("healthy", ctypes.c_uint64),
        ("healed", ctypes.c_uint64),
    ]


class _CVaultStats(ctypes.Structure):
    _fields_ = [
        ("container_size", ctypes.c_uint64),
        ("total_chunks", ctypes.c_uint64),
        ("dead_chunks", ctypes.c_uint64),
        ("total_refs", ctypes.c_uint64),
        ("files_tracked", ctypes.c_uint64),
        ("key_epochs", ctypes.c_uint32),
    ]


_LABEL_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)
_GENERATION_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(_CGenerationInfo), ctypes.c_void_p)
_HASH_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)
_TAG_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_void_p)
_TEXT_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)
_SIMILAR_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_double, ctypes.c_void_p)
_LABEL_COUNT_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_void_p)
_RAW_HASH_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_void_p)
_UUID_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.c_char_p, ctypes.c_void_p)

_UINT32_ERROR = 0xFFFFFFFF  # UINT32_MAX: pfs_rotate_key's error value (0 is a valid epoch)


def _load_lib():
    lib = ctypes.CDLL(_LIB_PATH)
    lib.pfs_open.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint8)]
    lib.pfs_open.restype = ctypes.c_void_p
    lib.pfs_close.argtypes = [ctypes.c_void_p]
    lib.pfs_close.restype = None
    lib.pfs_commit_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                      ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_commit_write.restype = ctypes.c_int
    lib.pfs_reconstruct_label.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.pfs_reconstruct_label.restype = ctypes.c_int
    lib.pfs_delete_label.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lib.pfs_delete_label.restype = ctypes.c_int
    lib.pfs_list_labels.argtypes = [ctypes.c_void_p, _LABEL_CALLBACK, ctypes.c_void_p]
    lib.pfs_list_labels.restype = ctypes.c_int
    lib.pfs_get_history.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _GENERATION_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_history.restype = ctypes.c_int
    lib.pfs_get_manifest_info.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(_CManifestInfo)]
    lib.pfs_get_manifest_info.restype = ctypes.c_int

    lib.pfs_fork_write.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                    ctypes.c_uint64, ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_fork_write.restype = ctypes.c_int
    lib.pfs_graft.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_graft.restype = ctypes.c_int
    lib.pfs_merge_branches.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64,
                                        ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_merge_branches.restype = ctypes.c_int
    lib.pfs_merge_branches_resolved.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_uint64), ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    lib.pfs_merge_branches_resolved.restype = ctypes.c_int
    lib.pfs_commit_write_lateral.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                                              ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_commit_write_lateral.restype = ctypes.c_int
    lib.pfs_checkout.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p]
    lib.pfs_checkout.restype = ctypes.c_int
    lib.pfs_rename_label.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.pfs_rename_label.restype = ctypes.c_int
    lib.pfs_delete_label_ex.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_int,
                                         ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
    lib.pfs_delete_label_ex.restype = ctypes.c_int
    lib.pfs_prune_generation.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64, ctypes.c_int,
                                          ctypes.POINTER(ctypes.c_int)]
    lib.pfs_prune_generation.restype = ctypes.c_int
    lib.pfs_vacuum.argtypes = [ctypes.c_void_p, ctypes.POINTER(_CVacuumReport)]
    lib.pfs_vacuum.restype = ctypes.c_int
    lib.pfs_fsck.argtypes = [ctypes.c_void_p, ctypes.POINTER(_CFsckReport), _HASH_CALLBACK, ctypes.c_void_p]
    lib.pfs_fsck.restype = ctypes.c_int
    lib.pfs_set_tag_bool.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    lib.pfs_set_tag_bool.restype = ctypes.c_int
    lib.pfs_set_tag_string.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.pfs_set_tag_string.restype = ctypes.c_int
    lib.pfs_remove_tag.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    lib.pfs_remove_tag.restype = ctypes.c_int
    lib.pfs_get_tags.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _TAG_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_tags.restype = ctypes.c_int
    lib.pfs_get_node_tags_by_uuid.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _TAG_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_node_tags_by_uuid.restype = ctypes.c_int
    lib.pfs_get_lateral_parents_by_uuid.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _UUID_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_lateral_parents_by_uuid.restype = ctypes.c_int
    lib.pfs_get_heads.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _GENERATION_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_heads.restype = ctypes.c_int
    lib.pfs_rotate_key.argtypes = [ctypes.c_void_p]
    lib.pfs_rotate_key.restype = ctypes.c_uint32

    lib.pfs_build_tree.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _TEXT_CALLBACK, ctypes.c_void_p]
    lib.pfs_build_tree.restype = ctypes.c_int
    lib.pfs_similar.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _SIMILAR_CALLBACK, ctypes.c_void_p]
    lib.pfs_similar.restype = ctypes.c_int
    lib.pfs_compute_clades.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_double, _TEXT_CALLBACK,
                                        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_compute_clades.restype = ctypes.c_int
    lib.pfs_get_unreliable_fingerprint_labels.argtypes = [ctypes.c_void_p, _LABEL_COUNT_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_unreliable_fingerprint_labels.restype = ctypes.c_int

    lib.pfs_debug_get_block_hash.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64,
                                              ctypes.POINTER(ctypes.c_uint8)]
    lib.pfs_debug_get_block_hash.restype = ctypes.c_int
    lib.pfs_debug_lookup_chunk.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
                                            ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64),
                                            ctypes.POINTER(ctypes.c_uint32)]
    lib.pfs_debug_lookup_chunk.restype = ctypes.c_int
    lib.pfs_debug_get_mirror.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint8),
                                          ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
    lib.pfs_debug_get_mirror.restype = ctypes.c_int
    lib.pfs_get_container_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_get_container_path.restype = ctypes.c_int
    lib.pfs_get_mirror_container_path.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t]
    lib.pfs_get_mirror_container_path.restype = ctypes.c_int
    lib.pfs_get_stats.argtypes = [ctypes.c_void_p, ctypes.POINTER(_CVaultStats)]
    lib.pfs_get_stats.restype = ctypes.c_int

    lib.pfs_get_manifest_fingerprint.argtypes = [ctypes.c_void_p, ctypes.c_char_p, _RAW_HASH_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_manifest_fingerprint.restype = ctypes.c_int
    lib.pfs_find_node_by_uuid.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
                                           ctypes.POINTER(_CGenerationInfo)]
    lib.pfs_find_node_by_uuid.restype = ctypes.c_int

    lib.pfs_get_generation_chunk_hashes.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint64,
                                                      _RAW_HASH_CALLBACK, ctypes.c_void_p]
    lib.pfs_get_generation_chunk_hashes.restype = ctypes.c_int

    lib.pfs_last_error.argtypes = []
    lib.pfs_last_error.restype = ctypes.c_char_p
    return lib


_lib = _load_lib()


def _err():
    return PfsEngineError(_lib.pfs_last_error().decode("utf-8", errors="replace"))


def _generation_info_from_c(info) -> GenerationInfo:
    return GenerationInfo(
        generation_index=info.generation_index,
        birth_timestamp=info.birth_timestamp,
        new_chunks=info.new_chunks,
        total_chunks=info.total_chunks,
        pruned=bool(info.pruned),
        has_parent=bool(info.has_parent),
        node_uuid_hex=info.node_uuid_hex.decode("ascii"),
        parent_uuid_hex=info.parent_uuid_hex.decode("ascii"),
        lateral_parent_count=info.lateral_parent_count,
    )


def _serialize_calls(cls):
    """Runs every method and property under the instance's reentrant
    self._call_lock: the C++ session isn't thread-safe and the clade worker
    calls it from another thread. Refuses calls on a closed session (a NULL
    handle would crash the process). pfs_last_error() is thread_local.
    """
    lifecycle = {"close", "__enter__", "__exit__", "__del__"}

    def locked(fn):
        @functools.wraps(fn)
        def wrapper(self, *args, **kwargs):
            lock = getattr(self, "_call_lock", None)  # absent if __init__ failed early
            if lock is None:
                return fn(self, *args, **kwargs)
            with lock:
                if fn.__name__ not in lifecycle and getattr(self, "_handle", None) is None:
                    raise PfsEngineError("this vault session is closed")
                return fn(self, *args, **kwargs)
        return wrapper

    for name, member in list(vars(cls).items()):
        if name == "__init__":
            continue
        if isinstance(member, property):
            setattr(cls, name, property(locked(member.fget)))
        elif callable(member):
            setattr(cls, name, locked(member))
    return cls


@_serialize_calls
class CppVaultSession:
    """C++-engine counterpart to VaultSession. `kek`: the 32-byte KEK."""

    def __init__(self, storage_root: str, kek: bytes):
        if len(kek) != 32:
            raise ValueError(f"kek must be exactly 32 bytes, got {len(kek)}")
        self._call_lock = threading.RLock()  # see _serialize_calls
        os.makedirs(storage_root, exist_ok=True)
        kek_buf = (ctypes.c_uint8 * 32).from_buffer_copy(kek)
        handle = _lib.pfs_open(storage_root.encode("utf-8"), kek_buf)
        if not handle:
            raise _err()
        self._handle = handle
        self.storage_root = storage_root

    def close(self):
        if self._handle:
            _lib.pfs_close(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def commit_write(self, label: str, source_path: str) -> str:
        buf = ctypes.create_string_buffer(256)
        rc = _lib.pfs_commit_write(self._handle, label.encode("utf-8"), source_path.encode("utf-8"),
                                    buf, len(buf))
        if rc != 0:
            raise _err()
        return buf.value.decode("utf-8")

    def fork_write(self, label: str, source_path: str, fork_from_generation: int) -> str:
        buf = ctypes.create_string_buffer(256)
        rc = _lib.pfs_fork_write(self._handle, label.encode("utf-8"), source_path.encode("utf-8"),
                                  fork_from_generation, buf, len(buf))
        if rc != 0:
            raise _err()
        return buf.value.decode("utf-8")

    def commit_write_lateral(self, label: str, source_path: str, lateral_parent_label: str) -> str:
        buf = ctypes.create_string_buffer(256)
        rc = _lib.pfs_commit_write_lateral(self._handle, label.encode("utf-8"), source_path.encode("utf-8"),
                                            lateral_parent_label.encode("utf-8"), buf, len(buf))
        if rc != 0:
            raise _err()
        return buf.value.decode("utf-8")

    def graft(self, label_a: str, label_b: str, new_label: str) -> str:
        buf = ctypes.create_string_buffer(256)
        rc = _lib.pfs_graft(self._handle, label_a.encode("utf-8"), label_b.encode("utf-8"),
                             new_label.encode("utf-8"), buf, len(buf))
        if rc != 0:
            raise _err()
        return buf.value.decode("utf-8")

    def merge_branches(self, label: str, generation_a: int, generation_b: int, resolutions=None) -> str:
        """resolutions: {position: "a" or "b"}. Raises PfsMergeConflictError
        listing every unresolved conflict.
        """
        resolutions = resolutions or {}
        bad = [side for side in resolutions.values() if side not in ("a", "b")]
        if bad:
            raise ValueError(f"A resolution must be 'a' or 'b', not {bad[0]!r}.")
        items = sorted(resolutions.items())
        positions = (ctypes.c_uint64 * len(items))(*[p for p, _ in items])
        sides = "".join(s for _, s in items).encode("ascii")
        buf = ctypes.create_string_buffer(256)
        cap = 1024
        while True:
            conflicts = (ctypes.c_uint64 * cap)()
            count = ctypes.c_size_t(0)
            rc = _lib.pfs_merge_branches_resolved(
                self._handle, label.encode("utf-8"), generation_a, generation_b, positions, sides, len(items),
                buf, len(buf), conflicts, cap, ctypes.byref(count))
            if rc == 1 and count.value > cap:  # nothing was committed: ask again with room for all
                cap = count.value
                continue
            break
        if rc == 1:
            message = _lib.pfs_last_error().decode("utf-8", errors="replace")
            raise PfsMergeConflictError(message, list(conflicts[:count.value]))
        if rc != 0:
            raise _err()
        return buf.value.decode("utf-8")

    def reconstruct_label(self, label: str, output_path: str) -> None:
        rc = _lib.pfs_reconstruct_label(self._handle, label.encode("utf-8"), output_path.encode("utf-8"))
        if rc != 0:
            raise _err()

    def checkout(self, label: str, generation_index: int, output_path: str) -> None:
        rc = _lib.pfs_checkout(self._handle, label.encode("utf-8"), generation_index, output_path.encode("utf-8"))
        if rc != 0:
            raise _err()

    def rename_label(self, old_label: str, new_label: str) -> None:
        rc = _lib.pfs_rename_label(self._handle, old_label.encode("utf-8"), new_label.encode("utf-8"))
        if rc != 0:
            raise _err()

    def delete_label(self, label: str, force: bool = False) -> dict:
        freed = ctypes.c_uint64(0)
        kept_shared = ctypes.c_uint64(0)
        rc = _lib.pfs_delete_label_ex(self._handle, label.encode("utf-8"), int(force),
                                       ctypes.byref(freed), ctypes.byref(kept_shared))
        if rc != 0:
            raise _err()
        return {"manifests_freed": freed.value, "manifests_kept_shared": kept_shared.value}

    def prune_generation(self, label: str, generation_index: int, force: bool = False) -> bool:
        freed = ctypes.c_int(0)
        rc = _lib.pfs_prune_generation(self._handle, label.encode("utf-8"), generation_index, int(force),
                                        ctypes.byref(freed))
        if rc != 0:
            raise _err()
        return bool(freed.value)

    def vacuum(self) -> dict:
        report = _CVacuumReport()
        rc = _lib.pfs_vacuum(self._handle, ctypes.byref(report))
        if rc != 0:
            raise _err()
        return {
            "old_size": report.old_size,
            "new_size": report.new_size,
            "bytes_reclaimed": report.bytes_reclaimed,
            "live_chunks": report.live_chunks,
            "chunks_corrected": report.chunks_corrected,
            "orphaned_manifests_removed": report.orphaned_manifests_removed,
            "orphaned_tmp_files_removed": report.orphaned_tmp_files_removed,
            "mirror_old_size": report.mirror_old_size,
            "mirror_new_size": report.mirror_new_size,
            "mirror_bytes_reclaimed": report.mirror_bytes_reclaimed,
            "live_mirrors": report.live_mirrors,
        }

    def fsck(self) -> dict:
        report = _CFsckReport()
        unrecoverable = []

        @_HASH_CALLBACK
        def _cb(hex_cstr, _user_data):
            unrecoverable.append(hex_cstr.decode("ascii"))

        rc = _lib.pfs_fsck(self._handle, ctypes.byref(report), _cb, None)
        if rc != 0:
            raise _err()
        return {
            "scanned": report.scanned,
            "healthy": report.healthy,
            "healed": report.healed,
            "unrecoverable": unrecoverable,
        }

    def set_tag(self, label: str, key: str, value) -> None:
        """value: bool sets a boolean tag; anything else is stored as its str()."""
        if isinstance(value, bool):
            rc = _lib.pfs_set_tag_bool(self._handle, label.encode("utf-8"), key.encode("utf-8"), int(value))
        else:
            rc = _lib.pfs_set_tag_string(self._handle, label.encode("utf-8"), key.encode("utf-8"),
                                          str(value).encode("utf-8"))
        if rc != 0:
            raise _err()

    def remove_tag(self, label: str, key: str) -> bool:
        rc = _lib.pfs_remove_tag(self._handle, label.encode("utf-8"), key.encode("utf-8"))
        if rc < 0:
            raise _err()
        return bool(rc)

    def get_tags(self, label: str) -> dict:
        tags = {}

        @_TAG_CALLBACK
        def _cb(key_cstr, is_bool, bool_value, string_value_cstr, _user_data):
            key = key_cstr.decode("utf-8")
            tags[key] = bool(bool_value) if is_bool else string_value_cstr.decode("utf-8")

        rc = _lib.pfs_get_tags(self._handle, label.encode("utf-8"), _cb, None)
        if rc < 0:
            raise _err()
        return tags

    def get_node_tags(self, uuid_hex: str) -> dict:
        """Tags recorded on this generation (may differ from the current tip's)."""
        tags = {}

        @_TAG_CALLBACK
        def _cb(key_cstr, is_bool, bool_value, string_value_cstr, _user_data):
            key = key_cstr.decode("utf-8")
            tags[key] = bool(bool_value) if is_bool else string_value_cstr.decode("utf-8")

        rc = _lib.pfs_get_node_tags_by_uuid(self._handle, uuid_hex.encode("ascii"), _cb, None)
        if rc < 0:
            raise _err()
        return tags

    def get_lateral_parents(self, uuid_hex: str) -> list:
        """Lateral parent uuids of this generation (graft sources, duplicate source)."""
        uuids = []

        @_UUID_CALLBACK
        def _cb(uuid_cstr, _user_data):
            uuids.append(uuid_cstr.decode("ascii"))

        rc = _lib.pfs_get_lateral_parents_by_uuid(self._handle, uuid_hex.encode("ascii"), _cb, None)
        if rc < 0:
            raise _err()
        return uuids

    def list_labels(self) -> list:
        labels = []

        @_LABEL_CALLBACK
        def _cb(label_cstr, _user_data):
            labels.append(label_cstr.decode("utf-8"))

        rc = _lib.pfs_list_labels(self._handle, _cb, None)
        if rc < 0:
            raise _err()
        return labels

    def get_history(self, label: str) -> list:
        history = []

        @_GENERATION_CALLBACK
        def _cb(info_ptr, _user_data):
            history.append(_generation_info_from_c(info_ptr.contents))

        rc = _lib.pfs_get_history(self._handle, label.encode("utf-8"), _cb, None)
        if rc < 0:
            raise _err()
        return history

    def get_heads(self, label: str) -> list:
        heads = []

        @_GENERATION_CALLBACK
        def _cb(info_ptr, _user_data):
            heads.append(_generation_info_from_c(info_ptr.contents))

        rc = _lib.pfs_get_heads(self._handle, label.encode("utf-8"), _cb, None)
        if rc < 0:
            raise _err()
        return heads

    def get_manifest_info(self, label: str) -> dict:
        info = _CManifestInfo()
        rc = _lib.pfs_get_manifest_info(self._handle, label.encode("utf-8"), ctypes.byref(info))
        if rc != 0:
            raise _err()
        return {
            "total_blocks": info.total_blocks,
            "original_size": info.original_size,
            "new_chunks_written": info.new_chunks_written,
            "duplicate_chunks_found": info.duplicate_chunks_found,
            "has_similarity_fingerprint": bool(info.has_similarity_fingerprint),
            "similarity_fingerprint_count": info.similarity_fingerprint_count,
            "phenotype_mask": info.phenotype_mask,
            "phenotype_name": info.phenotype_name.decode("utf-8", errors="replace"),
            "manifest_filename": info.manifest_filename.decode("utf-8", errors="replace"),
        }

    def get_fingerprint(self, label: str) -> set:
        """The current tip's similarity fingerprint (set of 32-byte hashes); empty if none."""
        traits = set()

        @_RAW_HASH_CALLBACK
        def _cb(hash_ptr, _user_data):
            traits.add(bytes(hash_ptr[:32]))

        rc = _lib.pfs_get_manifest_fingerprint(self._handle, label.encode("utf-8"), _cb, None)
        if rc < 0:
            raise _err()
        return traits

    def find_node_by_uuid(self, uuid_hex: str):
        """(label, GenerationInfo) for a node uuid in any label, or None."""
        label_buf = ctypes.create_string_buffer(256)
        info = _CGenerationInfo()
        rc = _lib.pfs_find_node_by_uuid(self._handle, uuid_hex.encode("ascii"), label_buf, len(label_buf),
                                         ctypes.byref(info))
        if rc != 0:
            return None
        return label_buf.value.decode("utf-8"), _generation_info_from_c(info)

    def build_tree(self, algorithm: str = "upgma") -> str:
        """Clade tree (UPGMA or NJ) over every label with a fingerprint."""
        rendering = []

        @_TEXT_CALLBACK
        def _cb(text_cstr, _user_data):
            rendering.append(text_cstr.decode("utf-8", errors="replace"))

        rc = _lib.pfs_build_tree(self._handle, algorithm.encode("utf-8"), _cb, None)
        if rc < 0:
            raise _err()
        return rendering[0] if rendering else ""

    def similar(self, label: str) -> list:
        """Every other fingerprinted label, as (label, distance), closest first."""
        ranked = []

        @_SIMILAR_CALLBACK
        def _cb(other_label_cstr, distance, _user_data):
            ranked.append((other_label_cstr.decode("utf-8"), distance))

        rc = _lib.pfs_similar(self._handle, label.encode("utf-8"), _cb, None)
        if rc < 0:
            raise _err()
        return ranked

    def compute_clades(self, label: str, threshold: float = 0.0) -> tuple:
        """(representative, [members]) of `label`'s clade. threshold <= 0 uses the
        default 0.80. The representative is the smallest member, not a root.
        """
        members = []

        @_TEXT_CALLBACK
        def _cb(text_cstr, _user_data):
            members.append(text_cstr.decode("utf-8"))

        rep_buf = ctypes.create_string_buffer(256)
        rc = _lib.pfs_compute_clades(self._handle, label.encode("utf-8"), threshold, _cb, None,
                                      rep_buf, len(rep_buf))
        if rc < 0:
            raise _err()
        return rep_buf.value.decode("utf-8"), members

    def unreliable_fingerprint_labels(self) -> dict:
        """{label: chunk_count} for fingerprints below kMinReliableTraitCount."""
        unreliable = {}

        @_LABEL_COUNT_CALLBACK
        def _cb(label_cstr, count, _user_data):
            unreliable[label_cstr.decode("utf-8")] = count

        rc = _lib.pfs_get_unreliable_fingerprint_labels(self._handle, _cb, None)
        if rc < 0:
            raise _err()
        return unreliable

    def get_generation_chunk_hashes(self, label: str, generation_index: int) -> list:
        """Ordered chunk hashes of any generation of `label` (for lineage diffs)."""
        hashes = []

        @_RAW_HASH_CALLBACK
        def _cb(hash_ptr, _user_data):
            hashes.append(bytes(hash_ptr[:32]))

        rc = _lib.pfs_get_generation_chunk_hashes(self._handle, label.encode("utf-8"), generation_index, _cb, None)
        if rc < 0:
            raise _err()
        return hashes

    def debug_get_block_hash(self, label: str, block_index: int) -> bytes:
        """Diagnostic, for 'attack'."""
        buf = (ctypes.c_uint8 * 32)()
        rc = _lib.pfs_debug_get_block_hash(self._handle, label.encode("utf-8"), block_index, buf)
        if rc != 0:
            raise _err()
        return bytes(buf)

    def debug_lookup_chunk(self, content_hash: bytes) -> dict:
        """Diagnostic, for 'attack'."""
        if len(content_hash) != 32:
            raise ValueError("content_hash must be exactly 32 bytes")
        buf = (ctypes.c_uint8 * 32).from_buffer_copy(content_hash)
        offset = ctypes.c_uint64(0)
        length = ctypes.c_uint64(0)
        epoch_id = ctypes.c_uint32(0)
        rc = _lib.pfs_debug_lookup_chunk(self._handle, buf, ctypes.byref(offset), ctypes.byref(length),
                                          ctypes.byref(epoch_id))
        if rc != 0:
            raise _err()
        return {"offset": offset.value, "length": length.value, "epoch_id": epoch_id.value}

    def debug_get_mirror(self, content_hash: bytes) -> Optional[dict]:
        """Diagnostic: a chunk's mirror location, or None."""
        if len(content_hash) != 32:
            raise ValueError("content_hash must be exactly 32 bytes")
        buf = (ctypes.c_uint8 * 32).from_buffer_copy(content_hash)
        offset = ctypes.c_uint64(0)
        length = ctypes.c_uint64(0)
        rc = _lib.pfs_debug_get_mirror(self._handle, buf, ctypes.byref(offset), ctypes.byref(length))
        if rc != 0:
            return None
        return {"offset": offset.value, "length": length.value}

    @property
    def container_path(self) -> str:
        buf = ctypes.create_string_buffer(1024)
        _lib.pfs_get_container_path(self._handle, buf, len(buf))
        return buf.value.decode("utf-8")

    @property
    def mirror_container_path(self) -> str:
        buf = ctypes.create_string_buffer(1024)
        _lib.pfs_get_mirror_container_path(self._handle, buf, len(buf))
        return buf.value.decode("utf-8")

    def rotate_key(self) -> int:
        new_epoch_id = _lib.pfs_rotate_key(self._handle)
        if new_epoch_id == _UINT32_ERROR:
            raise _err()
        return new_epoch_id

    def get_stats(self) -> dict:
        """Vault statistics from a full dedup-index scan."""
        stats = _CVaultStats()
        rc = _lib.pfs_get_stats(self._handle, ctypes.byref(stats))
        if rc != 0:
            raise _err()
        return {
            "container_size": stats.container_size,
            "total_chunks": stats.total_chunks,
            "dead_chunks": stats.dead_chunks,
            "total_refs": stats.total_refs,
            "files_tracked": stats.files_tracked,
            "key_epochs": stats.key_epochs,
        }
