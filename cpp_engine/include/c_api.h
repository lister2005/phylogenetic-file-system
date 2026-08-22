/* Plain C ABI over VaultSession -- the actual boundary Python's ctypes
 * crosses. No C++ types leak through (ctypes can only call C functions:
 * no name mangling, no classes, no exceptions across the boundary,
 * which is exactly why this file exists as a thin shim rather than
 * exposing VaultSession itself).
 *
 * Division of responsibility, deliberate: this does NOT do passphrase-
 * based unlocking (master_key_store.py's scrypt KEK derivation isn't
 * ported to C++ -- see cpp_port_plan.txt). Python still owns "how do we
 * turn a human's passphrase into a key" (it already does, via
 * gearhash.master_key_store.load_vault_key); this API takes the raw
 * 32-byte KEK Python already has. C++ owns "given a key, do fast
 * storage operations" -- that split is intentional, not a shortcut.
 *
 * Error handling: every function that can fail returns 0 on success,
 * -1 on failure. pfs_last_error() returns the most recent failure's
 * message (thread-local, valid until the next failing call on the same
 * thread) -- ctypes callers should check it immediately after a -1.
 */
#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pfs_session pfs_session_t; /* opaque */

/* kek32 must point to exactly 32 bytes. Returns NULL on failure. */
pfs_session_t* pfs_open(const char* storage_root, const uint8_t* kek32);
void pfs_close(pfs_session_t* session);

/* Writes source_path's content under `label`, recording a real lineage
 * generation (skipped only for a byte-identical resave of the current
 * tip) and moving the catalog pointer -- the exact same commit_write()
 * semantics vault_session.py's Python callers get. The resulting
 * manifest filename (not full path) is copied into out_manifest_filename
 * (a caller-supplied buffer of out_buf_len bytes; 128 bytes is always
 * enough -- manifest filenames are a fixed 64-hex-char hash + a short
 * fixed suffix). */
int pfs_commit_write(pfs_session_t* session, const char* label, const char* source_path,
                      char* out_manifest_filename, size_t out_buf_len);

/* Reconstructs `label`'s CURRENT TIP to output_path. */
int pfs_reconstruct_label(pfs_session_t* session, const char* label, const char* output_path);

int pfs_delete_label(pfs_session_t* session, const char* label);

typedef void (*pfs_label_callback)(const char* label, void* user_data);
/* Invokes cb once per label currently in the catalog. Returns the
 * number of labels enumerated, or -1 on failure. */
int pfs_list_labels(pfs_session_t* session, pfs_label_callback cb, void* user_data);

typedef struct {
    uint64_t generation_index;
    double birth_timestamp;
    uint64_t new_chunks;
    uint64_t total_chunks;
    int pruned;     /* 0/1 */
    int has_parent; /* 0/1 */
    char node_uuid_hex[33];   /* 32 hex chars + NUL */
    char parent_uuid_hex[33]; /* only meaningful if has_parent */
    uint64_t lateral_parent_count;
} pfs_generation_info_t;

typedef void (*pfs_generation_callback)(const pfs_generation_info_t* info, void* user_data);
/* Invokes cb once per generation of `label`, oldest first -- exactly
 * what a Tree-mode GUI view needs to render. Returns the number of
 * generations enumerated, or -1 on failure. */
int pfs_get_history(pfs_session_t* session, const char* label, pfs_generation_callback cb, void* user_data);

typedef struct {
    uint64_t total_blocks;
    uint64_t original_size;
    uint64_t new_chunks_written;
    uint64_t duplicate_chunks_found;
    int has_similarity_fingerprint;      /* 0/1 */
    uint64_t similarity_fingerprint_count;
    uint32_t phenotype_mask;
    char phenotype_name[64];
    char manifest_filename[128];
} pfs_manifest_info_t;

int pfs_get_manifest_info(pfs_session_t* session, const char* label, pfs_manifest_info_t* out_info);

/* Every 32-byte SIMILARITY_PROFILE fingerprint hash for `label`'s
 * current tip, via cb (raw bytes, not hex -- unlike pfs_hash_callback's
 * hex strings, this is for a caller like the GUI that wants to run its
 * own Jaccard-distance math against another label's fingerprint, not
 * display it). Returns the count enumerated (0 if none stored), or -1
 * on error (e.g. no such label). */
typedef void (*pfs_raw_hash_callback)(const uint8_t* hash32, void* user_data);
int pfs_get_manifest_fingerprint(pfs_session_t* session, const char* label,
                                  pfs_raw_hash_callback cb, void* user_data);

/* Finds a lineage node by its hex UUID, searching across EVERY label
 * (matching lineage.py's find_node_by_uuid, which is a global index,
 * not scoped to one label) -- needed by the GUI to figure out which
 * label owns a node the user clicked on. out_label_buf must be at
 * least 256 bytes. Returns 0 on success, -1 if not found/error. */
int pfs_find_node_by_uuid(pfs_session_t* session, const char* uuid_hex,
                           char* out_label_buf, size_t out_label_buf_len,
                           pfs_generation_info_t* out_info);

/* This generation's ordered (block_index -> content_hash) list, via cb
 * (raw 32-byte hashes, in block order) -- unlike
 * pfs_debug_get_block_hash (current tip only, one block at a time,
 * diagnostic-only), this reaches ANY past generation_index of `label`,
 * which is what a real lineage diff (comparing two generations' chunk
 * lists position-by-position, the same technique merge_branches uses
 * against a common ancestor) needs. Returns the count enumerated, or
 * -1 on error (no such generation, or it's pruned -- its content is no
 * longer available). */
int pfs_get_generation_chunk_hashes(pfs_session_t* session, const char* label, uint64_t generation_index,
                                     pfs_raw_hash_callback cb, void* user_data);

/* fork: like pfs_commit_write, but the new generation's PRIMARY parent
 * is fork_from_generation (an OLD generation, not necessarily the
 * current tip) instead -- this is what actually creates a second
 * branch head. */
int pfs_fork_write(pfs_session_t* session, const char* label, const char* source_path,
                    uint64_t fork_from_generation, char* out_manifest_filename, size_t out_buf_len);

/* Lateral Gene Transfer: concatenates label_a's current content then
 * label_b's, commits the result under new_label with both current tips
 * recorded as parents. Refuses if either source is tagged
 * "no_graft_source". */
int pfs_graft(pfs_session_t* session, const char* label_a, const char* label_b, const char* new_label,
              char* out_manifest_filename, size_t out_buf_len);

/* Commits source_path's content under `label` (a NEW label, ordinarily
 * -- there's nothing stopping an existing one) with lateral_parent_
 * label's CURRENT tip recorded as an additional (non-primary) parent.
 * The underlying VaultSession::commit_write already supports an
 * arbitrary list of lateral parents (used internally by pfs_graft with
 * two); this exposes the single-lateral-parent case directly, for a
 * "duplicate this label under a new name, linked back to the original"
 * operation -- distinct from graft, which concatenates TWO sources'
 * bytes together rather than reusing one source's content as-is. */
int pfs_commit_write_lateral(pfs_session_t* session, const char* label, const char* source_path,
                              const char* lateral_parent_label,
                              char* out_manifest_filename, size_t out_buf_len);

/* Resolves two divergent branches of `label` (see merge.hpp for the
 * algorithm). On a genuine content conflict, returns -1 and
 * pfs_last_error() lists every conflicting chunk position -- commits
 * nothing in that case. */
int pfs_merge_branches(pfs_session_t* session, const char* label, uint64_t generation_a, uint64_t generation_b,
                       char* out_manifest_filename, size_t out_buf_len);

/* Reconstructs one SPECIFIC past generation of `label` (not
 * necessarily the current tip) to output_path. */
int pfs_checkout(pfs_session_t* session, const char* label, uint64_t generation_index, const char* output_path);

int pfs_rename_label(pfs_session_t* session, const char* old_label, const char* new_label);

/* Full delete semantics: refuses (unless force) if the current tip is
 * tagged "protected"; only actually frees a manifest from disk once
 * NOTHING else in the vault still references it (out_freed/
 * out_kept_shared may be NULL if the caller doesn't need the counts). */
int pfs_delete_label_ex(pfs_session_t* session, const char* label, int force,
                         uint64_t* out_freed, uint64_t* out_kept_shared);

/* Reclaims ONE historical generation's storage, keeping the label and
 * every OTHER generation intact. Refuses to prune the current tip, and
 * refuses (unless force) if THIS generation is tagged "protected".
 * *out_freed is set to 1/0 (may be NULL). */
int pfs_prune_generation(pfs_session_t* session, const char* label, uint64_t generation_index, int force,
                          int* out_freed);

typedef struct {
    uint64_t old_size;
    uint64_t new_size;
    uint64_t bytes_reclaimed;
    uint64_t live_chunks;
    uint64_t chunks_corrected;
    uint64_t orphaned_manifests_removed;
    uint64_t orphaned_tmp_files_removed;
    /* Ancestral Hardening mirror container compaction. All 0 when this
     * call had nothing mirrored to reclaim (the mirror container is left
     * completely untouched in that case, not just "reported as zero"). */
    uint64_t mirror_old_size;
    uint64_t mirror_new_size;
    uint64_t mirror_bytes_reclaimed;
    uint64_t live_mirrors;
} pfs_vacuum_report_t;

int pfs_vacuum(pfs_session_t* session, pfs_vacuum_report_t* out_report);

typedef struct {
    uint64_t scanned;
    uint64_t healthy;
    uint64_t healed;
} pfs_fsck_report_t;

typedef void (*pfs_hash_callback)(const char* content_hash_hex64, void* user_data);
/* Ancestral Hardening's proactive scan. cb (may be NULL) is invoked
 * once per UNRECOVERABLE chunk's hex-encoded content hash. */
int pfs_fsck(pfs_session_t* session, pfs_fsck_report_t* out_report, pfs_hash_callback cb, void* user_data);

int pfs_set_tag_bool(pfs_session_t* session, const char* label, const char* key, int value);
int pfs_set_tag_string(pfs_session_t* session, const char* label, const char* key, const char* value);
/* Returns 1 if a tag was actually removed, 0 if the key didn't exist (not an error), -1 on error. */
int pfs_remove_tag(pfs_session_t* session, const char* label, const char* key);

typedef void (*pfs_tag_callback)(const char* key, int is_bool, int bool_value, const char* string_value,
                                  void* user_data);
int pfs_get_tags(pfs_session_t* session, const char* label, pfs_tag_callback cb, void* user_data);

/* Tags recorded on THIS SPECIFIC generation (a past generation's own
 * epigenetic_tags snapshot, which can differ from the label's CURRENT
 * tags if a tag was added/removed since -- unlike pfs_get_tags, which
 * always reads the current tip). */
int pfs_get_node_tags_by_uuid(pfs_session_t* session, const char* uuid_hex,
                               pfs_tag_callback cb, void* user_data);

typedef void (*pfs_uuid_callback)(const char* uuid_hex, void* user_data);
/* Every lateral (non-primary) parent uuid recorded on this SPECIFIC
 * generation -- e.g. both source uuids for a graft, or the one source
 * uuid for a duplicate. Needed by the GUI's Cosmic Web view to draw
 * cross-label edges. Returns the count enumerated, or -1. */
int pfs_get_lateral_parents_by_uuid(pfs_session_t* session, const char* uuid_hex,
                                     pfs_uuid_callback cb, void* user_data);

/* Every currently-open branch head for `label` (normally exactly one;
 * more than one once 'fork' has created a divergent branch). */
int pfs_get_heads(pfs_session_t* session, const char* label, pfs_generation_callback cb, void* user_data);

/* Generates a fresh DEK for a new epoch, makes it current, persists
 * immediately -- does NOT re-encrypt any existing data (rotation is
 * cheap regardless of vault size). Returns the new epoch_id, or
 * UINT32_MAX on error (check pfs_last_error()) -- 0 is itself a valid
 * epoch_id, so this can't use the usual 0/-1 convention. */
uint32_t pfs_rotate_key(pfs_session_t* session);

/* Clade clustering (PhylogeneticAnalyzer.py + TreeConstructor.py port).
 * Every write already attaches a SIMILARITY_PROFILE fingerprint to its
 * manifest synchronously (see pipeline.cpp) -- unlike the Python CLI,
 * which backgrounds this on its own thread, so these never need to warn
 * about "still fingerprinting in the background." Labels with no stored
 * fingerprint (a manifest read failure, in practice) are silently
 * excluded, same as Python's own "stale" exclusion. */

typedef void (*pfs_text_callback)(const char* text, void* user_data);
/* Builds the clade tree (algorithm: "upgma" or "nj") over every label
 * with a stored fingerprint and renders it as ASCII art via cb, called
 * exactly once with the full rendering. Returns the number of labels
 * included, or -1 (including "fewer than 2 labels have a fingerprint"). */
int pfs_build_tree(pfs_session_t* session, const char* algorithm, pfs_text_callback cb, void* user_data);

typedef void (*pfs_similar_callback)(const char* other_label, double jaccard_distance, void* user_data);
/* Ranks every OTHER label with a stored fingerprint by Jaccard distance
 * to `label`, closest first. Returns the count enumerated, or -1. */
int pfs_similar(pfs_session_t* session, const char* label, pfs_similar_callback cb, void* user_data);

/* Finds the clade (similarity connected-component -- see phylo.hpp's
 * compute_clades(), already used internally by pfs_fuse_cpp.cpp's clade
 * directories, just not previously exposed through this C API) that
 * `label` belongs to. Pass threshold <= 0.0 to use the design doc's own
 * kDefaultCladeThreshold (0.80); a positive value overrides it, same
 * knob TreeConstructor.py's compute_clades() exposes on the Python side.
 * Invokes cb once per member of that clade (including `label` itself),
 * in compute_clades()'s own lexicographic order. If out_representative
 * and out_buf_len are non-null/non-zero, the clade's representative
 * label (compute_clades()'s lexicographically-smallest member, used as
 * its map key) is copied there, NUL-terminated and truncated to fit.
 * Returns the member count, or -1 (no such label, or it has no stored
 * fingerprint -- check pfs_last_error()). */
int pfs_compute_clades(pfs_session_t* session, const char* label, double threshold,
                        pfs_text_callback cb, void* user_data,
                        char* out_representative, size_t out_buf_len);

typedef void (*pfs_label_count_callback)(const char* label, uint64_t chunk_count, void* user_data);
/* Every label (of those with a stored similarity fingerprint) whose
 * fingerprint has fewer chunks than phylo.hpp's kMinReliableTraitCount
 * -- the same "too little data to fingerprint reliably" check
 * PhylogeneticAnalyzer.py's trait_set_is_reliable() makes on the Python
 * engine, so pfs_cli.py's CppPFSShell can print the identical
 * low-confidence warning `similar`/`tree`/`clade` print on the Python
 * side, filtered down to whichever labels are actually involved in that
 * particular result. Invokes cb once per such label with its real chunk
 * count. Returns the count found (0 if none), or -1 on error. */
int pfs_get_unreliable_fingerprint_labels(pfs_session_t* session, pfs_label_count_callback cb, void* user_data);

/* Diagnostic accessors for the 'attack' self-test suite ONLY -- expose
 * exactly enough low-level detail (a block's content hash; where a
 * chunk physically lives) to let a caller deliberately corrupt bytes
 * and verify detection, same idea as pfs_cli.py's own adversarial
 * tests. Not meant for ordinary use. out_hash32/out_content_hash32
 * must point to 32 writable bytes. */
int pfs_debug_get_block_hash(pfs_session_t* session, const char* label, uint64_t block_index,
                              uint8_t* out_hash32);
int pfs_debug_lookup_chunk(pfs_session_t* session, const uint8_t* content_hash32,
                            uint64_t* out_offset, uint64_t* out_length, uint32_t* out_epoch_id);
/* Same idea as pfs_debug_lookup_chunk, but for a chunk's Ancestral
 * Hardening mirror copy instead of its primary one -- lets a test/attack
 * caller find and directly corrupt/verify a mirror's bytes, and confirm
 * a mirror's offset actually changed after vacuum() compacted the
 * mirror container. Returns -1 (with an error message) if this chunk
 * has no mirror. */
int pfs_debug_get_mirror(pfs_session_t* session, const uint8_t* content_hash32,
                          uint64_t* out_offset, uint64_t* out_length);
/* Path to the primary data container -- a fixed, documented filename
 * (data_container.bin under storage_root), not a secret; exposed so
 * the attack suite can corrupt bytes directly without hardcoding the
 * convention on the Python side too. */
int pfs_get_container_path(pfs_session_t* session, char* out_path, size_t out_buf_len);
/* Path to the Ancestral Hardening mirror container -- same rationale as
 * pfs_get_container_path, for data_container_mirror.bin. */
int pfs_get_mirror_container_path(pfs_session_t* session, char* out_path, size_t out_buf_len);

typedef struct {
    uint64_t container_size;  /* bytes, primary data container on disk */
    uint64_t total_chunks;    /* unique chunks currently in the dedup index */
    uint64_t dead_chunks;     /* of those, ref_count == 0 -- reclaimable via vacuum */
    uint64_t total_refs;      /* sum of every chunk's ref_count -- dedup ratio is
                                * total_refs / total_chunks */
    uint64_t files_tracked;   /* labels currently in the catalog */
    uint32_t key_epochs;      /* current_epoch + 1 */
} pfs_vault_stats_t;

/* Vault-wide statistics -- the C++-engine equivalent of pfs_cli.py's
 * Python-engine 'stats' command. Computed for real off the dedup
 * index's full table scan (same iter_all() vacuum/fsck/rebuild_ref_counts
 * already use) plus the catalog and keyring, not cached/approximated. */
int pfs_get_stats(pfs_session_t* session, pfs_vault_stats_t* out_stats);

const char* pfs_last_error(void);

#ifdef __cplusplus
}
#endif
