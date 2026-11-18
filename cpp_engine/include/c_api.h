/*
 * Plain C ABI over VaultSession, for Python's ctypes (no C++ types,
 * names or exceptions cross it).
 *
 * Takes the raw 32-byte KEK: turning a passphrase into a key stays in
 * Python (gearhash.master_key_store).
 *
 * Functions return 0 on success and -1 on failure (unless noted);
 * pfs_last_error() gives the last failure's message, per thread.
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

/*
 * Stores source_path as `label` (VaultSession::commit_write semantics) and
 * copies the manifest filename into out_manifest_filename (128 bytes is
 * always enough).
 */
int pfs_commit_write(pfs_session_t* session, const char* label, const char* source_path,
                      char* out_manifest_filename, size_t out_buf_len);

/* Reconstructs `label`'s current tip to output_path. */
int pfs_reconstruct_label(pfs_session_t* session, const char* label, const char* output_path);

int pfs_delete_label(pfs_session_t* session, const char* label);

typedef void (*pfs_label_callback)(const char* label, void* user_data);
/* Calls cb once per catalog label. Returns the count, or -1. */
int pfs_list_labels(pfs_session_t* session, pfs_label_callback cb, void* user_data);

typedef struct {
    uint64_t generation_index;
    double birth_timestamp;
    uint64_t new_chunks;
    uint64_t total_chunks;
    int pruned;     /* 0/1 */
    int has_parent; /* 0/1 */
    char node_uuid_hex[33];   /* 32 hex chars + NUL */
    char parent_uuid_hex[33]; /* if has_parent */
    uint64_t lateral_parent_count;
} pfs_generation_info_t;

typedef void (*pfs_generation_callback)(const pfs_generation_info_t* info, void* user_data);
/* Calls cb once per generation of `label`, oldest first. Returns the count, or -1. */
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

/*
 * Calls cb with each raw 32-byte similarity fingerprint hash of `label`'s
 * tip. Returns the count (0 if none), or -1.
 */
typedef void (*pfs_raw_hash_callback)(const uint8_t* hash32, void* user_data);
int pfs_get_manifest_fingerprint(pfs_session_t* session, const char* label,
                                  pfs_raw_hash_callback cb, void* user_data);

/* Finds a node by hex uuid in any label. out_label_buf: at least 256 bytes. */
int pfs_find_node_by_uuid(pfs_session_t* session, const char* uuid_hex,
                           char* out_label_buf, size_t out_label_buf_len,
                           pfs_generation_info_t* out_info);

/*
 * Calls cb with each chunk hash of any generation of `label`, in block
 * order. Returns the count, or -1 (no such generation, or pruned).
 */
int pfs_get_generation_chunk_hashes(pfs_session_t* session, const char* label, uint64_t generation_index,
                                     pfs_raw_hash_callback cb, void* user_data);

/* Like pfs_commit_write, with fork_from_generation as the primary parent (a new branch). */
int pfs_fork_write(pfs_session_t* session, const char* label, const char* source_path,
                    uint64_t fork_from_generation, char* out_manifest_filename, size_t out_buf_len);

/*
 * Graft: label_a's content then label_b's, as new_label, with both tips
 * as parents. Refuses a "no_graft_source" source.
 */
int pfs_graft(pfs_session_t* session, const char* label_a, const char* label_b, const char* new_label,
              char* out_manifest_filename, size_t out_buf_len);

/*
 * Commits source_path as `label` with lateral_parent_label's tip as an
 * extra parent (duplicate-with-link).
 */
int pfs_commit_write_lateral(pfs_session_t* session, const char* label, const char* source_path,
                              const char* lateral_parent_label,
                              char* out_manifest_filename, size_t out_buf_len);

/*
 * Merges two branches of `label` (merge.hpp). On a conflict returns -1,
 * pfs_last_error() lists the positions, and nothing is committed.
 */
int pfs_merge_branches(pfs_session_t* session, const char* label, uint64_t generation_a, uint64_t generation_b,
                       char* out_manifest_filename, size_t out_buf_len);

/*
 * Like pfs_merge_branches, with resolutions: positions[i] is settled by
 * sides[i] ('a' or 'b'). Returns 0 on success, 1 on an unresolved conflict
 * (the first `conflicts_cap` conflicting positions go to out_conflicts and
 * the total to *out_conflict_count; nothing is committed), -1 on any other
 * error (see pfs_last_error()).
 */
int pfs_merge_branches_resolved(pfs_session_t* session, const char* label, uint64_t generation_a,
                                uint64_t generation_b, const uint64_t* positions, const char* sides,
                                size_t resolution_count, char* out_manifest_filename, size_t out_buf_len,
                                uint64_t* out_conflicts, size_t conflicts_cap, size_t* out_conflict_count);

/*
 * The generation two branches of label last had in common (for a
 * line-by-line merge done by the caller). Same checks as a merge.
 */
int pfs_merge_base(pfs_session_t* session, const char* label, uint64_t generation_a, uint64_t generation_b,
                   uint64_t* out_base_generation);

/*
 * Commits source_path (content the caller merged) as the merge of two
 * branches: generation_a primary parent, generation_b lateral parent.
 */
int pfs_commit_merged(pfs_session_t* session, const char* label, uint64_t generation_a, uint64_t generation_b,
                      const char* source_path, char* out_manifest_filename, size_t out_buf_len);

/* Reconstructs one past generation of `label` to output_path. */
int pfs_checkout(pfs_session_t* session, const char* label, uint64_t generation_index, const char* output_path);

int pfs_rename_label(pfs_session_t* session, const char* old_label, const char* new_label);

/*
 * Deletes a label. Refuses a "protected" tip unless force; frees a
 * manifest only once unreferenced. out_freed/out_kept_shared may be NULL.
 */
int pfs_delete_label_ex(pfs_session_t* session, const char* label, int force,
                         uint64_t* out_freed, uint64_t* out_kept_shared);

/*
 * Frees one past generation. Refuses the tip, and a "protected"
 * generation unless force. *out_freed: 1/0 (may be NULL).
 */
int pfs_prune_generation(pfs_session_t* session, const char* label, uint64_t generation_index, int force,
                          int* out_freed);

typedef struct {
    uint64_t versions_shredded;
    uint64_t manifests_freed;
    uint64_t manifests_kept_shared;
    uint64_t chunks_destroyed;
    uint64_t chunks_kept_shared;
} pfs_shred_report_t;

/*
 * Securely erases a label's whole history (has_generation 0) or one old
 * generation, overwriting content nothing else uses (see VaultSession::shred).
 * Refuses the current version, and "protected" unless force.
 */
int pfs_shred(pfs_session_t* session, const char* label, int has_generation, uint64_t generation_index,
              int force, pfs_shred_report_t* out_report);

typedef struct {
    uint64_t old_size;
    uint64_t new_size;
    uint64_t bytes_reclaimed;
    uint64_t live_chunks;
    uint64_t chunks_corrected;
    uint64_t orphaned_manifests_removed;
    uint64_t orphaned_tmp_files_removed;
    /* Mirror container compaction; all 0 when nothing mirrored died. */
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
/* Verify and repair. cb (may be NULL) gets each unrecoverable chunk's hex hash. */
int pfs_fsck(pfs_session_t* session, pfs_fsck_report_t* out_report, pfs_hash_callback cb, void* user_data);

int pfs_set_tag_bool(pfs_session_t* session, const char* label, const char* key, int value);
int pfs_set_tag_string(pfs_session_t* session, const char* label, const char* key, const char* value);
/* 1 if removed, 0 if the key wasn't set, -1 on error. */
int pfs_remove_tag(pfs_session_t* session, const char* label, const char* key);

typedef void (*pfs_tag_callback)(const char* key, int is_bool, int bool_value, const char* string_value,
                                  void* user_data);
int pfs_get_tags(pfs_session_t* session, const char* label, pfs_tag_callback cb, void* user_data);

/* Tags recorded on this generation (may differ from the current tip's). */
int pfs_get_node_tags_by_uuid(pfs_session_t* session, const char* uuid_hex,
                               pfs_tag_callback cb, void* user_data);

typedef void (*pfs_uuid_callback)(const char* uuid_hex, void* user_data);
/* Lateral parent uuids of this generation. Returns the count, or -1. */
int pfs_get_lateral_parents_by_uuid(pfs_session_t* session, const char* uuid_hex,
                                     pfs_uuid_callback cb, void* user_data);

/* Open branch heads of `label`. */
int pfs_get_heads(pfs_session_t* session, const char* label, pfs_generation_callback cb, void* user_data);

/*
 * Picks up changes other programs made to the vault (several programs may
 * have it open). Returns 1 if anything changed, 0 if not, -1 on error.
 */
int pfs_refresh(pfs_session_t* session);

/* 'spares all': 1 if every chunk gets a spare copy, 0 if only shared ones do. */
int pfs_get_mirror_all(pfs_session_t* session);

/* Turns 'spares all' on or off. *out_added (may be NULL): existing chunks that got a spare. */
int pfs_set_mirror_all(pfs_session_t* session, int enabled, uint64_t* out_added);

/*
 * Starts a new epoch with a fresh DEK; nothing is re-encrypted. Returns the
 * epoch_id, or UINT32_MAX on error (0 is a valid epoch).
 */
uint32_t pfs_rotate_key(pfs_session_t* session);

/*
 * Clade clustering (phylo.hpp). Every write attaches its fingerprint, so
 * only labels whose manifest can't be read are left out.
 */

typedef void (*pfs_text_callback)(const char* text, void* user_data);
/*
 * Renders the clade tree ("upgma" or "nj") through one cb call. Returns
 * the number of labels, or -1 (including fewer than 2 fingerprints).
 */
int pfs_build_tree(pfs_session_t* session, const char* algorithm, pfs_text_callback cb, void* user_data);

typedef void (*pfs_similar_callback)(const char* other_label, double jaccard_distance, void* user_data);
/* Every other fingerprinted label by Jaccard distance to `label`, closest first. */
int pfs_similar(pfs_session_t* session, const char* label, pfs_similar_callback cb, void* user_data);

/*
 * Calls cb with each member of `label`'s clade, in order. threshold <= 0
 * uses the default 0.80. If given, out_representative receives the
 * clade's smallest member (NUL-terminated, truncated to fit). Returns the
 * member count, or -1.
 */
int pfs_compute_clades(pfs_session_t* session, const char* label, double threshold,
                        pfs_text_callback cb, void* user_data,
                        char* out_representative, size_t out_buf_len);

typedef void (*pfs_label_count_callback)(const char* label, uint64_t chunk_count, void* user_data);
/*
 * Calls cb with each label whose fingerprint has fewer than
 * kMinReliableTraitCount chunks, and its count. Returns how many.
 */
int pfs_get_unreliable_fingerprint_labels(pfs_session_t* session, pfs_label_count_callback cb, void* user_data);

/*
 * Diagnostics for the 'attack' self-test: a block's content hash and a
 * chunk's location. out_hash32/out_content_hash32: 32 writable bytes.
 */
int pfs_debug_get_block_hash(pfs_session_t* session, const char* label, uint64_t block_index,
                              uint8_t* out_hash32);
int pfs_debug_lookup_chunk(pfs_session_t* session, const uint8_t* content_hash32,
                            uint64_t* out_offset, uint64_t* out_length, uint32_t* out_epoch_id);
/* A chunk's mirror location; -1 if it has none. */
int pfs_debug_get_mirror(pfs_session_t* session, const uint8_t* content_hash32,
                          uint64_t* out_offset, uint64_t* out_length);
/* Path of the primary data container (data_container.bin). */
int pfs_get_container_path(pfs_session_t* session, char* out_path, size_t out_buf_len);
/* Path of the mirror container (data_container_mirror.bin). */
int pfs_get_mirror_container_path(pfs_session_t* session, char* out_path, size_t out_buf_len);

typedef struct {
    uint64_t container_size;  /* bytes */
    uint64_t total_chunks;    /* chunks in the dedup index */
    uint64_t dead_chunks;     /* of those, ref_count == 0 */
    uint64_t total_refs;      /* sum of every chunk's ref_count -- dedup ratio is
                                * total_refs / total_chunks */
    uint64_t files_tracked;   /* labels in the catalog */
    uint32_t key_epochs;      /* current_epoch + 1 */
} pfs_vault_stats_t;

/* Vault statistics from a full dedup-index scan, the catalog and the keyring. */
int pfs_get_stats(pfs_session_t* session, pfs_vault_stats_t* out_stats);

const char* pfs_last_error(void);

#ifdef __cplusplus
}
#endif
