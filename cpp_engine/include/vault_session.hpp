#pragma once
// A minimal port of vault_session.py's VaultSession -- the orchestration
// layer that ties StoragePipeline + LineageStore + Catalog together so
// no caller (the FUSE driver, eventually a CLI) has to remember all
// three itself. Deliberately NOT a full port of every VaultSession
// method (lateral_gene_transfer, prune_generation, rename, tags...) --
// scoped to exactly what a real, working FUSE mount needs to start
// (commit_write, delete_label, and read access to the three
// sub-components for getattr/read/readdir). Widening this to the rest
// of VaultSession's surface is future work, tracked in cpp_port_plan.txt,
// not silently out of scope.
#include <optional>
#include <string>
#include <vector>

#include "catalog.hpp"
#include "lineage_store.hpp"
#include "merge.hpp"
#include "pipeline.hpp"
#include "vault_lock.hpp"

namespace pfs_engine {

struct DeleteLabelResult {
    uint64_t manifests_freed = 0;
    uint64_t manifests_kept_shared = 0;
};

struct PruneResult {
    bool freed = false;
};

class VaultSession {
public:
    VaultSession(std::string storage_root, const Bytes32& kek);

    // Declared here (before every other member) so it is CONSTRUCTED
    // FIRST and DESTROYED LAST, matching pfs_open()/pfs_close()'s full
    // session lifetime: the OS-level advisory lock (vault_lock.hpp) is
    // held for the entire time pipeline/lineage/catalog exist, and
    // released the moment this VaultSession is destroyed (pfs_close(),
    // or a session going out of scope) -- enforcing the "one process at
    // a time" invariant manual.txt PART 6 already documented as
    // assumed-but-unenforced. See vault_lock.hpp's own docstring for
    // why a second VaultSession against the same vault WITHIN this same
    // process (e.g. the CLI's C++-engine 'attack' self-test) is still
    // allowed -- only a different OS process is refused.
    VaultLock lock_;

    // The one place a write should go through: persists the content,
    // records a real lineage generation (skipped only for a byte-
    // identical no-op resave of the label's CURRENT TIP, matching
    // vault_session.py's commit_write exactly -- a fork always records
    // a new generation even if its content happens to match something
    // else, since the fork itself is the meaningful event), and moves
    // the catalog pointer to the new manifest. Returns the manifest path.
    std::string commit_write(const std::string& label, const std::string& source_path,
                              const std::vector<std::string>& lateral_parent_labels = {},
                              std::optional<uint64_t> fork_from_generation = std::nullopt);

    // Full purge of a label's history (every generation, not just the
    // tip) plus its catalog entry -- "delete means delete". Refuses
    // (unless force) if the current tip is tagged "protected". A
    // manifest is only actually removed from disk (chunks' ref counts
    // decremented via pipeline.delete_file) once nothing else in the
    // vault -- another label's tip, another generation, this label's
    // OWN other generations -- still references it, matching
    // vault_session.py's manifest-reference-counted delete_label
    // exactly (the fix for the real 2026-07-23 bug: two labels sharing
    // byte-identical content share one manifest file by design, so
    // blindly deleting either one used to destroy the other).
    DeleteLabelResult delete_label(const std::string& label, bool force = false);

    // Reclaims ONE specific historical generation's storage while
    // keeping the label and every OTHER generation intact. Refuses to
    // prune the current tip (use delete_label for that), and refuses
    // (unless force) if THIS SPECIFIC generation is tagged
    // "protected" -- checks the generation being pruned, not the
    // current tip. Matches vault_session.py's prune_generation.
    PruneResult prune_generation(const std::string& label, uint64_t generation_index, bool force = false);

    // Lateral Gene Transfer: grafts two independent, already-published
    // labels into one new node descending from both. Reconstructs
    // both labels' current content, concatenates (label_a's bytes
    // first, then label_b's -- no format-aware splicing, matching
    // vault_session.py's own deliberately content-agnostic choice),
    // and commits the result under new_label with both current tips
    // recorded as parents. Refuses if either source is tagged
    // "no_graft_source". Like every other write, this goes through the
    // normal commit_write() path, so the grafted label DOES get a real
    // similarity fingerprint (extract_similarity_traits runs unconditionally
    // in StoragePipeline::secure_and_persist_file) and appears in clade-tree
    // views immediately -- verified directly via CppEngineAdapter in
    // tests/test_gui_cpp_engine.py (this comment used to say the opposite,
    // from back when PhylogeneticAnalyzer/traits extraction wasn't ported
    // to C++ yet; that porting happened since). Returns the new manifest path.
    std::string graft(const std::string& label_a, const std::string& label_b, const std::string& new_label);

    // Resolves two divergent branches of `label` back into one (see
    // merge.hpp for the actual algorithm). Thin wrapper around the
    // free function merge_branches() that ALSO moves the catalog
    // pointer to the merge result on success -- merge_branches() itself
    // only touches pipeline+lineage (it's cross-cutting over those two,
    // not catalog-aware), so this is the one place that has to remember
    // the catalog update, matching vault_session.py's merge_branches
    // exactly. Throws MutationConflictError (merge.hpp) on a genuine
    // conflict; commits nothing in that case.
    MergeResult merge(const std::string& label, uint64_t generation_a, uint64_t generation_b);

    // The one place either front end should call to vacuum: computes
    // the live-manifest set from THIS session's own catalog + lineage
    // (StoragePipeline can't see those on its own) and passes it to
    // pipeline.vacuum(), which folds ref-count repair + orphan sweep +
    // container compaction together. Matches vault_session.py's
    // vacuum() exactly.
    VacuumReport vacuum();

    // Ancestral Hardening's proactive half -- direct passthrough,
    // needs no catalog/lineage context of its own.
    FsckReport fsck() { return pipeline.verify_and_repair(); }

    StoragePipeline pipeline;
    LineageStore lineage;
    Catalog catalog;

private:
    // How many live references -- the catalog's current-tip entries
    // PLUS every lineage node across every label -- currently point at
    // this manifest filename. Shared authoritative source for
    // delete_label and prune_generation, matching vault_session.py's
    // _manifest_reference_count exactly.
    uint64_t manifest_reference_count(const std::string& manifest_filename) const;

    // Every manifest filename currently referenced anywhere in the
    // vault -- catalog tips plus every recorded generation across
    // every label. Matches vault_session.py's _live_manifest_filenames.
    std::vector<std::string> live_manifest_filenames() const;
};

}  // namespace pfs_engine
