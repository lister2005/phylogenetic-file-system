// C++ port of pfs_fuse.py -- Component 3 of the port. Uses libfuse3's
// high-level path-based API (struct fuse_operations + fuse_main()),
// the closest match to fusepy's own high-level Operations class that
// pfs_fuse.py is built on, for a natural, direct port.
//
// Two-level clade presentation (see pfs_fuse.py's own _resolve()/
// _get_clades()/PORTFOLIO.md Sec 2.4): files with no near neighbor sit
// at the mount root; files that cluster (2+ members, Jaccard distance
// <= phylo.hpp's kDefaultCladeThreshold) appear grouped into a computed
// subdirectory named after the clade's lexicographically-smallest
// member. Built on phylo.hpp's compute_clades() (the C++ port of
// TreeConstructor.py's own clade partitioning), over every label's
// already-stored SIMILARITY_PROFILE fingerprint -- unlike Python, that
// fingerprint is attached SYNCHRONOUSLY at write time here (see
// pipeline.cpp), so there's no "still fingerprinting in the background"
// state to special-case: a file is either grouped as of its last write,
// or (fingerprint read failure aside) it isn't yet.
//
// Still out of scope for this pass: the daemonization lifecycle (fork/
// setsid/PID file/status/stop) pfs_fuse.py's CLI wraps around this --
// this binary runs in the foreground only, matching how Python's OWN
// Phase 2 milestone was first verified before daemonization was added.
//
// Passphrase-based vault unlocking: NOT done natively in C++ (scrypt
// KEK derivation isn't ported here -- see cpp_port_plan.txt's binding
// section for why that's deliberate). This binary still takes the KEK
// directly via the PFS_KEK_HEX environment variable; mount_pfs_cpp.py
// at the repo root is the real entry point for interactive use -- it
// prompts for the passphrase, derives the KEK via the EXISTING, already-
// tested gearhash.master_key_store.create_new_vault_key()/
// load_vault_key(), and execs this binary with PFS_KEK_HEX set.
#define FUSE_USE_VERSION 31
#include <fuse3/fuse.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "manifest.hpp"
#include "phylo.hpp"
#include "vault_session.hpp"

using namespace pfs_engine;

namespace {

struct FileHandle {
    std::string label;
    std::vector<uint8_t> buffer;
    bool dirty = false;
};

struct PfsFuseState {
    std::unique_ptr<VaultSession> session;
    std::string scratch_dir;
    std::mutex mutex;
    std::map<uint64_t, FileHandle> handles;
    uint64_t next_fh = 1;

    // Two-level clade presentation cache -- the C++ counterpart to
    // pfs_fuse.py's _clade_cache. has_clade_cache=false means "needs
    // recomputing"; invalidated on every write/delete/rename, since any
    // of those can change clade membership. Guarded by `mutex`, same as
    // catalog/handles -- every *_locked() helper below assumes the
    // caller already holds it (std::mutex isn't reentrant, unlike
    // Python's RLock, so callers must never lock twice).
    bool has_clade_cache = false;
    std::map<std::string, std::vector<std::string>> clade_to_labels;  // 2+ members only
    std::map<std::string, std::string> label_to_clade;                // member label -> clade name
};

PfsFuseState* state() {
    return static_cast<PfsFuseState*>(fuse_get_context()->private_data);
}

void invalidate_clade_cache_locked(PfsFuseState* st) { st->has_clade_cache = false; }

// Every label's stored SIMILARITY_PROFILE fingerprint, keyed by label.
// A manifest that fails to read is silently excluded (same as Python's
// own "stale"/unreadable exclusion) -- not fatal to the rest of the
// listing. Synchronous engine-wide: pipeline.cpp attaches this
// fingerprint at write time here, unlike Python's background thread, so
// (read failures aside) every write's fingerprint is already available
// by the time this runs.
std::map<std::string, TraitSet> gather_named_traits_locked(PfsFuseState* st) {
    std::map<std::string, TraitSet> named_traits;
    for (const auto& label : st->session->catalog.labels()) {
        auto manifest_filename = st->session->catalog.get(label);
        if (!manifest_filename) continue;
        std::string manifest_path = st->session->pipeline.storage_root() + "/" + *manifest_filename;
        try {
            Manifest m = read_manifest_file(manifest_path, *manifest_filename, st->session->pipeline.kek());
            if (m.metadata().similarity_fingerprint) {
                const auto& fp = *m.metadata().similarity_fingerprint;
                named_traits[label] = TraitSet(fp.begin(), fp.end());
            }
        } catch (const std::exception&) {
            // Excluded, not fatal -- matches Python's own behavior.
        }
    }
    return named_traits;
}

// Recomputes (if the cache is stale) the two-level clade partition.
// clade_to_labels only ever holds clades with 2+ members -- a "clade"
// of one is just a file at the root, not a directory, matching
// pfs_fuse.py's own choice (a mount where every single file gets its
// own one-entry folder would be technically accurate but genuinely
// annoying to browse).
void ensure_clades_locked(PfsFuseState* st) {
    if (st->has_clade_cache) return;

    std::map<std::string, TraitSet> named_traits = gather_named_traits_locked(st);
    std::map<std::string, std::vector<std::string>> groups;
    if (named_traits.size() >= 2) {
        groups = compute_clades(named_traits, kDefaultCladeThreshold);
    }

    st->clade_to_labels.clear();
    st->label_to_clade.clear();
    for (auto& kv : groups) {
        if (kv.second.size() < 2) continue;
        st->clade_to_labels[kv.first] = kv.second;
        for (const auto& member : kv.second) st->label_to_clade[member] = kv.first;
    }
    st->has_clade_cache = true;
}

enum class ResolveKind { kRoot, kCladeDir, kFile };

struct Resolved {
    ResolveKind kind;
    std::string name;  // clade name (kCladeDir) or label (kFile); empty for kRoot
};

// Path convention, matching pfs_fuse.py's _resolve() exactly:
//   "/"                  -> root
//   "/<name>"             -> a clade subdirectory, if <name> names a
//                            clade with 2+ members; otherwise a root-
//                            level file, if <name> is a label that's
//                            NOT currently in any clade (and either sits
//                            in the catalog or has an open handle)
//   "/<clade>/<label>"    -> a file, if <clade> is a real clade and
//                            <label> is one of ITS members
//   anything else (3+ components, or neither case above) -> unresolved
bool resolve_locked(PfsFuseState* st, const std::string& path, Resolved* out) {
    ensure_clades_locked(st);

    if (path == "/") {
        *out = Resolved{ResolveKind::kRoot, ""};
        return true;
    }
    if (path.empty() || path[0] != '/') return false;
    std::string rest = path.substr(1);
    if (rest.empty()) return false;

    size_t slash = rest.find('/');
    if (slash == std::string::npos) {
        auto clade_it = st->clade_to_labels.find(rest);
        if (clade_it != st->clade_to_labels.end()) {
            *out = Resolved{ResolveKind::kCladeDir, rest};
            return true;
        }
        bool in_clade = st->label_to_clade.count(rest) > 0;
        bool in_catalog = st->session->catalog.get(rest).has_value();
        bool has_open_handle = false;
        for (const auto& kv : st->handles) {
            if (kv.second.label == rest) { has_open_handle = true; break; }
        }
        if (!in_clade && (in_catalog || has_open_handle)) {
            *out = Resolved{ResolveKind::kFile, rest};
            return true;
        }
        return false;
    }

    if (rest.find('/', slash + 1) != std::string::npos) return false;  // no nesting past 2 components
    std::string clade_name = rest.substr(0, slash);
    std::string label = rest.substr(slash + 1);
    if (label.empty()) return false;
    auto clade_it = st->clade_to_labels.find(clade_name);
    if (clade_it == st->clade_to_labels.end()) return false;
    const auto& members = clade_it->second;
    if (std::find(members.begin(), members.end(), label) == members.end()) return false;
    *out = Resolved{ResolveKind::kFile, label};
    return true;
}

uint64_t new_handle(PfsFuseState* st, const std::string& label, std::vector<uint8_t> buffer, bool dirty) {
    std::lock_guard<std::mutex> lock(st->mutex);
    uint64_t fh = st->next_fh++;
    st->handles[fh] = FileHandle{label, std::move(buffer), dirty};
    return fh;
}

std::vector<uint8_t> reconstruct_bytes(PfsFuseState* st, const std::string& manifest_path) {
    std::string tmp_path = st->scratch_dir + "/read_XXXXXX";
    std::vector<char> tmp_template(tmp_path.begin(), tmp_path.end());
    tmp_template.push_back('\0');
    int fd = mkstemp(tmp_template.data());
    if (fd < 0) throw std::runtime_error("mkstemp failed");
    close(fd);
    std::string real_tmp_path(tmp_template.data());

    std::vector<uint8_t> data;
    try {
        st->session->pipeline.reconstruct(manifest_path, real_tmp_path);
        std::ifstream in(real_tmp_path, std::ios::binary);
        data.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    } catch (...) {
        remove(real_tmp_path.c_str());
        throw;
    }
    remove(real_tmp_path.c_str());
    return data;
}

void commit(PfsFuseState* st, const std::string& label, const std::vector<uint8_t>& data) {
    std::string tmp_path = st->scratch_dir + "/write_XXXXXX";
    std::vector<char> tmp_template(tmp_path.begin(), tmp_path.end());
    tmp_template.push_back('\0');
    int fd = mkstemp(tmp_template.data());
    if (fd < 0) throw std::runtime_error("mkstemp failed");
    std::string real_tmp_path(tmp_template.data());
    ssize_t written = write(fd, data.data(), data.size());
    close(fd);
    if (written < 0 || static_cast<size_t>(written) != data.size()) {
        remove(real_tmp_path.c_str());
        throw std::runtime_error("failed writing scratch file");
    }

    try {
        std::lock_guard<std::mutex> lock(st->mutex);
        st->session->commit_write(label, real_tmp_path);
        // Content (and therefore this label's similarity fingerprint)
        // just changed -- the cached clade partition may be stale.
        // Synchronous fingerprinting means the NEXT resolve/readdir
        // already sees the up-to-date grouping, unlike Python's
        // background-thread version which invalidates a second time
        // once its job finishes.
        invalidate_clade_cache_locked(st);
    } catch (...) {
        remove(real_tmp_path.c_str());
        throw;
    }
    remove(real_tmp_path.c_str());
}

// ---------- FUSE operation callbacks ----------

int pfs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info*) {
    memset(stbuf, 0, sizeof(struct stat));
    auto* st = state();
    std::string p(path);

    std::lock_guard<std::mutex> lock(st->mutex);
    Resolved r;
    if (!resolve_locked(st, p, &r)) return -ENOENT;

    if (r.kind == ResolveKind::kRoot || r.kind == ResolveKind::kCladeDir) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        stbuf->st_uid = getuid();
        stbuf->st_gid = getgid();
        // A directory entry left at the memset(0) default reads as the Unix
        // epoch (Jan 1 1970) to `ls -la` and every other stat consumer --
        // cosmetic but confusing (found during the new-user acceptance
        // pass). Root/clade dirs are synthesized (no backing manifest file
        // to take a real mtime from), so "now" is the honest answer.
        time_t now = time(nullptr);
        stbuf->st_mtime = now;
        stbuf->st_ctime = now;
        stbuf->st_atime = now;
        return 0;
    }

    const std::string& label = r.name;
    for (const auto& kv : st->handles) {
        if (kv.second.label == label) {
            stbuf->st_mode = S_IFREG | 0644;
            stbuf->st_nlink = 1;
            stbuf->st_size = static_cast<off_t>(kv.second.buffer.size());
            stbuf->st_uid = getuid();
            stbuf->st_gid = getgid();
            return 0;
        }
    }

    auto manifest_filename = st->session->catalog.get(label);
    if (!manifest_filename) return -ENOENT;
    std::string manifest_path = st->session->pipeline.storage_root() + "/" + *manifest_filename;
    Manifest m = read_manifest_file(manifest_path, *manifest_filename, st->session->pipeline.kek());

    struct stat manifest_stat{};
    stat(manifest_path.c_str(), &manifest_stat);

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = static_cast<off_t>(m.metadata().original_size);
    stbuf->st_uid = getuid();
    stbuf->st_gid = getgid();
    stbuf->st_mtime = manifest_stat.st_mtime;
    stbuf->st_ctime = manifest_stat.st_ctime;
    stbuf->st_atime = manifest_stat.st_atime;
    return 0;
}

int pfs_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t, struct fuse_file_info*,
                enum fuse_readdir_flags) {
    auto* st = state();
    std::string p(path);

    std::lock_guard<std::mutex> lock(st->mutex);
    Resolved r;
    if (!resolve_locked(st, p, &r)) return -ENOENT;

    filler(buf, ".", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    filler(buf, "..", nullptr, 0, static_cast<fuse_fill_dir_flags>(0));

    if (r.kind == ResolveKind::kCladeDir) {
        auto it = st->clade_to_labels.find(r.name);
        if (it != st->clade_to_labels.end()) {
            std::vector<std::string> members = it->second;
            std::sort(members.begin(), members.end());
            for (const auto& m : members) filler(buf, m.c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
        }
        return 0;
    }

    if (r.kind != ResolveKind::kRoot) return -ENOTDIR;

    // Matches pfs_fuse.py's readdir exactly: clade subdirectory names
    // (sorted) first, then root-level files (sorted) -- two separate
    // sorted groups, not one merged sort, so clade directories always
    // list before loose files.
    std::vector<std::string> clade_names;
    for (const auto& kv : st->clade_to_labels) clade_names.push_back(kv.first);
    std::sort(clade_names.begin(), clade_names.end());

    std::set<std::string> all_names;
    for (const auto& label : st->session->catalog.labels()) all_names.insert(label);
    for (const auto& kv : st->handles) all_names.insert(kv.second.label);
    std::vector<std::string> root_files;
    for (const auto& name : all_names) {
        if (st->label_to_clade.count(name) == 0) root_files.push_back(name);
    }
    std::sort(root_files.begin(), root_files.end());

    for (const auto& name : clade_names) filler(buf, name.c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    for (const auto& name : root_files) filler(buf, name.c_str(), nullptr, 0, static_cast<fuse_fill_dir_flags>(0));
    return 0;
}

int pfs_open(const char* path, struct fuse_file_info* fi) {
    auto* st = state();
    std::string p(path);
    std::string label;
    std::string manifest_path;
    {
        std::lock_guard<std::mutex> lock(st->mutex);
        Resolved r;
        if (!resolve_locked(st, p, &r) || r.kind != ResolveKind::kFile) return -ENOENT;
        label = r.name;
        auto manifest_filename = st->session->catalog.get(label);
        if (!manifest_filename) return -ENOENT;
        manifest_path = st->session->pipeline.storage_root() + "/" + *manifest_filename;
    }

    bool want_trunc = (fi->flags & O_TRUNC) != 0;
    std::vector<uint8_t> buffer;
    if (!want_trunc) {
        try {
            buffer = reconstruct_bytes(st, manifest_path);
        } catch (const std::exception&) {
            return -EIO;
        }
    }
    fi->fh = new_handle(st, label, std::move(buffer), want_trunc);
    return 0;
}

int pfs_create(const char* path, mode_t, struct fuse_file_info* fi) {
    std::string label;
    // Clade directories are computed, not a place to manually drop new
    // files into -- new files can only be created at the root; they'll
    // be filed into a clade automatically once commit_write() attaches
    // a fingerprint and it turns out something matches. resolve_locked()
    // itself would refuse this path anyway (the label doesn't exist yet
    // to resolve), so this checks the same single-component-only rule
    // directly instead. Matches pfs_fuse.py's create() exactly.
    std::string p(path);
    if (p.empty() || p[0] != '/') return -EACCES;
    std::string rest = p.substr(1);
    if (rest.empty() || rest.find('/') != std::string::npos) return -EACCES;
    label = rest;

    fi->fh = new_handle(state(), label, {}, true);
    return 0;
}

int pfs_read(const char*, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    auto* st = state();
    std::lock_guard<std::mutex> lock(st->mutex);
    auto it = st->handles.find(fi->fh);
    if (it == st->handles.end()) return -EBADF;
    const auto& data = it->second.buffer;
    if (static_cast<size_t>(offset) >= data.size()) return 0;
    size_t n = std::min(size, data.size() - static_cast<size_t>(offset));
    memcpy(buf, data.data() + offset, n);
    return static_cast<int>(n);
}

int pfs_write(const char*, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    auto* st = state();
    std::lock_guard<std::mutex> lock(st->mutex);
    auto it = st->handles.find(fi->fh);
    if (it == st->handles.end()) return -EBADF;
    auto& data = it->second.buffer;
    size_t end = static_cast<size_t>(offset) + size;
    if (data.size() < end) data.resize(end, 0);  // sparse-write gap, zero-filled
    memcpy(data.data() + offset, buf, size);
    it->second.dirty = true;
    return static_cast<int>(size);
}

int pfs_truncate(const char* path, off_t length, struct fuse_file_info* fi) {
    auto* st = state();
    if (fi != nullptr) {
        std::lock_guard<std::mutex> lock(st->mutex);
        auto it = st->handles.find(fi->fh);
        if (it != st->handles.end()) {
            it->second.buffer.resize(static_cast<size_t>(length), 0);
            it->second.dirty = true;
            return 0;
        }
    }

    std::string p(path);
    std::string label;
    std::string manifest_path;
    {
        std::lock_guard<std::mutex> lock(st->mutex);
        Resolved r;
        if (!resolve_locked(st, p, &r) || r.kind != ResolveKind::kFile) {
            return (length == 0) ? 0 : -ENOENT;
        }
        label = r.name;
        auto manifest_filename = st->session->catalog.get(label);
        if (!manifest_filename) return -ENOENT;
        manifest_path = st->session->pipeline.storage_root() + "/" + *manifest_filename;
    }
    try {
        std::vector<uint8_t> data = reconstruct_bytes(st, manifest_path);
        data.resize(static_cast<size_t>(length), 0);
        commit(st, label, data);
    } catch (const std::exception&) {
        return -EIO;
    }
    return 0;
}

int pfs_release(const char*, struct fuse_file_info* fi) {
    auto* st = state();
    FileHandle handle;
    {
        std::lock_guard<std::mutex> lock(st->mutex);
        auto it = st->handles.find(fi->fh);
        if (it == st->handles.end()) return 0;
        handle = std::move(it->second);
        st->handles.erase(it);
    }
    if (handle.dirty) {
        try {
            commit(st, handle.label, handle.buffer);
        } catch (const std::exception&) {
            return -EIO;
        }
    }
    return 0;
}

int pfs_unlink(const char* path) {
    auto* st = state();
    std::string p(path);
    std::lock_guard<std::mutex> lock(st->mutex);
    Resolved r;
    if (!resolve_locked(st, p, &r) || r.kind != ResolveKind::kFile) return -ENOENT;
    if (!st->session->catalog.get(r.name)) return -ENOENT;
    // delete_label(), not a raw pipeline.delete_file() call: a manifest
    // can be shared by more than one label (byte-identical content
    // dedups to the same manifest) or by this label's own older
    // generations -- only actually free it once nothing else needs it.
    st->session->delete_label(r.name);
    invalidate_clade_cache_locked(st);
    return 0;
}

int pfs_rename(const char* old_path, const char* new_path, unsigned int) {
    auto* st = state();
    std::string old_p(old_path);
    std::lock_guard<std::mutex> lock(st->mutex);
    Resolved r;
    if (!resolve_locked(st, old_p, &r) || r.kind != ResolveKind::kFile) return -ENOENT;
    std::string old_label = r.name;

    // A clade-dir prefix on the destination, if any, is ignored --
    // membership is computed, not chosen by which path you typed; only
    // the destination's basename (the new label) is meaningful. Matches
    // pfs_fuse.py's rename() exactly.
    std::string new_p(new_path);
    if (new_p.empty() || new_p[0] != '/') return -EINVAL;
    std::string rest = new_p.substr(1);
    if (rest.empty()) return -EINVAL;
    size_t last_slash = rest.find_last_of('/');
    std::string new_label = (last_slash == std::string::npos) ? rest : rest.substr(last_slash + 1);
    if (new_label.empty()) return -EINVAL;

    if (!st->session->catalog.get(old_label)) return -ENOENT;
    if (st->session->catalog.get(new_label) && new_label != old_label) {
        // POSIX rename silently replaces an existing destination -- go
        // through delete_label so a manifest shared with something else
        // doesn't get destroyed out from under it.
        st->session->delete_label(new_label);
    }
    auto manifest_filename = st->session->catalog.get(old_label);
    st->session->catalog.remove(old_label);
    st->session->catalog.set(new_label, *manifest_filename);
    st->session->lineage.rename_label(old_label, new_label);
    invalidate_clade_cache_locked(st);
    return 0;
}

void* pfs_init(struct fuse_conn_info*, struct fuse_config* cfg) {
    cfg->kernel_cache = 0;  // content can change from underneath (writes commit new generations); don't cache
    // A path's TYPE can change from underneath too, now that clade
    // presentation is real: "/clade_a.bin" is a plain file right up
    // until a second, similar-enough file lands, at which point the
    // SAME PATH becomes a directory (the clade subdirectory, named
    // after its lexicographically-smallest member). Without this, the
    // kernel's default 1-second entry/attribute cache can hand back a
    // stale REGULAR-FILE dentry for a path our driver has already
    // reclassified as a DIRECTORY -- the VFS then refuses the type
    // mismatch with EIO, which is exactly what a real mount test (two
    // similar files written back-to-back, then `ls`) hit before this
    // was added. Disabling all three caches forces every lookup fresh.
    cfg->entry_timeout = 0;
    cfg->attr_timeout = 0;
    cfg->negative_timeout = 0;
    return fuse_get_context()->private_data;
}

const struct fuse_operations kOperations = [] {
    struct fuse_operations ops{};
    ops.getattr = pfs_getattr;
    ops.readdir = pfs_readdir;
    ops.open = pfs_open;
    ops.create = pfs_create;
    ops.read = pfs_read;
    ops.write = pfs_write;
    ops.truncate = pfs_truncate;
    ops.release = pfs_release;
    ops.unlink = pfs_unlink;
    ops.rename = pfs_rename;
    ops.init = pfs_init;
    return ops;
}();

Bytes32 kek_from_env() {
    const char* hex = std::getenv("PFS_KEK_HEX");
    if (!hex || strlen(hex) != 64) {
        fprintf(stderr, "PFS_KEK_HEX must be set to a 64-hex-char (32-byte) key.\n");
        exit(1);
    }
    Bytes32 k{};
    for (int i = 0; i < 32; i++) k[i] = static_cast<uint8_t>(strtol(std::string(hex + i * 2, 2).c_str(), nullptr, 16));
    return k;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: PFS_KEK_HEX=<hex> %s <storage_root> <mountpoint> [fuse options...]\n", argv[0]);
        return 1;
    }
    std::string storage_root = argv[1];
    std::string mountpoint = argv[2];

    auto st = std::make_unique<PfsFuseState>();
    Bytes32 kek = kek_from_env();
    try {
        st->session = std::make_unique<VaultSession>(storage_root, kek);
    } catch (const std::exception& e) {
        // Covers both a genuinely wrong/corrupt key AND the vault
        // already being open elsewhere (VaultSession's first member is
        // a VaultLock -- see vault_lock.hpp -- which throws a clear
        // message if a DIFFERENT process already holds this vault's
        // lock). Print it plainly rather than letting it propagate to
        // an uncaught-exception abort/backtrace.
        fprintf(stderr, "Couldn't open vault '%s': %s\n", storage_root.c_str(), e.what());
        return 1;
    }
    st->scratch_dir = storage_root + "/.fuse_scratch_cpp";
    mkdir(st->scratch_dir.c_str(), 0700);

    std::vector<char*> fuse_argv;
    fuse_argv.push_back(argv[0]);
    fuse_argv.push_back(const_cast<char*>(mountpoint.c_str()));
    fuse_argv.push_back(const_cast<char*>("-f"));  // foreground -- this pass doesn't do Python's daemonization
    // Single-threaded, matching pfs_fuse.py's own explicit nothreads=True.
    // Several handlers (open/truncate, and now resolve_locked's clade
    // cache) release st->mutex between an initial catalog snapshot and a
    // later slow I/O step, then re-lock to act on it -- safe only if no
    // OTHER callback can run in between. libfuse3's default is a
    // multi-threaded dispatch pool; without -s, a concurrent callback
    // CAN interleave there (observed directly: a real mount test hit a
    // transient getattr EIO under concurrent cp invocations before this
    // flag was added). -s removes that whole race class instead of
    // trying to make every multi-step handler concurrency-safe piecemeal.
    fuse_argv.push_back(const_cast<char*>("-s"));
    for (int i = 3; i < argc; i++) fuse_argv.push_back(argv[i]);

    return fuse_main(static_cast<int>(fuse_argv.size()), fuse_argv.data(), &kOperations, st.get());
}
