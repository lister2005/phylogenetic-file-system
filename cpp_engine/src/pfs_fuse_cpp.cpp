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
// member. The partition (compute_clades()'s, over every label's stored
// SIMILARITY_PROFILE fingerprint) is maintained incrementally by a
// background CladeWorker (clade_worker.hpp), never on the path of a
// filesystem call: lookups use its latest partition filtered against the
// live catalog, so a just-written file shows at the root until clustered.
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
#include <tuple>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "clade_worker.hpp"
#include "manifest.hpp"
#include "phylo.hpp"
#include "vault_session.hpp"

using namespace pfs_engine;

namespace {

// Streaming, memory bounded regardless of file size -- same model as
// pfs_fuse.py's READ/WRITE MODEL. A handle reads through a
// ManifestReader (only the chunks each read() touches are decrypted)
// until its first write/truncate, which copies that version into a
// scratch file on DISK; from then on reads and writes go to that file,
// and release() commits it through VaultSession::commit_write().
// Exactly one of reader / spill_fd is set at a time.
struct FileHandle {
    std::string label;
    std::unique_ptr<ManifestReader> reader;
    int spill_fd = -1;
    std::string spill_path;
    bool dirty = false;
};

// How much of a version one ManifestReader::read() pulls at a time when
// copying it into a scratch file (copy-on-first-write).
constexpr size_t kSpillCopyBytes = 1 << 20;

struct PfsFuseState {
    std::unique_ptr<VaultSession> session;
    std::string scratch_dir;
    std::mutex mutex;
    std::map<uint64_t, FileHandle> handles;
    uint64_t next_fh = 1;

    // Background clade clustering (clade_worker.hpp), started in
    // pfs_init(). Declared after `session` so it's destroyed (and its
    // thread joined) first.
    std::unique_ptr<CladeWorker> clades;
    // Filtered view of the worker's latest partition -- 2+ live members
    // only -- rebuilt when the partition or the catalog changes. Guarded
    // by `mutex`, same as catalog/handles -- every *_locked() helper
    // below assumes the caller already holds it (std::mutex isn't
    // reentrant, unlike Python's RLock, so callers must never lock twice).
    uint64_t catalog_epoch = 0;
    uint64_t view_version = UINT64_MAX;
    uint64_t view_epoch = UINT64_MAX;
    std::map<std::string, std::vector<std::string>> clade_to_labels;  // 2+ members only
    std::map<std::string, std::string> label_to_clade;                // member label -> clade name
};

PfsFuseState* state() {
    return static_cast<PfsFuseState*>(fuse_get_context()->private_data);
}

// Reports a catalog change to the clade worker. Caller holds st->mutex.
void label_changed_locked(PfsFuseState* st, const std::string& label) {
    st->catalog_epoch++;
    auto manifest_filename = st->session->catalog.get(label);
    if (manifest_filename && st->clades) st->clades->changed(label, *manifest_filename);
}

void label_removed_locked(PfsFuseState* st, const std::string& label) {
    st->catalog_epoch++;
    if (st->clades) st->clades->removed(label);
}

// Brings clade_to_labels/label_to_clade up to date with the worker's
// latest partition, never waiting for a recompute in progress. Filtered
// against the live catalog, so a label deleted or renamed since the
// partition was computed never appears; a new label sits at the root
// until the worker has clustered it. Only clades with 2+ members are
// directories -- a "clade" of one is just a file at the root, matching
// pfs_fuse.py.
void ensure_clades_locked(PfsFuseState* st) {
    if (!st->clades) return;
    auto partition = st->clades->snapshot();
    if (partition->version == st->view_version && st->catalog_epoch == st->view_epoch) return;
    auto view = filtered_clades(
        *partition, [st](const std::string& label) { return st->session->catalog.get(label).has_value(); }, 2);
    st->clade_to_labels = std::move(view.first);
    st->label_to_clade = std::move(view.second);
    st->view_version = partition->version;
    st->view_epoch = st->catalog_epoch;
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

uint64_t new_handle(PfsFuseState* st, FileHandle handle) {
    std::lock_guard<std::mutex> lock(st->mutex);
    uint64_t fh = st->next_fh++;
    st->handles.emplace(fh, std::move(handle));
    return fh;
}

// A new, empty scratch file: {fd, path}. Throws on failure.
std::pair<int, std::string> new_spill(PfsFuseState* st) {
    std::string tmp_path = st->scratch_dir + "/write_XXXXXX";
    std::vector<char> tmp_template(tmp_path.begin(), tmp_path.end());
    tmp_template.push_back('\0');
    int fd = mkstemp(tmp_template.data());
    if (fd < 0) throw std::runtime_error("mkstemp failed");
    return {fd, std::string(tmp_template.data())};
}

void copy_into(ManifestReader& reader, int fd) {
    std::vector<uint8_t> piece(kSpillCopyBytes);
    uint64_t position = 0;
    while (position < reader.size()) {
        size_t n = reader.read(position, piece.size(), piece.data());
        if (pwrite(fd, piece.data(), n, static_cast<off_t>(position)) != static_cast<ssize_t>(n)) {
            throw std::runtime_error("failed writing scratch file");
        }
        position += n;
    }
}

// Copy-on-first-write: moves a handle from streaming reads to its own
// scratch file, copying the version it opened chunk by chunk (never the
// whole file in memory). A no-op once done. Caller holds st->mutex.
void materialize_locked(PfsFuseState* st, FileHandle& handle) {
    if (handle.spill_fd >= 0) return;
    auto [fd, path] = new_spill(st);
    try {
        copy_into(*handle.reader, fd);
    } catch (...) {
        close(fd);
        remove(path.c_str());
        throw;
    }
    handle.reader.reset();
    handle.spill_fd = fd;
    handle.spill_path = path;
}

off_t handle_size(const FileHandle& handle) {
    if (handle.spill_fd >= 0) {
        struct stat sb{};
        return fstat(handle.spill_fd, &sb) == 0 ? sb.st_size : 0;
    }
    return static_cast<off_t>(handle.reader->size());
}

// The Speciation-on-Write event: hands a complete scratch file to
// commit_write(), the same path the CLI's 'write' uses. Takes ownership
// of scratch_path and removes it either way.
void commit(PfsFuseState* st, const std::string& label, const std::string& scratch_path) {
    try {
        std::lock_guard<std::mutex> lock(st->mutex);
        st->session->commit_write(label, scratch_path);
        // The fingerprint is attached synchronously by commit_write, so
        // the worker can cluster the new content right away.
        label_changed_locked(st, label);
    } catch (...) {
        remove(scratch_path.c_str());
        throw;
    }
    remove(scratch_path.c_str());
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
            stbuf->st_size = handle_size(kv.second);
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

    FileHandle handle;
    handle.label = label;
    try {
        if (fi->flags & O_TRUNC) {
            std::tie(handle.spill_fd, handle.spill_path) = new_spill(st);
            handle.dirty = true;
        } else {
            std::lock_guard<std::mutex> lock(st->mutex);
            handle.reader = std::make_unique<ManifestReader>(st->session->pipeline, manifest_path);
        }
    } catch (const std::exception&) {
        return -EIO;
    }
    fi->fh = new_handle(st, std::move(handle));
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

    FileHandle handle;
    handle.label = label;
    try {
        std::tie(handle.spill_fd, handle.spill_path) = new_spill(state());
    } catch (const std::exception&) {
        return -EIO;
    }
    handle.dirty = true;
    fi->fh = new_handle(state(), std::move(handle));
    return 0;
}

int pfs_read(const char*, char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    auto* st = state();
    std::lock_guard<std::mutex> lock(st->mutex);
    auto it = st->handles.find(fi->fh);
    if (it == st->handles.end()) return -EBADF;
    FileHandle& handle = it->second;
    if (handle.spill_fd >= 0) {
        ssize_t n = pread(handle.spill_fd, buf, size, offset);
        return n < 0 ? -errno : static_cast<int>(n);
    }
    try {
        return static_cast<int>(handle.reader->read(static_cast<uint64_t>(offset), size,
                                                    reinterpret_cast<uint8_t*>(buf)));
    } catch (const std::exception&) {
        return -EIO;
    }
}

int pfs_write(const char*, const char* buf, size_t size, off_t offset, struct fuse_file_info* fi) {
    auto* st = state();
    std::lock_guard<std::mutex> lock(st->mutex);
    auto it = st->handles.find(fi->fh);
    if (it == st->handles.end()) return -EBADF;
    FileHandle& handle = it->second;
    try {
        materialize_locked(st, handle);
    } catch (const std::exception&) {
        return -EIO;
    }
    // Writing past the end leaves a hole the OS reads back as zeros --
    // the same zero-filled sparse-write gap as before.
    ssize_t n = pwrite(handle.spill_fd, buf, size, offset);
    if (n < 0) return -errno;
    handle.dirty = true;
    return static_cast<int>(n);
}

int pfs_truncate(const char* path, off_t length, struct fuse_file_info* fi) {
    auto* st = state();
    if (fi != nullptr) {
        std::lock_guard<std::mutex> lock(st->mutex);
        auto it = st->handles.find(fi->fh);
        if (it != st->handles.end()) {
            try {
                materialize_locked(st, it->second);
            } catch (const std::exception&) {
                return -EIO;
            }
            if (ftruncate(it->second.spill_fd, length) != 0) return -errno;
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

        // A path truncate while the file is open applies to every open
        // handle on it; each commits the truncated content on release()
        // -- committing a separate truncated version here instead would
        // be silently overwritten by those handles' pre-truncate copies.
        // Same rule as pfs_fuse.py's truncate().
        bool any_open = false;
        for (auto& kv : st->handles) {
            if (kv.second.label != label) continue;
            any_open = true;
            try {
                materialize_locked(st, kv.second);
            } catch (const std::exception&) {
                return -EIO;
            }
            if (ftruncate(kv.second.spill_fd, length) != 0) return -errno;
            kv.second.dirty = true;
        }
        if (any_open) return 0;

        auto manifest_filename = st->session->catalog.get(label);
        if (!manifest_filename) return -ENOENT;
        manifest_path = st->session->pipeline.storage_root() + "/" + *manifest_filename;
    }
    // No open handle covers this path (truncate called standalone) --
    // copy into a scratch file, resize it, and commit now.
    try {
        std::unique_ptr<ManifestReader> reader;
        {
            std::lock_guard<std::mutex> lock(st->mutex);
            reader = std::make_unique<ManifestReader>(st->session->pipeline, manifest_path);
        }
        auto [fd, path] = new_spill(st);
        bool ok = true;
        try {
            copy_into(*reader, fd);
            ok = ftruncate(fd, length) == 0;
        } catch (...) {
            ok = false;
        }
        close(fd);
        if (!ok) {
            remove(path.c_str());
            return -EIO;
        }
        commit(st, label, path);
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
    handle.reader.reset();
    if (handle.spill_fd >= 0) {
        close(handle.spill_fd);
        if (!handle.dirty) {
            remove(handle.spill_path.c_str());
            return 0;
        }
        try {
            commit(st, handle.label, handle.spill_path);
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
    label_removed_locked(st, r.name);
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
    st->catalog_epoch++;
    if (st->clades) st->clades->renamed(old_label, new_label);
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

    auto* st = static_cast<PfsFuseState*>(fuse_get_context()->private_data);
    std::string root = st->session->pipeline.storage_root();
    Bytes32 kek = st->session->pipeline.kek();
    // Runs on the worker thread: reads and decrypts one manifest file,
    // named by the event, and nothing else (VaultSession isn't thread-safe).
    auto loader = [root, kek](const std::string&, const std::string& manifest_filename) -> std::optional<SortedTraits> {
        Manifest m = read_manifest_file(root + "/" + manifest_filename, manifest_filename, kek);
        if (!m.metadata().similarity_fingerprint) return std::nullopt;
        SortedTraits traits = *m.metadata().similarity_fingerprint;
        std::sort(traits.begin(), traits.end());
        traits.erase(std::unique(traits.begin(), traits.end()), traits.end());
        return traits;
    };
    std::vector<std::pair<std::string, std::string>> labels;
    {
        std::lock_guard<std::mutex> lock(st->mutex);
        for (const auto& label : st->session->catalog.labels()) {
            auto manifest_filename = st->session->catalog.get(label);
            if (manifest_filename) labels.push_back({label, *manifest_filename});
        }
    }
    st->clades = std::make_unique<CladeWorker>(loader);
    st->clades->start(labels);
    return st;
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
