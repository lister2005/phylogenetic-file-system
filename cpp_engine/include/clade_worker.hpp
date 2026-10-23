#pragma once
// Background, incremental clade clustering -- the C++ counterpart of
// clade_worker.py (see its docstring for the full rationale). Keeps the
// compute_clades() partition (connected components of "Jaccard distance
// <= threshold", keyed by smallest member, singletons included) up to
// date on its own thread: a change compares only the changed labels
// against everyone else (O(n), not O(n^2)), then re-runs union-find over
// the kept related-pairs edges and publishes a new immutable partition.
// Readers take snapshot() and never wait.
//
// The loader runs ONLY on the worker thread. Each changed() carries a
// caller-chosen `source` string (pfs_fuse_cpp passes the label's manifest
// filename, captured on its own thread) so the loader never has to touch
// state the caller mutates -- VaultSession isn't thread-safe.
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "phylo.hpp"

namespace pfs_engine {

struct CladePartition {
    // representative (smallest member) -> sorted members; every clade, singletons included
    std::map<std::string, std::vector<std::string>> clade_to_labels;
    uint64_t version = 0;  // 0 = nothing computed yet
};

// Sorted, duplicate-free trait hashes (a manifest's similarity_fingerprint).
using SortedTraits = std::vector<Bytes32>;

// Same Jaccard distance as jaccard_distance(), over sorted vectors.
double sorted_jaccard_distance(const SortedTraits& a, const SortedTraits& b);

// `partition` restricted to labels for which is_live() is true, re-keyed
// by each clade's smallest surviving member, keeping clades with at least
// min_members survivors. Lets a reader use a slightly stale partition: a
// label deleted or renamed since it was computed never shows up.
std::pair<std::map<std::string, std::vector<std::string>>, std::map<std::string, std::string>>
filtered_clades(const CladePartition& partition, const std::function<bool(const std::string&)>& is_live,
                size_t min_members);

class CladeWorker {
public:
    // Returns the label's traits, or nullopt if it has no fingerprint.
    using Loader = std::function<std::optional<SortedTraits>(const std::string& label, const std::string& source)>;

    explicit CladeWorker(Loader loader, double threshold = kDefaultCladeThreshold);
    ~CladeWorker();  // stop()s
    CladeWorker(const CladeWorker&) = delete;
    CladeWorker& operator=(const CladeWorker&) = delete;

    // Queues every (label, source) and starts the thread.
    void start(const std::vector<std::pair<std::string, std::string>>& labels);
    void changed(const std::string& label, const std::string& source);
    void removed(const std::string& label);
    void renamed(const std::string& old_label, const std::string& new_label);

    std::shared_ptr<const CladePartition> snapshot() const;
    // True once every change posted so far is in snapshot().
    bool wait_idle(std::chrono::milliseconds timeout);
    void stop();

    uint64_t distance_calls() const { return distance_calls_; }  // for tests

private:
    struct Event {
        enum Kind { kChanged, kRemoved, kRenamed } kind;
        std::string a;  // label (changed/removed) or old label (renamed)
        std::string b;  // source (changed) or new label (renamed)
    };

    void run();
    void process(const std::vector<Event>& events);
    void drop(const std::string& label);
    void maybe_link(const std::string& a, const SortedTraits& ta, const std::string& b, const SortedTraits& tb);
    void publish();

    Loader loader_;
    double threshold_;

    mutable std::mutex mutex_;
    std::condition_variable cond_;
    std::vector<Event> events_;  // guarded by mutex_
    bool busy_ = false;          // guarded by mutex_
    bool stopping_ = false;      // guarded by mutex_
    std::shared_ptr<const CladePartition> snapshot_;  // guarded by mutex_
    std::thread thread_;

    // Worker-thread-only state.
    std::map<std::string, SortedTraits> traits_;
    std::map<std::string, std::set<std::string>> neighbors_;
    uint64_t distance_calls_ = 0;
};

}  // namespace pfs_engine
