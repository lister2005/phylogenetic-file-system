#include "clade_worker.hpp"

#include <algorithm>
#include <cstdio>
#include <exception>

namespace pfs_engine {

double sorted_jaccard_distance(const SortedTraits& a, const SortedTraits& b) {
    size_t i = 0, j = 0, common = 0;
    while (i < a.size() && j < b.size()) {
        if (a[i] < b[j]) {
            i++;
        } else if (b[j] < a[i]) {
            j++;
        } else {
            common++;
            i++;
            j++;
        }
    }
    size_t union_size = a.size() + b.size() - common;
    if (union_size == 0) return 1.0;
    return 1.0 - static_cast<double>(common) / static_cast<double>(union_size);
}

std::pair<std::map<std::string, std::vector<std::string>>, std::map<std::string, std::string>>
filtered_clades(const CladePartition& partition, const std::function<bool(const std::string&)>& is_live,
                size_t min_members) {
    std::map<std::string, std::vector<std::string>> clade_to_labels;
    std::map<std::string, std::string> label_to_clade;
    for (const auto& kv : partition.clade_to_labels) {
        std::vector<std::string> surviving;
        for (const auto& member : kv.second) {
            if (is_live(member)) surviving.push_back(member);
        }
        if (surviving.size() < min_members || surviving.empty()) continue;
        const std::string name = surviving.front();  // members are sorted
        for (const auto& member : surviving) label_to_clade[member] = name;
        clade_to_labels[name] = std::move(surviving);
    }
    return {std::move(clade_to_labels), std::move(label_to_clade)};
}

CladeWorker::CladeWorker(Loader loader, double threshold)
    : loader_(std::move(loader)), threshold_(threshold), snapshot_(std::make_shared<CladePartition>()) {}

CladeWorker::~CladeWorker() { stop(); }

void CladeWorker::start(const std::vector<std::pair<std::string, std::string>>& labels) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& kv : labels) events_.push_back({Event::kChanged, kv.first, kv.second});
    }
    thread_ = std::thread([this] { run(); });
}

void CladeWorker::changed(const std::string& label, const std::string& source) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back({Event::kChanged, label, source});
    cond_.notify_all();
}

void CladeWorker::removed(const std::string& label) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back({Event::kRemoved, label, ""});
    cond_.notify_all();
}

void CladeWorker::renamed(const std::string& old_label, const std::string& new_label) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back({Event::kRenamed, old_label, new_label});
    cond_.notify_all();
}

std::shared_ptr<const CladePartition> CladeWorker::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return snapshot_;
}

bool CladeWorker::wait_idle(std::chrono::milliseconds timeout) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cond_.wait_for(lock, timeout, [this] { return events_.empty() && !busy_; });
}

void CladeWorker::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
        cond_.notify_all();
    }
    if (thread_.joinable()) thread_.join();
}

void CladeWorker::run() {
    for (;;) {
        std::vector<Event> events;
        {
            std::unique_lock<std::mutex> lock(mutex_);
            cond_.wait(lock, [this] { return !events_.empty() || stopping_; });
            if (stopping_) return;
            events.swap(events_);
            busy_ = true;
        }
        try {
            process(events);
        } catch (const std::exception& e) {  // never let the thread die
            fprintf(stderr, "[clade-worker] clustering pass failed: %s\n", e.what());
        }
        std::lock_guard<std::mutex> lock(mutex_);
        busy_ = !events_.empty();
        cond_.notify_all();
    }
}

void CladeWorker::drop(const std::string& label) {
    traits_.erase(label);
    auto it = neighbors_.find(label);
    if (it == neighbors_.end()) return;
    for (const auto& other : it->second) neighbors_[other].erase(label);
    neighbors_.erase(it);
}

void CladeWorker::maybe_link(const std::string& a, const SortedTraits& ta, const std::string& b,
                             const SortedTraits& tb) {
    distance_calls_++;
    if (sorted_jaccard_distance(ta, tb) <= threshold_) {
        neighbors_[a].insert(b);
        neighbors_[b].insert(a);
    }
}

void CladeWorker::process(const std::vector<Event>& events) {
    std::map<std::string, std::string> dirty;  // label -> source
    for (const auto& ev : events) {
        switch (ev.kind) {
            case Event::kChanged:
                dirty[ev.a] = ev.b;
                break;
            case Event::kRemoved:
                drop(ev.a);
                dirty.erase(ev.a);
                break;
            case Event::kRenamed: {
                const std::string& old_label = ev.a;
                const std::string& new_label = ev.b;
                if (old_label == new_label) break;
                drop(new_label);  // a rename over an existing label replaces it
                dirty.erase(new_label);
                auto t = traits_.find(old_label);
                if (t != traits_.end()) {
                    traits_[new_label] = std::move(t->second);
                    traits_.erase(old_label);
                    std::set<std::string> neighbors = std::move(neighbors_[old_label]);
                    neighbors_.erase(old_label);
                    for (const auto& other : neighbors) {
                        neighbors_[other].erase(old_label);
                        neighbors_[other].insert(new_label);
                    }
                    neighbors_[new_label] = std::move(neighbors);
                }
                auto d = dirty.find(old_label);
                if (d != dirty.end()) {
                    dirty[new_label] = d->second;
                    dirty.erase(old_label);
                }
                break;
            }
        }
    }

    std::map<std::string, SortedTraits> loaded;
    for (const auto& kv : dirty) {
        drop(kv.first);
        std::optional<SortedTraits> traits;
        try {
            traits = loader_(kv.first, kv.second);
        } catch (const std::exception& e) {
            fprintf(stderr, "[clade-worker] loading '%s' failed: %s\n", kv.first.c_str(), e.what());
        }
        if (traits) loaded[kv.first] = std::move(*traits);
    }

    // Every unordered pair involving a newly loaded label, exactly once.
    for (auto a = loaded.begin(); a != loaded.end(); ++a) {
        for (const auto& existing : traits_) maybe_link(a->first, a->second, existing.first, existing.second);
        for (auto b = std::next(a); b != loaded.end(); ++b) maybe_link(a->first, a->second, b->first, b->second);
    }
    for (auto& kv : loaded) {
        neighbors_[kv.first];  // ensure an entry, even with no neighbors
        traits_[kv.first] = std::move(kv.second);
    }

    publish();
}

void CladeWorker::publish() {
    std::map<std::string, std::string> parent;
    for (const auto& kv : traits_) parent[kv.first] = kv.first;
    std::function<std::string(const std::string&)> find = [&](const std::string& x) {
        std::string root = x;
        while (parent[root] != root) root = parent[root];
        std::string cur = x;
        while (parent[cur] != root) {
            std::string next = parent[cur];
            parent[cur] = root;
            cur = next;
        }
        return root;
    };
    for (const auto& kv : neighbors_) {
        if (!parent.count(kv.first)) continue;
        for (const auto& other : kv.second) {
            if (!parent.count(other)) continue;
            std::string ra = find(kv.first), rb = find(other);
            if (ra != rb) parent[ra] = rb;
        }
    }

    auto partition = std::make_shared<CladePartition>();
    std::map<std::string, std::vector<std::string>> groups;
    for (const auto& kv : traits_) groups[find(kv.first)].push_back(kv.first);
    for (auto& kv : groups) {
        std::sort(kv.second.begin(), kv.second.end());
        partition->clade_to_labels[kv.second.front()] = std::move(kv.second);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    partition->version = snapshot_->version + 1;
    snapshot_ = std::move(partition);
}

}  // namespace pfs_engine
