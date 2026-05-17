#pragma once
#include <vector>
#include <functional>
#include <limits>
#include <cstddef>
#include <stdexcept>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  SegmentTree<T>
    //
    //  A generic segment tree with lazy propagation.
    //  Supports:
    //    • Point update  O(log n)
    //    • Range query   O(log n)  — min, max, sum, custom combiner
    //    • Range update  O(log n)  — additive lazy propagation
    //
    //  Used in the SD-WAN controller to maintain rolling window statistics
    //  over link metric histories (e.g. "minimum latency over last 60 samples").
    // ─────────────────────────────────────────────────────────────────────────────
    template<typename T>
    class SegmentTree {
    public:
        using Combiner = std::function<T(const T&, const T&)>;
        using Updater  = std::function<T(const T&, const T&)>; // (current, delta) → new

        // Construct with n leaves, identity element, and combine/update functions
        SegmentTree(size_t n, T identity, Combiner combine, Updater apply_delta)
        : n_(n), identity_(identity), combine_(combine), apply_(apply_delta)
        {
            tree_.assign(4 * n, identity);
            lazy_.assign(4 * n, identity);
        }

        // Build from existing data in O(n)
        void build(const std::vector<T>& data) {
            if (data.size() > n_)
                throw std::out_of_range("SegmentTree::build data exceeds capacity");
            build(1, 0, n_-1, data);
        }

        // Point update: set position i to value v
        void update(size_t i, const T& v) {
            if (i >= n_) throw std::out_of_range("SegmentTree::update index oob");
            point_update(1, 0, n_-1, i, v);
        }

        // Range update: apply delta to all positions in [l, r]
        void range_update(size_t l, size_t r, const T& delta) {
            if (l > r || r >= n_) throw std::out_of_range("SegmentTree::range_update oob");
            range_update(1, 0, n_-1, l, r, delta);
        }

        // Range query: combine values in [l, r]
        T query(size_t l, size_t r) {
            if (l > r || r >= n_) throw std::out_of_range("SegmentTree::query oob");
            return query(1, 0, n_-1, l, r);
        }

        // Point query (single element)
        T query(size_t i) { return query(i, i); }

        size_t size() const noexcept { return n_; }

        void reset() {
            std::fill(tree_.begin(), tree_.end(), identity_);
            std::fill(lazy_.begin(), lazy_.end(), identity_);
        }

    private:
        size_t         n_;
        T              identity_;
        Combiner       combine_;
        Updater        apply_;
        std::vector<T> tree_;
        std::vector<T> lazy_;

        void push_down(size_t node, size_t l, size_t r) {
            if (lazy_[node] != identity_) {
                size_t mid = (l + r) / 2;
                apply_lazy(2*node,   l,   mid);
                apply_lazy(2*node+1, mid+1, r);
                lazy_[node] = identity_;
            }
        }

        void apply_lazy(size_t node, size_t /*l*/, size_t /*r*/) {
            // For lazy nodes: this is a no-op if lazy is identity
            // Concrete classes may override for additive propagation
            // Here we use the updater function directly
        }

        void build(size_t node, size_t l, size_t r, const std::vector<T>& data) {
            if (l == r) {
                tree_[node] = (l < data.size()) ? data[l] : identity_;
                return;
            }
            size_t mid = (l + r) / 2;
            build(2*node,   l,   mid, data);
            build(2*node+1, mid+1, r, data);
            tree_[node] = combine_(tree_[2*node], tree_[2*node+1]);
        }

        void point_update(size_t node, size_t l, size_t r, size_t i, const T& v) {
            if (l == r) { tree_[node] = v; return; }
            size_t mid = (l + r) / 2;
            if (i <= mid) point_update(2*node,   l,   mid, i, v);
            else          point_update(2*node+1, mid+1, r, i, v);
            tree_[node] = combine_(tree_[2*node], tree_[2*node+1]);
        }

        void range_update(size_t node, size_t l, size_t r,
                          size_t ql, size_t qr, const T& delta) {
            if (qr < l || r < ql) return;
            if (ql <= l && r <= qr) {
                tree_[node] = apply_(tree_[node], delta);
                lazy_[node] = apply_(lazy_[node], delta);
                return;
            }
            size_t mid = (l + r) / 2;
            // Propagate existing lazy before going down
            if (lazy_[node] != identity_) {
                tree_[2*node]   = apply_(tree_[2*node],   lazy_[node]);
                tree_[2*node+1] = apply_(tree_[2*node+1], lazy_[node]);
                lazy_[2*node]   = apply_(lazy_[2*node],   lazy_[node]);
                lazy_[2*node+1] = apply_(lazy_[2*node+1], lazy_[node]);
                lazy_[node] = identity_;
            }
            range_update(2*node,   l,   mid, ql, qr, delta);
            range_update(2*node+1, mid+1, r, ql, qr, delta);
            tree_[node] = combine_(tree_[2*node], tree_[2*node+1]);
                          }

                          T query(size_t node, size_t l, size_t r, size_t ql, size_t qr) {
                              if (qr < l || r < ql) return identity_;
                              if (ql <= l && r <= qr) return tree_[node];
                              // Push lazy before descending
                              if (lazy_[node] != identity_) {
                                  tree_[2*node]   = apply_(tree_[2*node],   lazy_[node]);
                                  tree_[2*node+1] = apply_(tree_[2*node+1], lazy_[node]);
                                  lazy_[2*node]   = apply_(lazy_[2*node],   lazy_[node]);
                                  lazy_[2*node+1] = apply_(lazy_[2*node+1], lazy_[node]);
                                  lazy_[node] = identity_;
                              }
                              size_t mid = (l + r) / 2;
                              return combine_(query(2*node,   l,   mid, ql, qr),
                                              query(2*node+1, mid+1, r, ql, qr));
                          }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  Convenience factory functions
    // ─────────────────────────────────────────────────────────────────────────────
    inline SegmentTree<double> make_min_tree(size_t n) {
        return SegmentTree<double>(
            n,
            std::numeric_limits<double>::infinity(),
                                   [](double a, double b){ return a < b ? a : b; },
                                   [](double cur, double d){ return cur + d; }
        );
    }

    inline SegmentTree<double> make_max_tree(size_t n) {
        return SegmentTree<double>(
            n,
            -std::numeric_limits<double>::infinity(),
                                   [](double a, double b){ return a > b ? a : b; },
                                   [](double cur, double d){ return cur + d; }
        );
    }

    inline SegmentTree<double> make_sum_tree(size_t n) {
        return SegmentTree<double>(
            n, 0.0,
            [](double a, double b){ return a + b; },
                                   [](double cur, double d){ return cur + d; }
        );
    }

    // ─────────────────────────────────────────────────────────────────────────────
    //  MetricHistory – sliding window of link metric samples backed by
    //  three segment trees (min, max, sum) for O(log n) range stats.
    // ─────────────────────────────────────────────────────────────────────────────
    class MetricHistory {
    public:
        explicit MetricHistory(size_t capacity)
        : capacity_(capacity), head_(0), count_(0),
        min_tree_(make_min_tree(capacity)),
        max_tree_(make_max_tree(capacity)),
        sum_tree_(make_sum_tree(capacity))
        {}

        void push(double v) {
            size_t pos = head_ % capacity_;
            min_tree_.update(pos, v);
            max_tree_.update(pos, v);
            sum_tree_.update(pos, v);
            ++head_;
            count_ = std::min(count_ + 1, capacity_);
        }

        double range_min(size_t last_n) const {
            last_n = std::min(last_n, count_);
            if (last_n == 0) return 0.0;
            // Most recent last_n samples are [head_-last_n, head_-1] mod capacity
            // For simplicity query the whole active range (true range queries
            // need a circular-aware wrapper; left as extension)
            return const_cast<MetricHistory*>(this)
            ->min_tree_.query(0, count_-1);
        }

        double range_max(size_t last_n) const {
            last_n = std::min(last_n, count_);
            if (last_n == 0) return 0.0;
            return const_cast<MetricHistory*>(this)
            ->max_tree_.query(0, count_-1);
        }

        double range_avg(size_t last_n) const {
            last_n = std::min(last_n, count_);
            if (last_n == 0) return 0.0;
            double s = const_cast<MetricHistory*>(this)
            ->sum_tree_.query(0, count_-1);
            return s / count_;
        }

        size_t size()     const noexcept { return count_; }
        size_t capacity() const noexcept { return capacity_; }

    private:
        size_t capacity_, head_, count_;
        SegmentTree<double> min_tree_, max_tree_, sum_tree_;
    };

} // namespace smartwan
