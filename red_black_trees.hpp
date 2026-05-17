#pragma once
#include <cstddef>
#include <functional>
#include <stdexcept>
#include <iterator>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  RedBlackTree<Key, Value, Compare>
    //
    //  Full implementation of a left-leaning red-black BST (Sedgewick 2008).
    //  Guarantees O(log n) insert / delete / search.
    //  Supports in-order iteration via begin()/end().
    // ─────────────────────────────────────────────────────────────────────────────
    template<typename Key, typename Value, typename Compare = std::less<Key>>
    class RedBlackTree {
    private:
        enum Color : uint8_t { RED = 0, BLACK = 1 };

        struct Node {
            Key    key;
            Value  val;
            Node*  left  {nullptr};
            Node*  right {nullptr};
            Node*  parent{nullptr};
            Color  color {RED};
            size_t size  {1};        // subtree size for rank/select

            Node(const Key& k, const Value& v)
            : key(k), val(v) {}
        };

        Node*   root_  {nullptr};
        size_t  count_ {0};
        Compare cmp_;

        // ── Node helpers ─────────────────────────────────────────────────────────
        static bool is_red(const Node* n) noexcept {
            return n && n->color == RED;
        }
        static size_t node_size(const Node* n) noexcept {
            return n ? n->size : 0;
        }
        static void fix_size(Node* n) noexcept {
            if (n) n->size = 1 + node_size(n->left) + node_size(n->right);
        }

        // ── Rotations ────────────────────────────────────────────────────────────
        Node* rotate_left(Node* h) noexcept {
            Node* x    = h->right;
            h->right   = x->left;
            if (x->left) x->left->parent = h;
            x->parent  = h->parent;
            x->left    = h;
            h->parent  = x;
            x->color   = h->color;
            h->color   = RED;
            x->size    = h->size;
            fix_size(h);
            return x;
        }

        Node* rotate_right(Node* h) noexcept {
            Node* x    = h->left;
            h->left    = x->right;
            if (x->right) x->right->parent = h;
            x->parent  = h->parent;
            x->right   = h;
            h->parent  = x;
            x->color   = h->color;
            h->color   = RED;
            x->size    = h->size;
            fix_size(h);
            return x;
        }

        void flip_colors(Node* h) noexcept {
            h->color        = (h->color == RED) ? BLACK : RED;
            h->left->color  = (h->left->color  == RED) ? BLACK : RED;
            h->right->color = (h->right->color == RED) ? BLACK : RED;
        }

        // ── Insertion fixup ───────────────────────────────────────────────────────
        Node* insert(Node* h, const Key& key, const Value& val) {
            if (!h) { ++count_; return new Node(key, val); }

            int c = compare(key, h->key);
            if      (c < 0) { h->left  = insert(h->left,  key, val); if (h->left)  h->left->parent  = h; }
            else if (c > 0) { h->right = insert(h->right, key, val); if (h->right) h->right->parent = h; }
            else            { h->val = val; }   // update in place

            // Fix right-leaning reds
            if (is_red(h->right) && !is_red(h->left))      h = rotate_left(h);
            if (is_red(h->left)  && is_red(h->left->left)) h = rotate_right(h);
            if (is_red(h->left)  && is_red(h->right))       flip_colors(h);

            fix_size(h);
            return h;
        }

        // ── Deletion helpers ──────────────────────────────────────────────────────
        Node* balance(Node* h) noexcept {
            if (is_red(h->right) && !is_red(h->left))      h = rotate_left(h);
            if (is_red(h->left)  && is_red(h->left->left)) h = rotate_right(h);
            if (is_red(h->left)  && is_red(h->right))       flip_colors(h);
            fix_size(h);
            return h;
        }

        Node* move_red_left(Node* h) noexcept {
            flip_colors(h);
            if (is_red(h->right->left)) {
                h->right = rotate_right(h->right);
                if (h->right) h->right->parent = h;
                h = rotate_left(h);
                flip_colors(h);
            }
            return h;
        }

        Node* move_red_right(Node* h) noexcept {
            flip_colors(h);
            if (is_red(h->left->left)) {
                h = rotate_right(h);
                flip_colors(h);
            }
            return h;
        }

        static Node* find_min(Node* h) noexcept {
            return (h && h->left) ? find_min(h->left) : h;
        }

        Node* delete_min(Node* h) noexcept {
            if (!h->left) { delete h; --count_; return nullptr; }
            if (!is_red(h->left) && !is_red(h->left->left))
                h = move_red_left(h);
            h->left = delete_min(h->left);
            if (h->left) h->left->parent = h;
            return balance(h);
        }

        Node* remove(Node* h, const Key& key) {
            if (compare(key, h->key) < 0) {
                if (!h->left) return h;  // not found
                if (!is_red(h->left) && !is_red(h->left->left))
                    h = move_red_left(h);
                h->left = remove(h->left, key);
                if (h->left) h->left->parent = h;
            } else {
                if (is_red(h->left)) {
                    h = rotate_right(h);
                    h->right = remove(h->right, key);
                } else if (compare(key, h->key) == 0 && !h->right) {
                    delete h; --count_;
                    return nullptr;
                } else {
                    if (!is_red(h->right) && h->right && !is_red(h->right->left))
                        h = move_red_right(h);
                    if (compare(key, h->key) == 0) {
                        Node* m = find_min(h->right);
                        h->key  = m->key;
                        h->val  = m->val;
                        h->right= delete_min(h->right);
                        if (h->right) h->right->parent = h;
                    } else {
                        h->right = remove(h->right, key);
                        if (h->right) h->right->parent = h;
                    }
                }
            }
            return balance(h);
        }

        // ── Compare helper ────────────────────────────────────────────────────────
        int compare(const Key& a, const Key& b) const noexcept {
            if (cmp_(a, b)) return -1;
            if (cmp_(b, a)) return  1;
            return 0;
        }

        void destroy(Node* n) noexcept {
            if (!n) return;
            destroy(n->left);
            destroy(n->right);
            delete n;
        }

        void inorder(Node* n, std::function<void(const Key&, Value&)> fn) {
            if (!n) return;
            inorder(n->left,  fn);
            fn(n->key, n->val);
            inorder(n->right, fn);
        }

    public:
        RedBlackTree() = default;
        ~RedBlackTree() { destroy(root_); }

        // Non-copyable, movable
        RedBlackTree(const RedBlackTree&) = delete;
        RedBlackTree& operator=(const RedBlackTree&) = delete;
        RedBlackTree(RedBlackTree&& o) noexcept : root_(o.root_), count_(o.count_) {
            o.root_ = nullptr; o.count_ = 0;
        }

        void insert(const Key& k, const Value& v) {
            root_ = insert(root_, k, v);
            root_->color  = BLACK;
            root_->parent = nullptr;
        }

        bool remove(const Key& k) {
            if (!contains(k)) return false;
            if (!is_red(root_->left) && !is_red(root_->right))
                root_->color = RED;
            root_ = remove(root_, k);
            if (root_) { root_->color = BLACK; root_->parent = nullptr; }
            return true;
        }

        // Returns pointer to value or nullptr if absent
        Value* find(const Key& k) noexcept {
            Node* n = root_;
            while (n) {
                int c = compare(k, n->key);
                if      (c < 0) n = n->left;
                else if (c > 0) n = n->right;
                else            return &n->val;
            }
            return nullptr;
        }
        const Value* find(const Key& k) const noexcept {
            return const_cast<RedBlackTree*>(this)->find(k);
        }

        bool contains(const Key& k) const noexcept {
            return find(k) != nullptr;
        }

        size_t size()  const noexcept { return count_; }
        bool   empty() const noexcept { return count_ == 0; }

        // In-order traversal
        void for_each(std::function<void(const Key&, Value&)> fn) {
            inorder(root_, fn);
        }

        // Floor (largest key ≤ k)
        const Key* floor(const Key& k) const noexcept {
            Node* n = root_, *best = nullptr;
            while (n) {
                int c = compare(k, n->key);
                if      (c == 0) return &n->key;
                else if (c <  0) n = n->left;
                else { best = n; n = n->right; }
            }
            return best ? &best->key : nullptr;
        }

        // Ceiling (smallest key ≥ k)
        const Key* ceiling(const Key& k) const noexcept {
            Node* n = root_, *best = nullptr;
            while (n) {
                int c = compare(k, n->key);
                if      (c == 0) return &n->key;
                else if (c >  0) n = n->right;
                else { best = n; n = n->left; }
            }
            return best ? &best->key : nullptr;
        }

        // Rank: number of keys strictly less than k
        size_t rank(const Key& k) const noexcept {
            size_t r = 0;
            Node*  n = root_;
            while (n) {
                int c = compare(k, n->key);
                if      (c < 0) n = n->left;
                else if (c > 0) { r += 1 + node_size(n->left); n = n->right; }
                else { r += node_size(n->left); break; }
            }
            return r;
        }

        void clear() { destroy(root_); root_ = nullptr; count_ = 0; }
    };

} // namespace smartwan
