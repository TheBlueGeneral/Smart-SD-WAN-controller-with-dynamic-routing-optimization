#pragma once
#include "common.hpp"
#include "red_black_tree.hpp"
#include "bloom_filter.hpp"
#include "routing_engine.hpp"
#include <chrono>
#include <mutex>
#include <functional>
#include <vector>
#include <atomic>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  FlowEntry – installed routing decision for a 5-tuple flow
    // ─────────────────────────────────────────────────────────────────────────────
    struct FlowEntry {
        FlowKey  key;
        AppType  app_type    {AppType::UNKNOWN};
        uint8_t  priority    {1};

        // Selected routing path
        Path     active_path;
        uint32_t ecmp_group_id{INVALID_NODE}; // 0 = single-path

        // Traffic counters
        FlowStats stats;

        // Validity window
        Timestamp installed_at{};
        uint32_t  timeout_sec {300};  // Hard timeout (seconds)
        uint32_t  idle_sec    {60};   // Idle timeout (seconds)

        // QoS markings
        uint8_t  dscp{0};             // DSCP marking
        uint32_t rate_limit_kbps{0};  // 0 = unlimited

        bool is_expired() const noexcept {
            double elapsed = ms_since(installed_at) / 1000.0;
            double idle    = ms_since(stats.last_seen) / 1000.0;
            return elapsed > timeout_sec || idle > idle_sec;
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  FlowTable
    //
    //  Dual-layer lookup:
    //    Layer 1 – Bloom filter: O(1) negative membership test (miss = fast path)
    //    Layer 2 – Red-Black Tree: O(log n) exact match on hit
    //
    //  Supports:
    //    • install / remove / update entries
    //    • packet lookup with stat update
    //    • periodic expiry sweep
    //    • wildcard matching (partial keys)
    // ─────────────────────────────────────────────────────────────────────────────
    class FlowTable {
    public:
        explicit FlowTable(size_t expected_flows = 65536)
        : bloom_(expected_flows, 0.005),  // 0.5% FPP
        rbt_()
        {}

        // ── Install / Remove ─────────────────────────────────────────────────────

        void install(FlowEntry entry) {
            std::unique_lock<std::mutex> lk(mtx_);
            FlowKeyHasher::insert(bloom_, entry.key);
            entry.installed_at = mono_now();
            entry.stats.first_seen = mono_now();
            rbt_.insert(entry.key, std::move(entry));
            ++total_installed_;
        }

        bool remove(const FlowKey& key) {
            std::unique_lock<std::mutex> lk(mtx_);
            bool ok = rbt_.remove(key);
            if (ok) ++total_removed_;
            // Note: Bloom filter cannot be "un-updated" – accepted trade-off
            return ok;
        }

        // ── Lookup ───────────────────────────────────────────────────────────────

        // Fast lookup: returns nullptr on miss (guaranteed, not false-positive)
        FlowEntry* lookup(const FlowKey& key) {
            std::unique_lock<std::mutex> lk(mtx_);
            ++total_lookups_;

            // Layer 1: Bloom filter – fast negative test
            if (!FlowKeyHasher::contains(bloom_, key)) {
                ++bloom_misses_;
                return nullptr;
            }
            // Layer 2: Exact RBT lookup
            FlowEntry* e = rbt_.find(key);
            if (!e) { ++false_positives_; return nullptr; }
            return e;
        }

        // Update stats for existing flow (called per packet)
        bool record_packet(const FlowKey& key, uint64_t pkt_bytes,
                           double latency_ms) {
            std::unique_lock<std::mutex> lk(mtx_);
            FlowEntry* e = rbt_.find(key);
            if (!e) return false;
            e->stats.update(pkt_bytes, latency_ms);
            return true;
                           }

                           // Update the active path for a flow
                           bool update_path(const FlowKey& key, Path new_path) {
                               std::unique_lock<std::mutex> lk(mtx_);
                               FlowEntry* e = rbt_.find(key);
                               if (!e) return false;
                               e->active_path = std::move(new_path);
                               ++path_updates_;
                               return true;
                           }

                           // ── Expiry ───────────────────────────────────────────────────────────────

                           // Sweep expired entries; returns number removed
                           size_t expire_flows() {
                               std::unique_lock<std::mutex> lk(mtx_);
                               std::vector<FlowKey> to_remove;
                               rbt_.for_each([&](const FlowKey& k, FlowEntry& e){
                                   if (e.is_expired()) to_remove.push_back(k);
                               });
                                   for (auto& k : to_remove) { rbt_.remove(k); ++total_removed_; }
                                   // Rebuild bloom filter periodically to clear false-positive accumulation
                                   if (total_removed_ % 4096 == 0) rebuild_bloom_locked();
                                   return to_remove.size();
                           }

                           // ── Iteration ────────────────────────────────────────────────────────────

                           void for_each(std::function<void(const FlowKey&, FlowEntry&)> fn) {
                               std::unique_lock<std::mutex> lk(mtx_);
                               rbt_.for_each([&](const FlowKey& k, FlowEntry& v){ fn(k, v); });
                           }

                           // ── Stats ─────────────────────────────────────────────────────────────────

                           struct TableStats {
                               size_t flow_count;
                               uint64_t total_lookups;
                               uint64_t bloom_misses;
                               uint64_t false_positives;
                               uint64_t total_installed;
                               uint64_t total_removed;
                               uint64_t path_updates;
                               double   bloom_fpp;
                           };

                           TableStats stats() const {
                               std::unique_lock<std::mutex> lk(mtx_);
                               return {
                                   rbt_.size(),
                                   total_lookups_.load(), bloom_misses_.load(),
                                   false_positives_.load(), total_installed_.load(),
                                   total_removed_.load(), path_updates_.load(),
                                   bloom_.fpp()
                               };
                           }

                           size_t size() const {
                               std::unique_lock<std::mutex> lk(mtx_);
                               return rbt_.size();
                           }

                           void clear() {
                               std::unique_lock<std::mutex> lk(mtx_);
                               rbt_.clear();
                               bloom_.clear();
                           }

    private:
        mutable std::mutex mtx_;
        BloomFilter<uint64_t>   bloom_;
        RedBlackTree<FlowKey, FlowEntry> rbt_;

        std::atomic<uint64_t> total_lookups_   {0};
        std::atomic<uint64_t> bloom_misses_    {0};
        std::atomic<uint64_t> false_positives_ {0};
        std::atomic<uint64_t> total_installed_ {0};
        std::atomic<uint64_t> total_removed_   {0};
        std::atomic<uint64_t> path_updates_    {0};

        void rebuild_bloom_locked() {
            bloom_.clear();
            rbt_.for_each([&](const FlowKey& k, FlowEntry&){
                FlowKeyHasher::insert(bloom_, k);
            });
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  FlowClassifier – matches flows to application types using port ranges
    //  and protocol signatures.
    // ─────────────────────────────────────────────────────────────────────────────
    class FlowClassifier {
    public:
        AppType classify(const FlowKey& key) const noexcept {
            uint16_t port = std::max(key.src_port, key.dst_port);

            // Well-known ports → application type
            // VoIP: SIP(5060), RTP(5004-5005), SRTP
            if (port == 5060 || port == 5061 ||
                (port >= 5004 && port <= 5005) ||
                port == 16384) return AppType::VOIP;

            // Video conferencing: Zoom, Teams, WebRTC ranges
            if (port == 8801 || port == 8802 ||
                (port >= 50000 && port <= 50059) ||
                port == 3478 || port == 3479) return AppType::VIDEO_CONF;

            // Interactive: SSH, RDP, Telnet, HTTP/S interactive
            if (port == 22 || port == 23 || port == 3389 ||
                port == 443 || port == 80) return AppType::INTERACTIVE;

            // Streaming: RTMP, HLS, DASH
            if (port == 1935 || port == 8080 ||
                (port >= 554 && port <= 556)) return AppType::STREAMING;

            // Bulk transfer: FTP, SFTP, NFS, SMB, iSCSI
            if (port == 21 || port == 115 || port == 2049 ||
                port == 445 || port == 3260) return AppType::BULK_TRANSFER;

            // Background: DNS updates, NTP, SNMP, Syslog
            if (port == 53 || port == 123 || port == 161 ||
                port == 514) return AppType::BACKGROUND;

            return AppType::BEST_EFFORT;
        }

        // Returns priority 1-7 (7=highest)
        uint8_t priority(const FlowKey& key) const noexcept {
            return app_priority(classify(key));
        }
    };

} // namespace smartwan
