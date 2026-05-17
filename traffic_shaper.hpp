#pragma once
#include "common.hpp"
#include <array>
#include <queue>
#include <vector>
#include <mutex>
#include <cmath>
#include <atomic>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  TokenBucket – dual-rate (CIR/PIR) token bucket for policing & shaping
    //
    //  CIR = Committed Information Rate (guaranteed bandwidth)
    //  PIR = Peak Information Rate (burst allowance)
    // ─────────────────────────────────────────────────────────────────────────────
    struct TokenBucket {
        double cir_bps;      // Committed rate (bits/sec)
        double pir_bps;      // Peak rate (bits/sec)
        double cbs_bits;     // Committed burst size (bits)
        double pbs_bits;     // Peak burst size (bits)

        double c_tokens;     // Committed token counter
        double p_tokens;     // Peak token counter
        Timestamp last_refill;

        TokenBucket(double cir_mbps, double pir_mbps,
                    double cbs_ms = 100.0, double pbs_ms = 200.0)
        : cir_bps(cir_mbps * 1e6), pir_bps(pir_mbps * 1e6),
        cbs_bits(cir_mbps * 1e6 * cbs_ms / 1000.0),
        pbs_bits(pir_mbps * 1e6 * pbs_ms / 1000.0),
        c_tokens(cbs_bits), p_tokens(pbs_bits),
        last_refill(mono_now())
        {}

        // Attempt to consume bits_required tokens
        // Returns: "GREEN" / "YELLOW" / "RED" (RFC 4115 dual-rate, 3-colour)
        enum class Color { GREEN, YELLOW, RED };
        Color consume(double bits) {
            auto now = mono_now();
            double dt_s = std::chrono::duration<double>(now - last_refill).count();
            last_refill = now;

            // Refill tokens
            c_tokens = std::min(c_tokens + cir_bps * dt_s, cbs_bits);
            p_tokens = std::min(p_tokens + pir_bps * dt_s, pbs_bits);

            if (bits <= c_tokens) {
                c_tokens -= bits;
                p_tokens -= bits;
                return Color::GREEN;
            } else if (bits <= p_tokens) {
                p_tokens -= bits;
                return Color::YELLOW;
            }
            return Color::RED;
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  WFQ – Weighted Fair Queuing scheduler
    //
    //  Implements Deficit Round-Robin (DRR) – O(1) scheduling, approximates WFQ.
    //  8 priority classes (DSCP/802.1p mappings).
    // ─────────────────────────────────────────────────────────────────────────────
    class WFQScheduler {
    public:
        static constexpr int NUM_QUEUES = 8;

        struct Packet {
            uint64_t flow_id;
            uint32_t size_bytes;
            uint8_t  priority;    // 0 (lowest) – 7 (highest)
            double   enqueue_time;
            AppType  app;
        };

        // Quantum: bytes each queue is allowed to send per round
        // Higher priority queues get larger quanta
        WFQScheduler() {
            // Strict priority quanta: doubling per level
            for (int i = 0; i < NUM_QUEUES; ++i) {
                weights_[i]  = 1u << i;          // 1,2,4,8,16,32,64,128
                deficit_[i]  = 0;
                quantum_[i]  = (1u << i) * 512;  // bytes
            }
        }

        void enqueue(Packet pkt) {
            std::unique_lock<std::mutex> lk(mtx_);
            int q = std::min((int)pkt.priority, NUM_QUEUES-1);
            queues_[q].push(pkt);
            total_queued_.fetch_add(1);
        }

        // Dequeue next packet to transmit (DRR scheduling)
        std::optional<Packet> dequeue() {
            std::unique_lock<std::mutex> lk(mtx_);
            // Strict priority for top 2 queues (real-time traffic)
            for (int q = NUM_QUEUES-1; q >= NUM_QUEUES-2; --q) {
                if (!queues_[q].empty()) {
                    auto pkt = queues_[q].front(); queues_[q].pop();
                    total_dequeued_.fetch_add(1);
                    return pkt;
                }
            }
            // DRR for remaining queues
            for (int round = 0; round < NUM_QUEUES; ++round) {
                current_queue_ = (current_queue_ + 1) % (NUM_QUEUES-2);
                int q = current_queue_;
                if (queues_[q].empty()) { deficit_[q] = 0; continue; }

                deficit_[q] += quantum_[q];
                while (!queues_[q].empty() &&
                    queues_[q].front().size_bytes <= deficit_[q]) {
                    auto pkt = queues_[q].front(); queues_[q].pop();
                deficit_[q] -= pkt.size_bytes;
                total_dequeued_.fetch_add(1);
                return pkt;
                    }
            }
            return std::nullopt;
        }

        size_t queue_depth(int q) const {
            std::unique_lock<std::mutex> lk(mtx_);
            return queues_[q].size();
        }

        size_t total_queued()   const { return total_queued_.load(); }
        size_t total_dequeued() const { return total_dequeued_.load(); }

    private:
        mutable std::mutex         mtx_;
        std::queue<Packet>         queues_[NUM_QUEUES];
        std::array<uint32_t,NUM_QUEUES> weights_, quantum_;
        std::array<int32_t,NUM_QUEUES>  deficit_{};
        int current_queue_{0};
        std::atomic<size_t> total_queued_{0}, total_dequeued_{0};
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  RED – Random Early Detection / WRED gate
    //
    //  Implements Weighted RED with per-DSCP drop thresholds.
    //  Prevents TCP synchronisation by probabilistic early drops.
    // ─────────────────────────────────────────────────────────────────────────────
    class RED {
    public:
        struct Params {
            double min_th    {0.50}; // Queue fill fraction below which no drop
            double max_th    {0.90}; // Queue fill fraction above which always drop
            double max_p     {0.10}; // Maximum drop probability at max_th
            double w_q       {0.002}; // EWMA weight for avg queue length
        };

        RED(size_t max_queue_bytes, Params p = {})
        : max_bytes_(max_queue_bytes), p_(p),
        avg_(0.0), count_(0), cur_bytes_(0)
        {}

        // Decide whether to drop/mark an arriving packet
        // Returns true → DROP, false → ACCEPT
        bool should_drop(size_t pkt_bytes, std::mt19937_64& rng) {
            // Update EWMA queue average
            double q_frac = static_cast<double>(cur_bytes_) / max_bytes_;
            avg_ = (1.0 - p_.w_q) * avg_ + p_.w_q * q_frac;

            if (avg_ < p_.min_th) {
                count_ = 0;
                cur_bytes_ += pkt_bytes;
                return false;
            } else if (avg_ < p_.max_th) {
                ++count_;
                // Drop probability: linearly increases with avg queue
                double pb = p_.max_p * (avg_ - p_.min_th) / (p_.max_th - p_.min_th);
                // Gentle drop probability from count
                double pa = pb / (1.0 - count_ * pb);
                pa = std::min(pa, 1.0);
                std::uniform_real_distribution<double> uni(0.0, 1.0);
                if (uni(rng) < pa) {
                    count_ = 0;
                    return true; // Early drop
                }
            } else {
                // Queue saturated: always drop (tail drop)
                return true;
            }
            cur_bytes_ += pkt_bytes;
            return false;
        }

        void packet_departed(size_t bytes) {
            cur_bytes_ = cur_bytes_ > bytes ? cur_bytes_ - bytes : 0;
        }

        double avg_queue_frac() const { return avg_; }
        size_t current_bytes()  const { return cur_bytes_; }

    private:
        size_t max_bytes_;
        Params p_;
        double avg_;
        size_t count_;
        size_t cur_bytes_;
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  TrafficShaper – per-link QoS pipeline
    //  TokenBucket → WFQ Enqueue → RED Gate → WFQ Dequeue
    // ─────────────────────────────────────────────────────────────────────────────
    class TrafficShaper {
    public:
        TrafficShaper(double link_rate_mbps, size_t buffer_bytes = 4 * 1024 * 1024)
        : bucket_(link_rate_mbps * 0.9, link_rate_mbps),
        scheduler_(),
        red_(buffer_bytes),
        rng_(std::random_device{}())
        {}

        // Returns true if packet was accepted (not dropped)
        bool enqueue(WFQScheduler::Packet pkt) {
            auto color = bucket_.consume(pkt.size_bytes * 8.0);
            if (color == TokenBucket::Color::RED) { ++dropped_; return false; }
            if (red_.should_drop(pkt.size_bytes, rng_)) { ++dropped_; return false; }
            scheduler_.enqueue(pkt);
            return true;
        }

        std::optional<WFQScheduler::Packet> dequeue() {
            auto pkt = scheduler_.dequeue();
            if (pkt) red_.packet_departed(pkt->size_bytes);
            return pkt;
        }

        uint64_t dropped_packets() const { return dropped_.load(); }
        double   avg_queue_fill()  const { return red_.avg_queue_frac(); }

    private:
        TokenBucket      bucket_;
        WFQScheduler     scheduler_;
        RED              red_;
        std::mt19937_64  rng_;
        std::atomic<uint64_t> dropped_{0};
    };

} // namespace smartwan
