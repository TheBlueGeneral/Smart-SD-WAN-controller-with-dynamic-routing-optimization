#pragma once
#include <cstdint>
#include <cmath>
#include <string>
#include <vector>
#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <atomic>
#include <mutex>
#include <limits>
#include <sstream>
#include <iomanip>

namespace smartwan {

    // ─── IP Address ─────────────────────────────────────────────────────────────
    struct IPAddress {
        uint32_t value{0};

        IPAddress() = default;
        explicit IPAddress(uint32_t v) : value(v) {}
        IPAddress(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
        : value((uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|uint32_t(d)) {}

        std::string to_string() const {
            return std::to_string((value>>24)&0xFF)+"."+std::to_string((value>>16)&0xFF)+
            "."+std::to_string((value>>8)&0xFF)+"."+std::to_string(value&0xFF);
        }
        bool operator==(const IPAddress& o) const { return value==o.value; }
        bool operator< (const IPAddress& o) const { return value< o.value; }
        bool operator!=(const IPAddress& o) const { return value!=o.value; }
    };

    // ─── Enumerations ────────────────────────────────────────────────────────────
    enum class AppType : uint8_t {
        VOIP=0, VIDEO_CONF, INTERACTIVE, STREAMING, BULK_TRANSFER, BACKGROUND,
        BEST_EFFORT, UNKNOWN=255
    };

    enum class LinkState : uint8_t { UP, DOWN, DEGRADED, CONGESTED };
    enum class NodeType  : uint8_t { EDGE, CORE, GATEWAY, CLOUD };
    enum class Protocol  : uint8_t { TCP=6, UDP=17, ICMP=1, OTHER=255 };

    // ─── Timing ──────────────────────────────────────────────────────────────────
    using Timestamp = std::chrono::time_point<std::chrono::steady_clock>;
    using WallClock = std::chrono::time_point<std::chrono::system_clock>;

    inline Timestamp mono_now() { return std::chrono::steady_clock::now(); }
    inline double ms_since(const Timestamp& t) {
        return std::chrono::duration<double,std::milli>(mono_now()-t).count();
    }

    // ─── Link Metrics ────────────────────────────────────────────────────────────
    struct LinkMetrics {
        double latency_ms       {0.0};
        double packet_loss_pct  {0.0};
        double jitter_ms        {0.0};
        double bandwidth_mbps   {1000.0};
        double utilization      {0.0};   // 0–1
        double congestion_score {0.0};   // 0–1
        uint64_t bytes_sent     {0};
        uint64_t bytes_recv     {0};
        Timestamp last_updated  {};

        // Composite cost – weights sum to 1
        double composite_cost(double lw=0.40, double pw=0.30,
                              double cw=0.20, double jw=0.10) const noexcept {
                                  double nl = std::min(latency_ms / 500.0, 1.0);
                                  double np = packet_loss_pct / 100.0;
                                  double nc = congestion_score;
                                  double nj = std::min(jitter_ms  / 100.0, 1.0);
                                  return lw*nl + pw*np + cw*nc + jw*nj;
                              }

                              // Quality score (higher = better)
                              double quality_score() const noexcept {
                                  return 1.0 - composite_cost();
                              }
    };

    // ─── App-aware metric weights ─────────────────────────────────────────────────
    struct AppWeights {
        double latency_w, loss_w, congestion_w, jitter_w;

        static AppWeights for_app(AppType app) noexcept {
            switch (app) {
                case AppType::VOIP:         return {0.25, 0.30, 0.20, 0.25};
                case AppType::VIDEO_CONF:   return {0.30, 0.30, 0.25, 0.15};
                case AppType::INTERACTIVE:  return {0.50, 0.20, 0.25, 0.05};
                case AppType::STREAMING:    return {0.15, 0.45, 0.30, 0.10};
                case AppType::BULK_TRANSFER:return {0.05, 0.50, 0.40, 0.05};
                case AppType::BACKGROUND:   return {0.05, 0.40, 0.50, 0.05};
                default:                    return {0.25, 0.25, 0.25, 0.25};
            }
        }

        double compute_cost(const LinkMetrics& m) const noexcept {
            double nl = std::min(m.latency_ms/500.0, 1.0);
            double np = m.packet_loss_pct/100.0;
            double nc = m.congestion_score;
            double nj = std::min(m.jitter_ms/100.0, 1.0);
            return latency_w*nl + loss_w*np + congestion_w*nc + jitter_w*nj;
        }
    };

    // ─── Flow Key (5-tuple) ───────────────────────────────────────────────────────
    struct FlowKey {
        IPAddress src_ip, dst_ip;
        uint16_t  src_port{0}, dst_port{0};
        Protocol  proto{Protocol::TCP};

        bool operator==(const FlowKey& o) const {
            return src_ip==o.src_ip && dst_ip==o.dst_ip &&
            src_port==o.src_port && dst_port==o.dst_port &&
            proto==o.proto;
        }
        bool operator<(const FlowKey& o) const {
            if (src_ip  != o.src_ip)   return src_ip  < o.src_ip;
            if (dst_ip  != o.dst_ip)   return dst_ip  < o.dst_ip;
            if (src_port!= o.src_port) return src_port< o.src_port;
            if (dst_port!= o.dst_port) return dst_port< o.dst_port;
            return proto < o.proto;
        }

        // FNV-1a hash for the flow key (used by Bloom filter / hash table)
        uint64_t hash() const noexcept {
            uint64_t h = 14695981039346656037ULL;
            auto mix = [&](uint64_t v){ h ^= v; h *= 1099511628211ULL; };
            mix(src_ip.value); mix(dst_ip.value);
            mix((uint64_t(src_port)<<16)|dst_port);
            mix(static_cast<uint8_t>(proto));
            return h;
        }
    };

    // ─── Flow Stats ──────────────────────────────────────────────────────────────
    struct FlowStats {
        uint64_t packets{0};
        uint64_t bytes{0};
        double   avg_latency_ms{0.0};
        Timestamp first_seen{};
        Timestamp last_seen{};

        void update(uint64_t pkt_bytes, double latency_ms) {
            ++packets;
            bytes += pkt_bytes;
            avg_latency_ms = (avg_latency_ms*(packets-1)+latency_ms)/packets;
            last_seen = mono_now();
        }
    };

    // ─── Constants ───────────────────────────────────────────────────────────────
    constexpr uint32_t INVALID_NODE = std::numeric_limits<uint32_t>::max();
    constexpr double   INF_COST     = std::numeric_limits<double>::infinity();
    constexpr int      MAX_NODES    = 1024;
    constexpr int      MAX_PATHS    = 8;   // K-shortest paths K value
    constexpr int      MAX_HOPS     = 32;
    constexpr double   EPSILON      = 1e-9;

    // ─── Utility ─────────────────────────────────────────────────────────────────
    inline std::string app_type_str(AppType t) {
        switch(t) {
            case AppType::VOIP:          return "VoIP";
            case AppType::VIDEO_CONF:    return "VideoConf";
            case AppType::INTERACTIVE:   return "Interactive";
            case AppType::STREAMING:     return "Streaming";
            case AppType::BULK_TRANSFER: return "BulkTransfer";
            case AppType::BACKGROUND:    return "Background";
            case AppType::BEST_EFFORT:   return "BestEffort";
            default:                     return "Unknown";
        }
    }

    inline uint8_t app_priority(AppType t) {
        switch(t) {
            case AppType::VOIP:          return 7;
            case AppType::VIDEO_CONF:    return 6;
            case AppType::INTERACTIVE:   return 5;
            case AppType::STREAMING:     return 4;
            case AppType::BULK_TRANSFER: return 3;
            case AppType::BACKGROUND:    return 2;
            default:                     return 1;
        }
    }

} // namespace smartwan
