#pragma once
#include "common.hpp"
#include "network_graph.hpp"
#include <queue>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <optional>
#include <limits>
#include <algorithm>
#include <deque>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  Path – a routing result
    // ─────────────────────────────────────────────────────────────────────────────
    struct Path {
        std::vector<uint32_t> nodes;      // node ID sequence (src → dst)
        std::vector<uint32_t> links;      // link ID sequence
        double total_cost     {INF_COST};
        double total_latency  {0.0};
        double max_loss       {0.0};
        double min_bandwidth  {1e9};
        size_t hop_count      {0};
        bool   valid          {false};

        bool operator<(const Path& o) const { return total_cost < o.total_cost; }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  ECMP Group – set of equal-cost paths for load balancing
    // ─────────────────────────────────────────────────────────────────────────────
    struct ECMPGroup {
        std::vector<Path>  paths;
        std::vector<double> weights; // Normalised traffic fractions (sum=1)

        // Select path for a flow using Fibonacci-extended hashing on flow hash
        const Path& select(uint64_t flow_hash) const {
            // Double hashing for uniform distribution
            uint64_t h = flow_hash ^ (flow_hash >> 33);
            h *= 0xff51afd7ed558ccdULL;
            h ^= h >> 33;
            size_t idx = h % paths.size();
            return paths[idx];
        }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  RoutingEngine
    //
    //  All algorithms operate on a NetworkGraph::Snapshot (immutable copy)
    //  to avoid holding graph locks during computation.
    // ─────────────────────────────────────────────────────────────────────────────
    class RoutingEngine {
    public:
        explicit RoutingEngine(const NetworkGraph& graph) : graph_(graph) {}

        // ── 1. Multi-Metric Dijkstra ──────────────────────────────────────────────
        //  Returns cheapest path from src to dst using composite app-aware cost.
        Path dijkstra(uint32_t src, uint32_t dst, AppType app = AppType::BEST_EFFORT) const {
            auto snap = graph_.snapshot(app);
            return dijkstra_on_snapshot(snap, src, dst, app);
        }

        // ── 2. Yen's K-Shortest Paths ─────────────────────────────────────────────
        //  Finds the K cheapest loop-free paths from src to dst.
        //  Reference: Yen (1971) "Finding the k shortest loopless paths in a network"
        std::vector<Path> yen_k_shortest(uint32_t src, uint32_t dst,
                                         int K = MAX_PATHS,
                                         AppType app = AppType::BEST_EFFORT) const {
                                             auto snap = graph_.snapshot(app);
                                             std::vector<Path> A; // confirmed shortest paths
                                             std::vector<Path> B; // candidate paths (min-heap)

                                             // A[0] = shortest path
                                             Path p0 = dijkstra_on_snapshot(snap, src, dst, app);
                                             if (!p0.valid) return {};
                                             A.push_back(p0);

                                             for (int k = 1; k < K; ++k) {
                                                 const Path& prev = A[k-1];

                                                 // Iterate over each spur node in the previous path
                                                 for (size_t i = 0; i + 1 < prev.nodes.size(); ++i) {
                                                     uint32_t spur_node = prev.nodes[i];

                                                     // Root path = A[k-1][0..i]
                                                     std::vector<uint32_t> root_nodes(prev.nodes.begin(),
                                                                                      prev.nodes.begin()+i+1);
                                                     std::vector<uint32_t> root_links(prev.links.begin(),
                                                                                      prev.links.begin()+i);

                                                     // Build forbidden set: links used by any A[j] that shares root
                                                     std::unordered_set<uint32_t> forbidden_links;
                                                     std::unordered_set<uint32_t> forbidden_nodes;

                                                     for (const auto& a : A) {
                                                         if (a.nodes.size() > i &&
                                                             std::vector<uint32_t>(a.nodes.begin(), a.nodes.begin()+i+1) == root_nodes)
                                                         {
                                                             if (a.links.size() > i)
                                                                 forbidden_links.insert(a.links[i]);
                                                         }
                                                     }
                                                     // Forbid all root nodes except spur_node (avoids loops)
                                                     for (size_t j = 0; j + 1 < root_nodes.size(); ++j)
                                                         forbidden_nodes.insert(root_nodes[j]);

                                                     // Compute spur path from spur_node to dst, avoiding forbidden
                                                     Path spur = dijkstra_on_snapshot(snap, spur_node, dst, app,
                                                                                      forbidden_links, forbidden_nodes);
                                                     if (!spur.valid) continue;

                                                     // Assemble root + spur
                                                     Path candidate;
                                                     candidate.nodes = root_nodes;
                                                     candidate.links = root_links;
                                                     candidate.nodes.insert(candidate.nodes.end(),
                                                                            spur.nodes.begin()+1, spur.nodes.end());
                                                     candidate.links.insert(candidate.links.end(),
                                                                            spur.links.begin(), spur.links.end());
                                                     recompute_path_costs(snap, candidate, app);

                                                     // Add if not already in A or B
                                                     bool dup = false;
                                                     for (auto& b : B) if (b.nodes == candidate.nodes) { dup=true; break; }
                                                     if (!dup) B.push_back(std::move(candidate));
                                                 }

                                                 if (B.empty()) break;

                                                 // Pick minimum-cost candidate from B
                                                 auto it = std::min_element(B.begin(), B.end());
                                                 A.push_back(*it);
                                                 B.erase(it);
                                             }
                                             return A;
                                         }

                                         // ── 3. Bellman-Ford with SPFA (Shortest Path Faster Algorithm) ───────────
                                         //  O(VE) worst case but typically O(kE) in practice.
                                         //  Handles negative weights and detects negative cycles.
                                         struct BellmanFordResult {
                                             std::unordered_map<uint32_t, double>   dist;
                                             std::unordered_map<uint32_t, uint32_t> prev_link;
                                             bool negative_cycle{false};
                                         };

                                         BellmanFordResult bellman_ford_spfa(uint32_t src,
                                                                             AppType app = AppType::BEST_EFFORT) const {
                                                                                 auto snap = graph_.snapshot(app);
                                                                                 BellmanFordResult res;
                                                                                 std::unordered_map<uint32_t, bool> in_queue;
                                                                                 std::unordered_map<uint32_t, int>  relax_count;

                                                                                 // Initialise
                                                                                 for (uint32_t n : snap.node_ids) {
                                                                                     res.dist[n]       = INF_COST;
                                                                                     in_queue[n]       = false;
                                                                                     relax_count[n]    = 0;
                                                                                     res.prev_link[n]  = INVALID_NODE;
                                                                                 }
                                                                                 res.dist[src] = 0.0;

                                                                                 std::deque<uint32_t> queue;
                                                                                 queue.push_back(src);
                                                                                 in_queue[src] = true;

                                                                                 while (!queue.empty()) {
                                                                                     uint32_t u = queue.front(); queue.pop_front();
                                                                                     in_queue[u] = false;

                                                                                     for (auto& [lid, lsrc, ldst, cost] : snap.edges) {
                                                                                         if (lsrc != u) continue;
                                                                                         double nd = res.dist[u] + cost;
                                                                                         if (nd < res.dist[ldst] - EPSILON) {
                                                                                             res.dist[ldst]     = nd;
                                                                                             res.prev_link[ldst] = lid;
                                                                                             if (!in_queue[ldst]) {
                                                                                                 ++relax_count[ldst];
                                                                                                 if (relax_count[ldst] > (int)snap.node_ids.size()) {
                                                                                                     res.negative_cycle = true;
                                                                                                     return res;
                                                                                                 }
                                                                                                 // SLF optimisation: push front if new dist < head dist
                                                                                                 if (!queue.empty() && nd < res.dist[queue.front()])
                                                                                                     queue.push_front(ldst);
                                                                                                 else
                                                                                                     queue.push_back(ldst);
                                                                                                 in_queue[ldst] = true;
                                                                                             }
                                                                                         }
                                                                                     }
                                                                                 }
                                                                                 return res;
                                                                             }

                                                                             // ── 4. A* Search with Latency Heuristic ──────────────────────────────────
                                                                             //  Uses average link latency as an admissible heuristic.
                                                                             Path astar(uint32_t src, uint32_t dst,
                                                                                        AppType app = AppType::BEST_EFFORT) const {
                                                                                            auto snap = graph_.snapshot(app);

                                                                                            // Precompute average cost per link (used as heuristic denominator)
                                                                                            double avg_cost = 0.0;
                                                                                            for (auto& [l,s,d,c] : snap.edges) avg_cost += c;
                                                                                            avg_cost = snap.edges.empty() ? 1.0 : avg_cost / snap.edges.size();

                                                                                            // h(n): minimum hops × average cost (admissible, never overestimates)
                                                                                            // In production, replace with pre-computed geographic distances.
                                                                                            auto heuristic = [&](uint32_t) -> double {
                                                                                                return avg_cost * 0.5; // conservative lower bound
                                                                                            };

                                                                                            struct AStarNode {
                                                                                                double f, g;
                                                                                                uint32_t node;
                                                                                                bool operator>(const AStarNode& o) const { return f > o.f; }
                                                                                            };

                                                                                            std::priority_queue<AStarNode, std::vector<AStarNode>,
                                                                                            std::greater<AStarNode>> open;
                                                                                            std::unordered_map<uint32_t, double>   g_score;
                                                                                            std::unordered_map<uint32_t, uint32_t> came_from_link;
                                                                                            std::unordered_map<uint32_t, uint32_t> came_from_node;
                                                                                            std::unordered_set<uint32_t>           closed;

                                                                                            for (uint32_t n : snap.node_ids) g_score[n] = INF_COST;
                                                                                            g_score[src] = 0.0;
                                                                                            open.push({heuristic(src), 0.0, src});

                                                                                            while (!open.empty()) {
                                                                                                auto [f, g, u] = open.top(); open.pop();
                                                                                                if (closed.count(u)) continue;
                                                                                                if (u == dst) break;
                                                                                                closed.insert(u);

                                                                                                for (auto& [lid, lsrc, ldst, cost] : snap.edges) {
                                                                                                    if (lsrc != u || closed.count(ldst)) continue;
                                                                                                    double ng = g + cost;
                                                                                                    if (ng < g_score[ldst] - EPSILON) {
                                                                                                        g_score[ldst]       = ng;
                                                                                                        came_from_link[ldst] = lid;
                                                                                                        came_from_node[ldst] = u;
                                                                                                        open.push({ng + heuristic(ldst), ng, ldst});
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                            return reconstruct_path(snap, came_from_node, came_from_link, src, dst, app);
                                                                                        }

                                                                                        // ── 5. ECMP Group Construction ────────────────────────────────────────────
                                                                                        //  Finds K equal-cost paths and assigns load-balanced weights.
                                                                                        ECMPGroup build_ecmp(uint32_t src, uint32_t dst, int K = MAX_PATHS,
                                                                                                             AppType app = AppType::BEST_EFFORT) const {
                                                                                                                 auto paths = yen_k_shortest(src, dst, K, app);
                                                                                                                 ECMPGroup group;
                                                                                                                 if (paths.empty()) return group;

                                                                                                                 double best_cost = paths[0].total_cost;
                                                                                                                 // Accept paths within 15% of the best cost as ECMP candidates
                                                                                                                 double threshold = best_cost * 1.15;
                                                                                                                 double total_inv_cost = 0.0;

                                                                                                                 for (auto& p : paths) {
                                                                                                                     if (p.total_cost <= threshold) {
                                                                                                                         group.paths.push_back(p);
                                                                                                                         total_inv_cost += 1.0 / (p.total_cost + EPSILON);
                                                                                                                     }
                                                                                                                 }

                                                                                                                 // Assign inversely proportional weights (shorter = more traffic)
                                                                                                                 group.weights.resize(group.paths.size());
                                                                                                                 for (size_t i = 0; i < group.paths.size(); ++i)
                                                                                                                     group.weights[i] = (1.0 / (group.paths[i].total_cost + EPSILON)) / total_inv_cost;

                                                                                                                 return group;
                                                                                                             }

                                                                                                             // ── 6. All-Pairs Shortest Paths (Floyd-Warshall) ─────────────────────────
                                                                                                             //  Used for the digital twin and offline analysis. O(V³).
                                                                                                             struct APSPResult {
                                                                                                                 std::vector<std::vector<double>>   dist;
                                                                                                                 std::vector<std::vector<uint32_t>> next_link; // link to take from i to j
                                                                                                                 std::vector<uint32_t> node_order;             // maps index → node_id
                                                                                                             };

                                                                                                             APSPResult floyd_warshall(AppType app = AppType::BEST_EFFORT) const {
                                                                                                                 auto snap = graph_.snapshot(app);
                                                                                                                 size_t N = snap.node_ids.size();

                                                                                                                 // Index mapping
                                                                                                                 std::unordered_map<uint32_t,size_t> idx;
                                                                                                                 APSPResult res;
                                                                                                                 res.node_order = snap.node_ids;
                                                                                                                 for (size_t i = 0; i < N; ++i) idx[snap.node_ids[i]] = i;

                                                                                                                 res.dist.assign(N, std::vector<double>(N, INF_COST));
                                                                                                                 res.next_link.assign(N, std::vector<uint32_t>(N, INVALID_NODE));

                                                                                                                 for (size_t i = 0; i < N; ++i) res.dist[i][i] = 0.0;

                                                                                                                 for (auto& [lid, lsrc, ldst, cost] : snap.edges) {
                                                                                                                     size_t s = idx[lsrc], d = idx[ldst];
                                                                                                                     if (cost < res.dist[s][d]) {
                                                                                                                         res.dist[s][d]     = cost;
                                                                                                                         res.next_link[s][d] = lid;
                                                                                                                     }
                                                                                                                 }

                                                                                                                 for (size_t k = 0; k < N; ++k) {
                                                                                                                     for (size_t i = 0; i < N; ++i) {
                                                                                                                         if (res.dist[i][k] == INF_COST) continue;
                                                                                                                         for (size_t j = 0; j < N; ++j) {
                                                                                                                             if (res.dist[k][j] == INF_COST) continue;
                                                                                                                             double nd = res.dist[i][k] + res.dist[k][j];
                                                                                                                             if (nd < res.dist[i][j] - EPSILON) {
                                                                                                                                 res.dist[i][j]     = nd;
                                                                                                                                 res.next_link[i][j] = res.next_link[i][k];
                                                                                                                             }
                                                                                                                         }
                                                                                                                     }
                                                                                                                 }
                                                                                                                 return res;
                                                                                                             }

                                                                                                             // ── 7. Maximum Bandwidth Path (Widest Path) ───────────────────────────────
                                                                                                             //  Maximises minimum link bandwidth along path – good for bulk transfers.
                                                                                                             Path widest_path(uint32_t src, uint32_t dst) const {
                                                                                                                 auto snap = graph_.snapshot(AppType::BULK_TRANSFER);

                                                                                                                 // Build bandwidth edges
                                                                                                                 struct BWEdge { uint32_t lid, src, dst; double bw; };
                                                                                                                 std::vector<BWEdge> bw_edges;
                                                                                                                 for (auto& [lid,lsrc,ldst,_] : snap.edges) {
                                                                                                                     auto lp = graph_.get_link(lid);
                                                                                                                     if (lp) bw_edges.push_back({lid, lsrc, ldst, lp->metrics.bandwidth_mbps});
                                                                                                                 }

                                                                                                                 std::unordered_map<uint32_t, double>   best_bw;
                                                                                                                 std::unordered_map<uint32_t, uint32_t> prev_link, prev_node;
                                                                                                                 for (uint32_t n : snap.node_ids) best_bw[n] = 0.0;
                                                                                                                 best_bw[src] = 1e15;

                                                                                                                 // Max-heap: (bandwidth, node)
                                                                                                                 using Entry = std::pair<double, uint32_t>;
                                                                                                                 std::priority_queue<Entry> pq;
                                                                                                                 pq.push({1e15, src});

                                                                                                                 while (!pq.empty()) {
                                                                                                                     auto [bw, u] = pq.top(); pq.pop();
                                                                                                                     if (bw < best_bw[u] - EPSILON) continue;
                                                                                                                     for (auto& e : bw_edges) {
                                                                                                                         if (e.src != u) continue;
                                                                                                                         double nb = std::min(bw, e.bw);
                                                                                                                         if (nb > best_bw[e.dst] + EPSILON) {
                                                                                                                             best_bw[e.dst] = nb;
                                                                                                                             prev_link[e.dst] = e.lid;
                                                                                                                             prev_node[e.dst] = u;
                                                                                                                             pq.push({nb, e.dst});
                                                                                                                         }
                                                                                                                     }
                                                                                                                 }
                                                                                                                 return reconstruct_path(snap, prev_node, prev_link, src, dst,
                                                                                                                                         AppType::BULK_TRANSFER);
                                                                                                             }

    private:
        const NetworkGraph& graph_;

        // Core Dijkstra on snapshot with optional forbidden sets (for Yen's)
        Path dijkstra_on_snapshot(
            const NetworkGraph::Snapshot& snap,
            uint32_t src, uint32_t dst, AppType app,
            const std::unordered_set<uint32_t>& forbidden_links = {},
            const std::unordered_set<uint32_t>& forbidden_nodes = {}) const
            {
                using Entry = std::pair<double, uint32_t>;
                std::priority_queue<Entry, std::vector<Entry>, std::greater<Entry>> pq;
                std::unordered_map<uint32_t, double>   dist;
                std::unordered_map<uint32_t, uint32_t> prev_link, prev_node;

                for (uint32_t n : snap.node_ids) dist[n] = INF_COST;
                dist[src] = 0.0;
                pq.push({0.0, src});

                while (!pq.empty()) {
                    auto [d, u] = pq.top(); pq.pop();
                    if (d > dist[u] + EPSILON) continue;
                    if (u == dst) break;

                    for (auto& [lid, lsrc, ldst, cost] : snap.edges) {
                        if (lsrc != u) continue;
                        if (forbidden_links.count(lid)) continue;
                        if (forbidden_nodes.count(ldst)) continue;
                        double nd = dist[u] + cost;
                        if (nd < dist[ldst] - EPSILON) {
                            dist[ldst]       = nd;
                            prev_link[ldst]  = lid;
                            prev_node[ldst]  = u;
                            pq.push({nd, ldst});
                        }
                    }
                }
                return reconstruct_path(snap, prev_node, prev_link, src, dst, app);
            }

            Path reconstruct_path(const NetworkGraph::Snapshot& snap,
                                  const std::unordered_map<uint32_t,uint32_t>& prev_node,
                                  const std::unordered_map<uint32_t,uint32_t>& prev_link,
                                  uint32_t src, uint32_t dst, AppType app) const {
                                      Path path;
                                      if (!prev_node.count(dst) && dst != src) return path;
                                      if (!prev_link.count(dst) && dst != src) return path;

                                      // Backtrack
                                      uint32_t cur = dst;
                                      while (cur != src) {
                                          path.nodes.push_back(cur);
                                          path.links.push_back(prev_link.at(cur));
                                          cur = prev_node.at(cur);
                                      }
                                      path.nodes.push_back(src);
                                      std::reverse(path.nodes.begin(), path.nodes.end());
                                      std::reverse(path.links.begin(), path.links.end());

                                      path.valid     = true;
                                      path.hop_count = path.links.size();
                                      recompute_path_costs(snap, path, app);
                                      return path;
                                  }

                                  void recompute_path_costs(const NetworkGraph::Snapshot& snap,
                                                            Path& path, AppType app) const {
                                                                // Build edge lookup from snapshot
                                                                std::unordered_map<uint32_t,double> edge_cost;
                                                                for (auto& [lid,s,d,c] : snap.edges) edge_cost[lid]=c;

                                                                path.total_cost    = 0.0;
                                                                path.total_latency = 0.0;
                                                                path.max_loss      = 0.0;
                                                                path.min_bandwidth = 1e9;

                                                                for (uint32_t lid : path.links) {
                                                                    path.total_cost += edge_cost.count(lid) ? edge_cost[lid] : INF_COST;
                                                                    auto lp = graph_.get_link(lid);
                                                                    if (lp) {
                                                                        path.total_latency += lp->metrics.latency_ms;
                                                                        path.max_loss       = std::max(path.max_loss, lp->metrics.packet_loss_pct);
                                                                        path.min_bandwidth  = std::min(path.min_bandwidth, lp->metrics.bandwidth_mbps);
                                                                    }
                                                                }
                                                            }
    };

} // namespace smartwan
