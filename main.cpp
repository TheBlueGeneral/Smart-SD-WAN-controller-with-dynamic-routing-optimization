#include "network_graph.hpp"
#include "routing_engine.hpp"
#include "flow_table.hpp"
#include "digital_twin.hpp"
#include "traffic_shaper.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <sstream>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace smartwan;

static std::atomic<bool> g_running{true};

void signal_handler(int) { g_running = false; }

// ─────────────────────────────────────────────────────────────────────────────
//  Build a realistic WAN topology
// ─────────────────────────────────────────────────────────────────────────────
void build_wan_topology(NetworkGraph& g, DigitalTwin& twin) {
    // ── Nodes ─────────────────────────────────────────────────────────────────
    uint32_t nyc = g.add_node("NYC-HQ",        NodeType::GATEWAY, {10,0,0,1}, "New York");
    uint32_t lax = g.add_node("LAX-DC",        NodeType::CORE,    {10,0,1,1}, "Los Angeles");
    uint32_t chi = g.add_node("CHI-CORE",      NodeType::CORE,    {10,0,2,1}, "Chicago");
    uint32_t dal = g.add_node("DAL-EDGE",      NodeType::EDGE,    {10,0,3,1}, "Dallas");
    uint32_t sea = g.add_node("SEA-CLOUD",     NodeType::CLOUD,   {10,0,4,1}, "Seattle");
    uint32_t mia = g.add_node("MIA-EDGE",      NodeType::EDGE,    {10,0,5,1}, "Miami");
    uint32_t sfo = g.add_node("SFO-DC",        NodeType::CORE,    {10,0,6,1}, "San Francisco");
    uint32_t atl = g.add_node("ATL-EDGE",      NodeType::EDGE,    {10,0,7,1}, "Atlanta");

    // ── Links (bidirectional) ─────────────────────────────────────────────────
    // Primary backbone (high bandwidth)
    auto [l1,r1] = g.add_bidir_link(nyc, chi, "mpls-backbone",   10000.0, 80);
    auto [l2,r2] = g.add_bidir_link(chi, dal, "mpls-backbone",   10000.0, 80);
    auto [l3,r3] = g.add_bidir_link(dal, lax, "mpls-backbone",   10000.0, 80);
    auto [l4,r4] = g.add_bidir_link(lax, sfo, "mpls-backbone",    5000.0, 80);
    auto [l5,r5] = g.add_bidir_link(sfo, sea, "mpls-backbone",    5000.0, 80);

    // Regional spurs
    auto [l6,r6] = g.add_bidir_link(nyc, mia, "broadband",        1000.0, 120);
    auto [l7,r7] = g.add_bidir_link(mia, atl, "broadband",        1000.0, 120);
    auto [l8,r8] = g.add_bidir_link(atl, chi, "broadband",        1000.0, 120);
    auto [l9,r9] = g.add_bidir_link(dal, atl, "broadband",        1000.0, 120);

    // Cross-country backup links
    auto [la,ra] = g.add_bidir_link(nyc, lax, "internet-backup",   500.0, 200);
    auto [lb,rb] = g.add_bidir_link(chi, sfo, "internet-backup",   500.0, 200);
    auto [lc,rc] = g.add_bidir_link(sea, dal, "satellite",          100.0, 350);

    std::cout << "[TOPOLOGY] " << g.node_count() << " nodes, "
    << g.link_count() << " links\n";

    // ── Register link models with the digital twin ────────────────────────────
    auto reg = [&](uint32_t lid, double base_lat, double base_loss,
                   double base_util, double bw, bool backup=false) {
        LinkModel m;
        m.base_latency_ms  = base_lat;
        m.base_loss_pct    = base_loss;
        m.base_bandwidth   = bw;
        m.base_util        = base_util;
        m.failure_rate     = backup ? 5e-6 : 2e-6;
        m.recovery_rate    = backup ? 2e-3 : 1e-3;
        m.ou_sigma         = base_lat * 0.10;
        m.ou_theta         = 0.4;
        // Random diurnal phase per link
        m.diurnal_phase    = (double)lid * 0.37;
        twin.register_link_model(lid, m);
                   };

                   reg(l1, 12.0, 0.01, 0.40, 10000.0);  reg(r1, 12.0, 0.01, 0.40, 10000.0);
                   reg(l2, 18.0, 0.01, 0.35, 10000.0);  reg(r2, 18.0, 0.01, 0.35, 10000.0);
                   reg(l3, 25.0, 0.02, 0.50, 10000.0);  reg(r3, 25.0, 0.02, 0.50, 10000.0);
                   reg(l4,  8.0, 0.01, 0.30,  5000.0);  reg(r4,  8.0, 0.01, 0.30,  5000.0);
                   reg(l5, 10.0, 0.01, 0.25,  5000.0);  reg(r5, 10.0, 0.01, 0.25,  5000.0);
                   reg(l6, 20.0, 0.05, 0.60,  1000.0);  reg(r6, 20.0, 0.05, 0.60,  1000.0);
                   reg(l7, 15.0, 0.03, 0.55,  1000.0);  reg(r7, 15.0, 0.03, 0.55,  1000.0);
                   reg(l8, 20.0, 0.04, 0.50,  1000.0);  reg(r8, 20.0, 0.04, 0.50,  1000.0);
                   reg(l9, 18.0, 0.03, 0.45,  1000.0);  reg(r9, 18.0, 0.03, 0.45,  1000.0);
                   reg(la, 65.0, 0.10, 0.70,   500.0, true); reg(ra, 65.0, 0.10, 0.70,  500.0, true);
                   reg(lb, 55.0, 0.08, 0.65,   500.0, true); reg(rb, 55.0, 0.08, 0.65,  500.0, true);
                   reg(lc,200.0, 0.50, 0.80,   100.0, true); reg(rc,200.0, 0.50, 0.80,  100.0, true);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Controller Status Report
// ─────────────────────────────────────────────────────────────────────────────
void print_status(const NetworkGraph& g, const FlowTable& ft,
                  const DigitalTwin& twin, const RoutingEngine& re) {
    std::cout << "\n╔══════════════════════════════════════════╗\n";
    std::cout << "║      SmartWAN SD-WAN Controller Status  ║\n";
    std::cout << "╚══════════════════════════════════════════╝\n";
    std::cout << std::fixed << std::setprecision(2);
    std::cout << "  Sim time    : " << twin.sim_time() / 1000.0 << " s\n";
    std::cout << "  Nodes       : " << g.node_count() << "\n";
    std::cout << "  Links       : " << g.link_count() << "\n";
    std::cout << "  Active flows: " << ft.size() << "\n";

    auto ts = ft.stats();
    std::cout << "  Flow lookups: " << ts.total_lookups
    << "  bloom-miss=" << ts.bloom_misses
    << "  false-pos=" << ts.false_positives << "\n";
    std::cout << "  Bloom FPP   : " << ts.bloom_fpp * 100.0 << "%\n";

    // Show best path NYC→LAX for each app type
    static const std::array<AppType,4> apps{
        AppType::VOIP, AppType::VIDEO_CONF, AppType::INTERACTIVE, AppType::BULK_TRANSFER
    };
    auto nodes = g.all_node_ids();
    if (nodes.size() < 2) return;
    uint32_t src = nodes[0], dst = nodes[3];

    std::cout << "\n  ─── Routing Decisions (node 0 → node 3) ───\n";
    for (auto app : apps) {
        auto path = re.dijkstra(src, dst, app);
        std::cout << "  [" << app_type_str(app) << "] ";
        if (path.valid) {
            std::cout << "cost=" << path.total_cost
            << " lat=" << path.total_latency << "ms"
            << " hops=" << path.hop_count
            << " loss=" << path.max_loss << "%\n";
        } else {
            std::cout << "NO ROUTE\n";
        }
    }

    // K-shortest paths
    auto kpaths = re.yen_k_shortest(src, dst, 3, AppType::BEST_EFFORT);
    std::cout << "\n  ─── Top-" << kpaths.size() << " Paths (BEST_EFFORT) ───\n";
    for (size_t i = 0; i < kpaths.size(); ++i) {
        std::cout << "  [" << i+1 << "] hops=" << kpaths[i].hop_count
        << " cost=" << kpaths[i].total_cost
        << " lat=" << kpaths[i].total_latency << "ms\n";
    }

    // ECMP group
    auto ecmp = re.build_ecmp(src, dst, 3);
    std::cout << "\n  ─── ECMP Group (" << ecmp.paths.size() << " paths) ───\n";
    for (size_t i = 0; i < ecmp.paths.size(); ++i) {
        std::cout << "  Path " << i << ": weight=" << ecmp.weights[i]*100.0 << "%\n";
    }

    std::cout << "\n";
                  }

                  // ─────────────────────────────────────────────────────────────────────────────
                  //  Main
                  // ─────────────────────────────────────────────────────────────────────────────
                  int main(int argc, char** argv) {
                      std::signal(SIGINT,  signal_handler);
                      std::signal(SIGTERM, signal_handler);

                      std::cout << R"(
  ╔═══════════════════════════════════════════════════════╗
  ║      SmartWAN – AI-Driven SD-WAN Controller v1.0      ║
  ║  C++ Networking Core  +  Python AI Engine             ║
  ╚═══════════════════════════════════════════════════════╝
)" << "\n";

// ── Build topology ────────────────────────────────────────────────────────
NetworkGraph  graph;
DigitalTwin   twin(graph, 0xDEADBEEFCAFE);
build_wan_topology(graph, twin);

RoutingEngine engine(graph);
FlowTable     ft(65536);
FlowClassifier classifier;

// ── Register event callback ───────────────────────────────────────────────
twin.set_event_callback([&](const SimEvent& e, const NetworkGraph&) {
    std::cout << "[EVENT t=" << std::fixed << std::setprecision(0)
    << e.sim_time << "ms] " << e.description << "\n";
    // On link failure: recompute affected flows
    if (e.type == EventType::LINK_FAILURE) {
        ft.for_each([&](const FlowKey& k, FlowEntry& fe){
            for (uint32_t lid : fe.active_path.links) {
                if (lid == e.entity_id) {
                    // Reroute via Yen's algorithm
                    auto new_path = engine.dijkstra(
                        fe.active_path.nodes.front(),
                                                    fe.active_path.nodes.back(),
                                                    fe.app_type);
                    if (new_path.valid) {
                        fe.active_path = new_path;
                    }
                }
            }
        });
    }
});

// ── Seed some synthetic flows ──────────────────────────────────────────────
auto nodes = graph.all_node_ids();
uint32_t src = nodes[0], dst = nodes[3];

for (int i = 0; i < 100; ++i) {
    FlowKey k;
    k.src_ip   = IPAddress(10,0,0, (uint8_t)i);
    k.dst_ip   = IPAddress(10,0,3, (uint8_t)i);
    k.src_port = 10000 + i;
    k.dst_port = (i % 4 == 0) ? 5060 : (i % 4 == 1) ? 443 : 80;
    k.proto    = Protocol::TCP;

    FlowEntry fe;
    fe.key      = k;
    fe.app_type = classifier.classify(k);
    fe.priority = app_priority(fe.app_type);
    fe.active_path = engine.dijkstra(src, dst, fe.app_type);
    ft.install(fe);
}
std::cout << "[FLOWS] " << ft.size() << " flows installed\n\n";

// ── What-if analysis ───────────────────────────────────────────────────────
auto link_ids = graph.all_link_ids();
if (!link_ids.empty()) {
    std::cout << "[WHAT-IF] Simulating failure of link " << link_ids[0]
    << " for 30 seconds...\n";
    auto result = twin.what_if_link_failure(link_ids[0], 30000.0, 60000.0);
    std::cout << "  Route changes: " << result.route_changes << "\n";
    std::cout << "  Link failures: " << result.link_failure_count << "\n\n";
}

// ── Start live simulation ─────────────────────────────────────────────────
twin.start(200.0);
std::cout << "[SIM] Digital twin started (200ms step)\n";

// ── Main loop ─────────────────────────────────────────────────────────────
int iteration = 0;
while (g_running) {
    std::this_thread::sleep_for(std::chrono::seconds(5));
    ++iteration;

    ft.expire_flows();

    if (iteration % 3 == 0) {
        print_status(graph, ft, twin, engine);
    }

    // Inject anomalies periodically for ML training data
    if (iteration % 7 == 0 && !link_ids.empty()) {
        uint32_t target = link_ids[iteration % link_ids.size()];
        twin.inject_latency_spike(target, 50.0, 3000.0);
        std::cout << "[INJECT] Latency spike +50ms on link " << target << "\n";
    }
}

twin.stop();
std::cout << "\n[SHUTDOWN] SmartWAN controller stopped cleanly.\n";
return 0;
                  }
