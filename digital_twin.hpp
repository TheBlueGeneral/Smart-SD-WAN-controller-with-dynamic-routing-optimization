#pragma once
#include "common.hpp"
#include "network_graph.hpp"
#include "routing_engine.hpp"
#include "flow_table.hpp"
#include <vector>
#include <deque>
#include <unordered_map>
#include <functional>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <random>
#include <cmath>

namespace smartwan {

    // ─────────────────────────────────────────────────────────────────────────────
    //  Simulation Event – discrete event in the digital twin
    // ─────────────────────────────────────────────────────────────────────────────
    enum class EventType : uint8_t {
        LINK_METRIC_UPDATE,
        LINK_FAILURE,
        LINK_RECOVERY,
        NODE_FAILURE,
        NODE_RECOVERY,
        TRAFFIC_SURGE,
        CONGESTION_ONSET,
        ROUTE_CHANGE,
        FLOW_ARRIVAL,
        FLOW_DEPARTURE
    };

    struct SimEvent {
        double      sim_time;   // virtual simulation time (ms)
        EventType   type;
        uint32_t    entity_id;  // link or node ID
        double      magnitude;  // event magnitude (e.g. latency spike)
        std::string description;

        bool operator>(const SimEvent& o) const { return sim_time > o.sim_time; }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  LinkModel – stochastic link behaviour model for the digital twin
    //
    //  Models:
    //    • Latency:     Gaussian with auto-correlated Ornstein-Uhlenbeck noise
    //    • Packet Loss: Beta-distributed (captures burst loss behaviour)
    //    • Bandwidth:   ARIMA(1,0,1) process
    //    • Failure:     Two-state Markov chain (UP↔DOWN)
    // ─────────────────────────────────────────────────────────────────────────────
    struct LinkModel {
        // Base parameters
        double base_latency_ms   {10.0};
        double base_loss_pct     {0.0};
        double base_bandwidth    {1000.0};  // Mbps
        double base_util         {0.2};

        // OU noise parameters for latency
        double ou_theta          {0.5};   // Mean reversion rate
        double ou_sigma          {2.0};   // Volatility (ms)
        double ou_state          {0.0};   // Current noise state

        // Traffic model: diurnal pattern + random component
        double peak_multiplier   {2.5};   // Peak vs trough utilisation ratio
        double diurnal_phase     {0.0};   // Phase offset (0-2π)

        // Markov failure model
        double failure_rate      {1e-5};  // Failures per ms (MTBF ≈ 100k ms)
        double recovery_rate     {1e-3};  // Recovery per ms (MTTR ≈ 1k ms)
        bool   failed            {false};

        // ARIMA(1,0,1) state for bandwidth
        double arima_ar          {0.7};
        double arima_ma          {0.3};
        double arima_prev_noise  {0.0};
        double arima_prev_val    {0.0};

        // Advance model by dt milliseconds given sim_time
        void step(double sim_time, double dt, std::mt19937_64& rng,
                  LinkMetrics& out) {
            // ── Failure Markov Chain ───────────────────────────────────────────
            std::uniform_real_distribution<double> uni(0.0, 1.0);
            if (!failed) {
                if (uni(rng) < failure_rate * dt) failed = true;
            } else {
                if (uni(rng) < recovery_rate * dt) failed = false;
            }

            if (failed) {
                out.latency_ms       = 9999.0;
                out.packet_loss_pct  = 100.0;
                out.utilization      = 0.0;
                out.bandwidth_mbps   = 0.0;
                out.congestion_score = 1.0;
                return;
            }

            // ── Ornstein-Uhlenbeck latency noise ─────────────────────────────
            std::normal_distribution<double> norm(0.0, 1.0);
            double dW = norm(rng) * std::sqrt(dt);
            ou_state += -ou_theta * ou_state * dt / 1000.0 + ou_sigma * dW;
            double latency = base_latency_ms + std::max(ou_state, -base_latency_ms * 0.9);

            // ── Diurnal utilisation model ─────────────────────────────────────
            double hour_fraction = std::fmod(sim_time / 3600000.0, 24.0) / 24.0;
            double diurnal = 0.5 + 0.5 * std::sin(2.0 * M_PI * hour_fraction + diurnal_phase);
            double util = base_util * (1.0 + (peak_multiplier - 1.0) * diurnal);
            util = std::min(util, 0.98); // Never perfectly full

            // ── ARIMA(1,0,1) bandwidth fluctuation ───────────────────────────
            double bw_noise = norm(rng);
            double bw_innov = bw_noise + arima_ma * arima_prev_noise;
            double bw_delta = arima_ar * arima_prev_val + bw_innov * 20.0;
            arima_prev_val   = bw_delta;
            arima_prev_noise = bw_noise;
            double bw = std::max(base_bandwidth + bw_delta, 1.0);

            // ── Packet loss (Beta-like from util) ─────────────────────────────
            // Loss increases sharply near saturation
            double loss = 0.0;
            if (util > 0.70) {
                double overload = (util - 0.70) / 0.30;
                loss = std::min(base_loss_pct + 15.0 * std::pow(overload, 3.0), 50.0);
            } else {
                // Small baseline loss from bit errors
                loss = base_loss_pct + uni(rng) * 0.01;
            }

            // ── Jitter (proportional to latency variance) ─────────────────────
            double jitter = std::abs(ou_state) * 0.3 + util * 2.0;

            out.latency_ms       = latency;
            out.packet_loss_pct  = loss;
            out.utilization      = util;
            out.bandwidth_mbps   = bw;
            out.jitter_ms        = jitter;
            // Congestion score: nonlinear
            out.congestion_score = (util < 0.7) ? util * 0.3
            : 0.21 + std::pow((util-0.7)/0.3, 2.5) * 0.79;
            out.last_updated     = mono_now();
                  }
    };

    // ─────────────────────────────────────────────────────────────────────────────
    //  DigitalTwin
    //
    //  Real-time network state mirror + event-driven discrete simulation.
    //  Provides:
    //    • Live metric injection from physical network
    //    • Predictive simulation (fast-forward)
    //    • What-if analysis (scenario testing)
    //    • Anomaly injection for ML training
    //    • Routing policy impact assessment
    // ─────────────────────────────────────────────────────────────────────────────
    class DigitalTwin {
    public:
        using EventCallback = std::function<void(const SimEvent&, const NetworkGraph&)>;

        explicit DigitalTwin(NetworkGraph& graph, uint64_t seed = 42)
        : graph_(graph), rng_(seed), sim_time_(0.0)
        {}

        ~DigitalTwin() { stop(); }

        // ── Link Model Registration ──────────────────────────────────────────────
        void register_link_model(uint32_t link_id, LinkModel model) {
            std::unique_lock<std::mutex> lk(mtx_);
            link_models_[link_id] = std::move(model);
        }

        void set_event_callback(EventCallback cb) {
            std::unique_lock<std::mutex> lk(mtx_);
            callback_ = std::move(cb);
        }

        // ── Real-time Mode ────────────────────────────────────────────────────────
        void start(double step_ms = 100.0) {
            running_ = true;
            step_ms_ = step_ms;
            sim_thread_ = std::thread([this]{ simulation_loop(); });
        }

        void stop() {
            running_ = false;
            if (sim_thread_.joinable()) sim_thread_.join();
        }

        // ── Fast-forward Simulation ───────────────────────────────────────────────
        //  Runs N steps of dt_ms each; returns all emitted events.
        std::vector<SimEvent> fast_forward(size_t steps, double dt_ms = 100.0) {
            std::vector<SimEvent> events;
            for (size_t i = 0; i < steps; ++i) {
                auto evts = tick(dt_ms);
                events.insert(events.end(), evts.begin(), evts.end());
            }
            return events;
        }

        // ── What-if Analysis ─────────────────────────────────────────────────────
        struct ScenarioResult {
            double sim_duration_ms;
            size_t num_events;
            std::unordered_map<uint32_t, double> avg_link_latency;
            std::unordered_map<uint32_t, double> avg_link_loss;
            std::unordered_map<uint32_t, double> avg_link_util;
            size_t link_failure_count;
            size_t route_changes;
        };

        // Test: what happens if link link_id fails for failure_duration_ms?
        ScenarioResult what_if_link_failure(uint32_t link_id,
                                            double failure_duration_ms,
                                            double sim_duration_ms) {
            // Snapshot current model state
            auto saved_models = link_models_;
            double saved_time = sim_time_;

            // Inject failure
            if (link_models_.count(link_id))
                link_models_[link_id].failed = true;

            ScenarioResult result{};
            result.sim_duration_ms = sim_duration_ms;

            std::unordered_map<uint32_t, std::vector<double>> lat_acc, loss_acc, util_acc;
            double failure_end = sim_time_ + failure_duration_ms;

            double t = 0.0;
            while (t < sim_duration_ms) {
                // Recover link after failure duration
                if (sim_time_ >= failure_end && link_models_.count(link_id))
                    link_models_[link_id].failed = false;

                auto evts = tick(100.0);
                for (auto& e : evts) {
                    if (e.type == EventType::LINK_FAILURE)   ++result.link_failure_count;
                    if (e.type == EventType::ROUTE_CHANGE)   ++result.route_changes;
                }
                // Accumulate metrics
                for (auto& [lid, model] : link_models_) {
                    auto lp = graph_.get_link(lid);
                    if (lp) {
                        lat_acc[lid].push_back(lp->metrics.latency_ms);
                        loss_acc[lid].push_back(lp->metrics.packet_loss_pct);
                        util_acc[lid].push_back(lp->metrics.utilization);
                    }
                }
                result.num_events += evts.size();
                t += 100.0;
            }

            // Compute averages
            for (auto& [lid, v] : lat_acc) {
                double s = 0; for (auto x:v) s+=x;
                result.avg_link_latency[lid] = v.empty() ? 0 : s/v.size();
            }
            for (auto& [lid, v] : loss_acc) {
                double s = 0; for (auto x:v) s+=x;
                result.avg_link_loss[lid] = v.empty() ? 0 : s/v.size();
            }
            for (auto& [lid, v] : util_acc) {
                double s = 0; for (auto x:v) s+=x;
                result.avg_link_util[lid] = v.empty() ? 0 : s/v.size();
            }

            // Restore state
            link_models_ = saved_models;
            sim_time_    = saved_time;
            return result;
                                            }

                                            // ── Anomaly Injection (for ML training) ──────────────────────────────────
                                            void inject_latency_spike(uint32_t link_id, double spike_ms,
                                                                      double duration_ms) {
                                                std::unique_lock<std::mutex> lk(mtx_);
                                                pending_spikes_.push_back({link_id, spike_ms, sim_time_ + duration_ms});
                                                                      }

                                                                      void inject_congestion(uint32_t link_id, double util_target,
                                                                                             double duration_ms) {
                                                                          std::unique_lock<std::mutex> lk(mtx_);
                                                                          pending_congestion_.push_back({link_id, util_target, sim_time_ + duration_ms});
                                                                                             }

                                                                                             double sim_time() const { return sim_time_; }

                                                                                             // Return last N events from the history buffer
                                                                                             std::vector<SimEvent> recent_events(size_t n) const {
                                                                                                 std::unique_lock<std::mutex> lk(mtx_);
                                                                                                 size_t start = event_history_.size() > n ? event_history_.size()-n : 0;
                                                                                                 return std::vector<SimEvent>(event_history_.begin()+start,
                                                                                                                              event_history_.end());
                                                                                             }

    private:
        NetworkGraph&   graph_;
        std::mt19937_64 rng_;
        double          sim_time_;
        double          step_ms_{100.0};
        std::atomic<bool> running_{false};
        std::thread     sim_thread_;
        mutable std::mutex mtx_;
        EventCallback   callback_;
        std::deque<SimEvent> event_history_;

        std::unordered_map<uint32_t, LinkModel> link_models_;
        std::unordered_map<uint32_t, LinkState> prev_link_state_;

        struct SpikeInjection { uint32_t lid; double amount; double end_time; };
        struct CongestionInjection { uint32_t lid; double util; double end_time; };
        std::vector<SpikeInjection>     pending_spikes_;
        std::vector<CongestionInjection> pending_congestion_;

        // Single simulation tick: advance by dt_ms, update graph, emit events
        std::vector<SimEvent> tick(double dt_ms) {
            std::unique_lock<std::mutex> lk(mtx_);
            sim_time_ += dt_ms;
            std::vector<SimEvent> events;

            for (auto& [lid, model] : link_models_) {
                // Apply spike injections
                double extra_latency = 0.0;
                double forced_util   = -1.0;
                for (auto& s : pending_spikes_)
                    if (s.lid == lid && sim_time_ <= s.end_time)
                        extra_latency += s.amount;
                for (auto& c : pending_congestion_)
                    if (c.lid == lid && sim_time_ <= c.end_time)
                        forced_util = c.util;

                LinkMetrics m;
                model.step(sim_time_, dt_ms, rng_, m);
                m.latency_ms += extra_latency;
                if (forced_util >= 0.0) m.utilization = forced_util;

                // Check for state transitions
                LinkState new_state = m.packet_loss_pct >= 100.0 ? LinkState::DOWN
                : m.congestion_score >= 0.8  ? LinkState::CONGESTED
                : m.congestion_score >= 0.5  ? LinkState::DEGRADED
                : LinkState::UP;

                if (prev_link_state_.count(lid) && prev_link_state_[lid] != new_state) {
                    SimEvent ev;
                    ev.sim_time  = sim_time_;
                    ev.entity_id = lid;
                    ev.magnitude = m.latency_ms;
                    if (new_state == LinkState::DOWN) {
                        ev.type = EventType::LINK_FAILURE;
                        ev.description = "Link " + std::to_string(lid) + " FAILED";
                    } else if (prev_link_state_[lid] == LinkState::DOWN) {
                        ev.type = EventType::LINK_RECOVERY;
                        ev.description = "Link " + std::to_string(lid) + " RECOVERED";
                    } else {
                        ev.type = EventType::LINK_METRIC_UPDATE;
                        ev.description = "Link " + std::to_string(lid) + " state change";
                    }
                    events.push_back(ev);
                    event_history_.push_back(ev);
                }
                prev_link_state_[lid] = new_state;

                // Push to graph
                lk.unlock();
                graph_.update_link_metrics(lid, m.latency_ms, m.packet_loss_pct,
                                           m.utilization, m.bandwidth_mbps);
                graph_.set_link_state(lid, new_state);
                lk.lock();
            }

            // Clean up expired injections
            pending_spikes_.erase(
                std::remove_if(pending_spikes_.begin(), pending_spikes_.end(),
                               [&](auto& s){ return sim_time_ > s.end_time; }),
                                  pending_spikes_.end());
            pending_congestion_.erase(
                std::remove_if(pending_congestion_.begin(), pending_congestion_.end(),
                               [&](auto& c){ return sim_time_ > c.end_time; }),
                                      pending_congestion_.end());

            // Trim history buffer
            while (event_history_.size() > 10000) event_history_.pop_front();

            // Fire callbacks
            for (auto& e : events)
                if (callback_) { lk.unlock(); callback_(e, graph_); lk.lock(); }

                return events;
        }

        void simulation_loop() {
            while (running_) {
                tick(step_ms_);
                std::this_thread::sleep_for(
                    std::chrono::duration<double,std::milli>(step_ms_));
            }
        }
    };

} // namespace smartwan
