#pragma once

#include <cstdint>

#include "byteview.h"
#include "decode.h"
#include "flow.h"
#include "nat.h"

namespace nano {

/// Everything the pipeline counts.
///
/// Counted rather than logged, because the value of these is in the ratios. A
/// spike in short_header on real traffic means the capture's snaplen is cutting
/// frames; a spike in bad_ihl means the parser is walking off the rails. A single
/// "malformed" total would hide both.
struct Counters {
    uint64_t packets  = 0;
    uint64_t ipv4     = 0;
    uint64_t arp      = 0;
    uint64_t ipv6     = 0;
    uint64_t vlan     = 0;
    uint64_t other_l3 = 0;

    uint64_t short_header = 0;
    uint64_t bad_version  = 0;
    uint64_t bad_ihl      = 0;
    uint64_t bad_length   = 0;
    uint64_t bad_checksum = 0;

    uint64_t fragments = 0;  ///< later fragments, stopped at L3
    uint64_t other_l4  = 0;  ///< IP protocols we do not track (ICMP and friends)

    uint64_t sessions_created = 0;
    uint64_t sessions_retired = 0;

    uint64_t allowed = 0;
    uint64_t denied  = 0;
    uint64_t dropped = 0;

    /// Sessions whose verdict changed once the application was identified.
    uint64_t app_shifts = 0;

    /// Packets belonging to no known session that were not allowed to start one.
    ///
    /// The number that makes the firewall stateful. In strict mode a bare ACK for
    /// a conversation we never saw open is dropped and counted here rather than
    /// silently creating a session, which is precisely the difference between a
    /// stateful device and an ACL.
    uint64_t out_of_state = 0;

    uint64_t malformed() const {
        return short_header + bad_version + bad_ihl + bad_length;
    }
};

/// Drives one capture through decode, flow lookup and the state machine.
class Engine {
public:
    Engine() { policy_.load_default(); }

    Policy&       policy()       { return policy_; }
    const Policy& policy() const { return policy_; }

    /// Midstream pickup: adopt a session from a non-SYN packet.
    ///
    /// Off by default, because refusing is what statefulness means. It exists
    /// because real deployments need it -- a firewall that has just taken over
    /// from its HA peer, or one seeing only one leg of an asymmetrically routed
    /// flow, has no session table and would otherwise drop every established
    /// conversation on the wire. Knowing why the escape hatch exists is worth
    /// more than picking either behaviour and defending it alone.
    void set_midstream(bool on) { midstream_ = on; }

    void set_timeouts(const Timeouts& t) { timeouts_ = t; }

    /// Turns on source NAT for allowed trust -> untrust sessions.
    void set_nat(const NatPool& pool) { nat_ = pool; }

    /// Applies one frame. `ts_us` comes from the capture, never a wall clock.
    void process(ByteView frame, uint64_t ts_us);

    /// Runs a final aging pass. Call once the capture is exhausted so the closing
    /// state of the table reflects the last timestamp rather than whenever the
    /// most recent sweep happened to fall.
    void finish(uint64_t last_ts_us);

    const FlowTable& flows() const { return flows_; }
    const Counters&  counters() const { return counters_; }

private:
    void count_decode_failure(DecodeStatus s);
    void handle_l4(const Ipv4Header& ip, ByteView l4, uint64_t ts_us, uint32_t frame_bytes);
    void maybe_sweep(uint64_t now_us);

    /// Runs App-ID against a payload and, if it decides, re-evaluates policy.
    void classify_and_maybe_shift(Session& s, ByteView payload, uint16_t dst_port);

    /// Payload bytes to wait for before giving up on identifying a session.
    /// Every protocol worth naming announces itself in the first packet or two;
    /// beyond this the session is called unknown so it stops being reconsidered.
    static constexpr uint32_t kMaxL7Bytes = 4096;

    /// Packets between aging sweeps. Sweeping per packet would make the run
    /// quadratic in the session count; sweeping never would let the table grow
    /// without bound. 128 is small enough that timeouts land close to where they
    /// should and large enough that the sweep is not on the hot path.
    static constexpr uint64_t kSweepInterval = 128;

    FlowTable flows_;
    Policy    policy_;
    NatPool   nat_;
    Counters  counters_;
    Timeouts  timeouts_;
    bool      midstream_ = false;
};

}  // namespace nano
