#pragma once

#include <cstdint>
#include <unordered_map>
#include <vector>

namespace nano {

/// Everything the flow layer needs to know about one packet, extracted once by
/// the pipeline so the decoders are not re-run at every stage.
struct PacketMeta {
    uint32_t src_ip   = 0;
    uint32_t dst_ip   = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint8_t  proto    = 0;
    uint64_t ts_us    = 0;  ///< from the capture, never a wall clock
    uint32_t bytes    = 0;  ///< frame length, for the session counters
};

/// Direction-agnostic conversation key.
///
/// Both halves of a conversation must land on one session, so the two endpoints
/// are sorted into a canonical order. The subtlety: an (address, port) pair is
/// sorted *as a pair*. Sorting addresses and ports independently would collapse
/// 10.0.0.1:80 <-> 10.0.0.2:443 and 10.0.0.1:443 <-> 10.0.0.2:80 onto the same
/// key -- two unrelated conversations sharing one session.
///
/// Which end initiated is not recoverable from the key, by design. The Session
/// records it, taken from whoever sent the SYN.
struct FiveTuple {
    uint32_t ip_a   = 0;
    uint32_t ip_b   = 0;
    uint16_t port_a = 0;
    uint16_t port_b = 0;
    uint8_t  proto  = 0;

    static FiveTuple make(uint32_t src_ip, uint16_t src_port,
                          uint32_t dst_ip, uint16_t dst_port, uint8_t proto);

    bool operator==(const FiveTuple& o) const {
        return ip_a == o.ip_a && ip_b == o.ip_b &&
               port_a == o.port_a && port_b == o.port_b && proto == o.proto;
    }
};

/// Hasher supplied as a template argument rather than a std::hash specialisation,
/// which keeps namespace std untouched.
///
/// The combine step matters more than it looks. XOR-ing the fields together is
/// the obvious version and it is wrong here: the key is symmetric by construction,
/// so ip_a ^ ip_b cancels for any pair of hosts talking to each other on mirrored
/// ports, and whole groups of conversations collapse into one bucket.
///
/// That is not only a performance question. A flow table with predictable
/// collisions is an algorithmic complexity attack surface -- an adversary who can
/// force every lookup into the same bucket degrades the table to a linear scan and
/// takes the firewall down with modest traffic. Distinct from a SYN flood, which
/// exhausts entries rather than degrading lookups, and worth being able to
/// separate.
struct FiveTupleHash {
    static void combine(size_t& seed, size_t value) {
        seed ^= value + 0x9e3779b9u + (seed << 6) + (seed >> 2);
    }

    size_t operator()(const FiveTuple& t) const {
        size_t seed = 0;
        combine(seed, static_cast<size_t>(t.ip_a));
        combine(seed, static_cast<size_t>(t.ip_b));
        combine(seed, static_cast<size_t>(t.port_a));
        combine(seed, static_cast<size_t>(t.port_b));
        combine(seed, static_cast<size_t>(t.proto));
        return seed;
    }
};

/// Observed state of a conversation.
///
/// Deliberately not RFC 793. That document describes an *endpoint*, which must
/// track its own half of the connection and handle retransmission and reassembly
/// to deliver bytes in order. A firewall is a middlebox: it sees both directions
/// and needs only enough state to decide whether a packet belongs to a
/// conversation it has already authorised. PAN-OS makes the same reduction --
/// INIT / OPENING / ACTIVE / DISCARD / CLOSING / CLOSED -- and for the same reason.
///
/// Transitions land in tcp_state.h; this is the vocabulary they operate on.
enum class SessionState : uint8_t {
    New,          ///< allocated, no packet applied yet
    SynSeen,      ///< SYN from the initiator
    SynAckSeen,   ///< SYN+ACK from the responder
    Established,  ///< handshake complete, or a UDP flow's first packet
    FinSeen,      ///< one side has closed
    Closing,      ///< both sides have closed, final ACK outstanding
    Closed,       ///< finished or reset; eligible to be reaped
};

const char* to_string(SessionState s);

struct Session {
    uint32_t id = 0;

    // Direction is defined by the initiator: whoever sent the first SYN, or for
    // UDP whoever sent the first packet. Everything downstream -- policy zones,
    // App-ID, NAT -- is expressed relative to this.
    uint32_t init_ip   = 0;
    uint32_t resp_ip   = 0;
    uint16_t init_port = 0;
    uint16_t resp_port = 0;
    uint8_t  proto     = 0;

    SessionState state = SessionState::New;

    uint64_t first_seen_us = 0;
    uint64_t last_seen_us  = 0;

    uint64_t pkts_c2s  = 0;
    uint64_t pkts_s2c  = 0;
    uint64_t bytes_c2s = 0;
    uint64_t bytes_s2c = 0;
};

/// Hash table of live conversations.
///
/// Lookup and creation are separate operations rather than one lookup_or_create.
/// Policy has to run between them: a packet that misses the table is a candidate
/// for a new session, and whether it becomes one depends on the rule base and on
/// whether it is a SYN. Fusing the two would force the policy decision into the
/// table, which is the wrong place for it.
class FlowTable {
public:
    static constexpr uint32_t kNoSession = 0xffffffffu;

    /// Finds the session this packet belongs to, or kNoSession.
    /// `to_initiator` reports direction: true when the packet flows
    /// responder -> initiator, i.e. it is return traffic.
    uint32_t lookup(const PacketMeta& m, bool& to_initiator) const;

    /// Allocates a session with `m`'s source as the initiator.
    uint32_t create(const PacketMeta& m);

    /// Applies a packet to an existing session: counters and last-seen.
    void touch(uint32_t id, const PacketMeta& m, bool to_initiator);

    Session&       get(uint32_t id)       { return sessions_[id]; }
    const Session& get(uint32_t id) const { return sessions_[id]; }

    size_t size() const { return sessions_.size(); }

    /// Sessions never move, so iteration order is creation order -- which is what
    /// `show session all` wants.
    const std::vector<Session>& all() const { return sessions_; }

private:
    // Sessions live in a vector and are addressed by index, never by pointer.
    //
    // A vector reallocates as it grows and invalidates every pointer into it, so
    // a map of FiveTuple -> Session* would dangle the first time the table
    // outgrew its capacity -- intermittently, under load, which is the worst
    // possible failure shape. Indices survive reallocation, are half the size,
    // and double as the session ID the CLI prints.
    std::vector<Session>                                  sessions_;
    std::unordered_map<FiveTuple, uint32_t, FiveTupleHash> by_key_;
};

}  // namespace nano
