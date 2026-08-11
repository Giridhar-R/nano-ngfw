#include "flow.h"

namespace nano {

FiveTuple FiveTuple::make(uint32_t src_ip, uint16_t src_port,
                          uint32_t dst_ip, uint16_t dst_port, uint8_t proto) {
    FiveTuple t;
    t.proto = proto;

    // Order the two endpoints, comparing (address, port) as a unit. The tie on
    // equal addresses is broken by port, which is what keeps two conversations
    // between the same pair of hosts apart.
    const bool src_first = (src_ip < dst_ip) || (src_ip == dst_ip && src_port <= dst_port);
    if (src_first) {
        t.ip_a = src_ip;  t.port_a = src_port;
        t.ip_b = dst_ip;  t.port_b = dst_port;
    } else {
        t.ip_a = dst_ip;  t.port_a = dst_port;
        t.ip_b = src_ip;  t.port_b = src_port;
    }
    return t;
}

const char* to_string(SessionState s) {
    switch (s) {
        case SessionState::New:         return "NEW";
        case SessionState::SynSeen:     return "SYN-SEEN";
        case SessionState::SynAckSeen:  return "SYNACK-SEEN";
        case SessionState::Established: return "ESTABLISHED";
        case SessionState::FinSeen:     return "FIN-SEEN";
        case SessionState::Closing:     return "CLOSING";
        case SessionState::Closed:      return "CLOSED";
    }
    return "?";
}

uint32_t FlowTable::lookup(const PacketMeta& m, bool& to_initiator) const {
    const FiveTuple key = FiveTuple::make(m.src_ip, m.src_port, m.dst_ip, m.dst_port, m.proto);

    const auto it = by_key_.find(key);
    if (it == by_key_.end()) {
        to_initiator = false;
        return kNoSession;
    }

    // Direction comes from the session, not the key -- the key deliberately threw
    // that information away when it sorted the endpoints.
    const Session& s = sessions_[it->second];
    to_initiator = (m.dst_ip == s.init_ip && m.dst_port == s.init_port);
    return it->second;
}

uint32_t FlowTable::create(const PacketMeta& m) {
    const uint32_t id = static_cast<uint32_t>(sessions_.size());

    Session s;
    s.id            = id;
    s.init_ip       = m.src_ip;
    s.init_port     = m.src_port;
    s.resp_ip       = m.dst_ip;
    s.resp_port     = m.dst_port;
    s.proto         = m.proto;
    s.state         = SessionState::New;
    s.first_seen_us = m.ts_us;
    s.last_seen_us  = m.ts_us;
    sessions_.push_back(s);

    by_key_[FiveTuple::make(m.src_ip, m.src_port, m.dst_ip, m.dst_port, m.proto)] = id;
    return id;
}

uint64_t Timeouts::for_session(const Session& s) const {
    switch (s.state) {
        case SessionState::New:
        case SessionState::SynSeen:
        case SessionState::SynAckSeen:
            return syn_us;
        case SessionState::Established:
            return s.proto == 17 ? established_udp_us : established_tcp_us;
        case SessionState::FinSeen:
        case SessionState::Closing:
            return closing_us;
        case SessionState::Closed:
            return 0;
    }
    return closing_us;
}

size_t FlowTable::age_out(uint64_t now_us, const Timeouts& t) {
    size_t retired = 0;

    // A linear sweep of the index. Fine at this scale and called once every N
    // packets rather than per packet, which keeps it off the hot path -- a sweep
    // on every packet would be quadratic over the capture. A production dataplane
    // uses a timer wheel so expiry is O(1); that is a non-goal here, and naming it
    // is more useful than half-building it.
    for (auto it = by_key_.begin(); it != by_key_.end();) {
        Session& s = sessions_[it->second];

        const uint64_t idle    = now_us >= s.last_seen_us ? now_us - s.last_seen_us : 0;
        const uint64_t allowed = t.for_session(s);

        if (s.state == SessionState::Closed || idle > allowed) {
            s.state = SessionState::Closed;
            it      = by_key_.erase(it);
            ++retired;
        } else {
            ++it;
        }
    }
    return retired;
}

void FlowTable::touch(uint32_t id, const PacketMeta& m, bool to_initiator) {
    Session& s = sessions_[id];
    s.last_seen_us = m.ts_us;
    if (to_initiator) {
        ++s.pkts_s2c;
        s.bytes_s2c += m.bytes;
    } else {
        ++s.pkts_c2s;
        s.bytes_c2s += m.bytes;
    }
}

}  // namespace nano
