#include "engine.h"

#include "tcp_state.h"

namespace nano {

void Engine::count_decode_failure(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok:          break;
        case DecodeStatus::ShortHeader: ++counters_.short_header; break;
        case DecodeStatus::BadVersion:  ++counters_.bad_version;  break;
        case DecodeStatus::BadIhl:      ++counters_.bad_ihl;      break;
        case DecodeStatus::BadLength:   ++counters_.bad_length;   break;
    }
}

void Engine::maybe_sweep(uint64_t now_us) {
    if (counters_.packets % kSweepInterval == 0) {
        counters_.sessions_retired += flows_.age_out(now_us, timeouts_);
    }
}

void Engine::finish(uint64_t last_ts_us) {
    counters_.sessions_retired += flows_.age_out(last_ts_us, timeouts_);
}

void Engine::process(ByteView frame, uint64_t ts_us) {
    ++counters_.packets;
    maybe_sweep(ts_us);

    EthHeader eth;
    ByteView  l3;
    const DecodeStatus eth_status = decode_eth(frame, eth, l3);
    if (eth_status != DecodeStatus::Ok) {
        count_decode_failure(eth_status);
        return;
    }

    switch (static_cast<EtherType>(eth.ethertype)) {
        case EtherType::Ipv4: ++counters_.ipv4; break;
        case EtherType::Arp:  ++counters_.arp;  return;
        case EtherType::Ipv6: ++counters_.ipv6; return;
        case EtherType::Vlan: ++counters_.vlan; return;  // tag walking is a non-goal
        default:              ++counters_.other_l3; return;
    }

    Ipv4Header ip;
    ByteView   l4;
    const DecodeStatus ip_status = decode_ipv4(l3, ip, l4);
    if (ip_status != DecodeStatus::Ok) {
        count_decode_failure(ip_status);
        return;
    }
    if (!ip.checksum_ok) ++counters_.bad_checksum;

    // A later fragment has no L4 header. Its first bytes are payload from the
    // middle of a segment, and treating them as ports is how fragment evasion
    // works. Counted and stopped here; reassembly is a non-goal.
    if (ip.later_fragment()) {
        ++counters_.fragments;
        return;
    }

    handle_l4(ip, l4, ts_us, static_cast<uint32_t>(frame.size()));
}

void Engine::handle_l4(const Ipv4Header& ip, ByteView l4, uint64_t ts_us,
                       uint32_t frame_bytes) {
    PacketMeta m;
    m.src_ip = ip.src;
    m.dst_ip = ip.dst;
    m.proto  = ip.protocol;
    m.ts_us  = ts_us;
    m.bytes  = frame_bytes;

    TcpHeader tcp;
    ByteView  payload;
    bool      is_tcp = false;

    switch (static_cast<IpProto>(ip.protocol)) {
        case IpProto::Tcp: {
            const DecodeStatus st = decode_tcp(l4, tcp, payload);
            if (st != DecodeStatus::Ok) {
                count_decode_failure(st);
                return;
            }
            m.src_port = tcp.src_port;
            m.dst_port = tcp.dst_port;
            is_tcp     = true;
            break;
        }
        case IpProto::Udp: {
            UdpHeader udp;
            const DecodeStatus st = decode_udp(l4, udp, payload);
            if (st != DecodeStatus::Ok) {
                count_decode_failure(st);
                return;
            }
            m.src_port = udp.src_port;
            m.dst_port = udp.dst_port;
            break;
        }
        default:
            ++counters_.other_l4;
            return;
    }

    bool     to_initiator = false;
    uint32_t id           = flows_.lookup(m, to_initiator);

    if (id == FlowTable::kNoSession) {
        // The stateful decision, and the only place a session is born.
        //
        // TCP may open on a pure SYN. Anything else -- a bare ACK, a FIN, data
        // for a conversation we never saw start -- is out of state and refused,
        // unless midstream pickup is on. UDP has no handshake, so any first
        // packet opens a flow.
        const bool may_open = is_tcp ? (tcp.pure_syn() || midstream_) : true;
        if (!may_open) {
            ++counters_.out_of_state;
            return;
        }
        id = flows_.create(m);
        ++counters_.sessions_created;
        to_initiator = false;  // by construction, the creating packet is c2s
    }

    flows_.touch(id, m, to_initiator);

    Session& s = flows_.get(id);
    if (is_tcp) {
        tcp_advance(s, tcp.flags, to_initiator);
    } else {
        udp_advance(s);
    }
}

}  // namespace nano
