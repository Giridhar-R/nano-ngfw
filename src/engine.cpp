#include "engine.h"

#include <string>

#include "appid.h"
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

        // The one and only policy call site.
        //
        // This is what "stateful" means in code. A stateless ACL asks "is this
        // packet allowed?" for every packet; here the question is asked once, of
        // the session, on its first packet. Every subsequent packet -- including
        // every packet of the return direction -- is forwarded on the strength of
        // the session existing. That is why no inbound rule is needed for the
        // server's SYN+ACK, and why anyone tempted to call evaluate() from the
        // per-packet path has misunderstood the design.
        Session& created = flows_.get(id);
        created.from_zone = policy_.zone_for(m.src_ip);
        created.to_zone   = policy_.zone_for(m.dst_ip);
        created.matched_rule = policy_.evaluate(created.from_zone, created.to_zone,
                                                m.proto, m.dst_port,
                                                std::string(), created.verdict);
        switch (created.verdict) {
            case Verdict::Allow: ++counters_.allowed; break;
            case Verdict::Deny:  ++counters_.denied;  break;
            case Verdict::Drop:  ++counters_.dropped; break;
        }

        // NAT is applied after policy, and only to traffic that was allowed --
        // there is no point allocating a binding for a session about to be
        // dropped. Outbound only: trust -> untrust is the direction that needs an
        // address it does not have.
        if (created.verdict == Verdict::Allow && nat_.enabled() &&
            created.from_zone == Zone::Trust && created.to_zone == Zone::Untrust) {
            uint16_t translated = 0;
            if (nat_.allocate(translated)) {
                created.nat_applied = true;
                created.nat_ip      = nat_.public_ip();
                created.nat_port    = translated;
            }
        }
    }

    flows_.touch(id, m, to_initiator);

    Session& s = flows_.get(id);
    if (is_tcp) {
        tcp_advance(s, tcp.flags, to_initiator);
    } else {
        udp_advance(s);
    }

    if (!s.app_latched && !payload.empty()) {
        // Classify against the destination port of the *client's* direction, so
        // return traffic is still judged against the service the session is for.
        classify_and_maybe_shift(s, payload, to_initiator ? s.resp_port : m.dst_port);
    }
}

void Engine::classify_and_maybe_shift(Session& s, ByteView payload, uint16_t dst_port) {
    s.l7_bytes_seen += static_cast<uint32_t>(payload.size());

    const AppIdResult result = classify(payload, s.proto, dst_port);

    if (result.application.empty()) {
        // Undecided. Keep waiting unless the payload was recognisably nothing we
        // know, or we have simply seen enough.
        if (!result.exhausted && s.l7_bytes_seen < kMaxL7Bytes) return;
        s.app = app::kUnknown;
    } else {
        s.app = result.application;
        if (!result.sni.empty()) s.sni = result.sni;
    }
    s.app_latched = true;

    // --- the App-ID shift ---------------------------------------------------
    //
    // The timing problem this resolves is real, not academic. Policy was decided
    // on the session's first packet, when the only thing known about it was a
    // port -- which is precisely the thing an NGFW claims not to trust. The
    // application is not knowable until payload arrives, several packets later.
    //
    // So policy is evaluated a second time, now with the application in hand. If
    // the answer changes, the session was admitted under one identity and turned
    // out to have another: SSH wearing port 443 is allowed by a rule for web
    // traffic, then reclassified and torn down. PAN-OS calls this an App-ID shift
    // and handles it the same way.
    const Verdict before = s.verdict;

    Verdict   after     = before;
    const int new_rule  = policy_.evaluate(s.from_zone, s.to_zone, s.proto,
                                           s.resp_port, s.app, after);

    s.matched_rule = new_rule;
    s.verdict      = after;

    if (after != before) {
        s.app_shifted = true;
        ++counters_.app_shifts;

        // The verdict counters track sessions, so move this one across rather
        // than counting it twice.
        switch (before) {
            case Verdict::Allow: --counters_.allowed; break;
            case Verdict::Deny:  --counters_.denied;  break;
            case Verdict::Drop:  --counters_.dropped; break;
        }
        switch (after) {
            case Verdict::Allow: ++counters_.allowed; break;
            case Verdict::Deny:  ++counters_.denied;  break;
            case Verdict::Drop:  ++counters_.dropped; break;
        }

        // A session that has lost its rule is torn down, not merely marked.
        if (after != Verdict::Allow) {
            s.state = SessionState::Closed;
        }
    }
}

}  // namespace nano
