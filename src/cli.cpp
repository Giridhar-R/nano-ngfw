#include "cli.h"

#include <string>

#include "decode.h"

namespace nano {
namespace {

std::string endpoint(uint32_t ip, uint16_t port) {
    return ipv4_to_string(ip) + ":" + std::to_string(port);
}

const char* proto_name(uint8_t proto) {
    switch (static_cast<IpProto>(proto)) {
        case IpProto::Tcp:  return "tcp";
        case IpProto::Udp:  return "udp";
        case IpProto::Icmp: return "icmp";
    }
    return "ip";
}

/// Only printed when non-zero. A stats block where every line is a real event
/// stays readable; one padded with two dozen zeroes does not.
void line_if(std::FILE* out, const char* label, uint64_t value) {
    if (value != 0) std::fprintf(out, "  %-18s %10llu\n", label, static_cast<unsigned long long>(value));
}

}  // namespace

void print_sessions(std::FILE* out, const Engine& e) {
    std::fprintf(out, "%-4s %-18s %-8s %-8s %-22s %-22s %-12s %-6s\n",
                 "ID", "APP", "FROM", "TO", "SOURCE", "DESTINATION", "STATE", "ACTION");

    for (const Session& s : e.flows().all()) {
        std::fprintf(out, "%-4u %-18s %-8s %-8s %-22s %-22s %-12s %-6s\n",
                     s.id,
                     s.app_display(),
                     to_string(s.from_zone),
                     to_string(s.to_zone),
                     endpoint(s.init_ip, s.init_port).c_str(),
                     endpoint(s.resp_ip, s.resp_port).c_str(),
                     to_string(s.state),
                     to_string(s.verdict));
    }
}

void print_session_detail(std::FILE* out, const Engine& e, uint32_t id) {
    if (id >= e.flows().size()) {
        std::fprintf(out, "no session %u\n", id);
        return;
    }

    const Session& s = e.flows().get(id);
    const Rule*    rule = e.policy().rule_at(s.matched_rule);

    std::fprintf(out, "Session %u\n", s.id);
    std::fprintf(out, "  application  : %s\n", s.app_display());
    if (!s.sni.empty()) {
        std::fprintf(out, "  sni          : %s\n", s.sni.c_str());
    }
    std::fprintf(out, "  protocol     : %s\n", proto_name(s.proto));
    std::fprintf(out, "  initiator    : %s (%s)\n",
                 endpoint(s.init_ip, s.init_port).c_str(), to_string(s.from_zone));
    std::fprintf(out, "  responder    : %s (%s)\n",
                 endpoint(s.resp_ip, s.resp_port).c_str(), to_string(s.to_zone));
    std::fprintf(out, "  state        : %s\n", to_string(s.state));
    std::fprintf(out, "  rule         : %s\n", rule != nullptr ? rule->name.c_str()
                                                               : "(implicit default deny)");
    std::fprintf(out, "  action       : %s\n", to_string(s.verdict));
    if (s.app_shifted) {
        // The line the whole App-ID design exists to produce.
        std::fprintf(out, "  app-id shift : yes -- re-evaluated as %s after identification\n",
                     s.app.c_str());
    }
    if (s.nat_applied) {
        std::fprintf(out, "  nat          : %s -> %s (source PAT)\n",
                     endpoint(s.init_ip, s.init_port).c_str(),
                     endpoint(s.nat_ip, s.nat_port).c_str());
    }
    std::fprintf(out, "  c2s          : %llu packets, %llu bytes\n",
                 static_cast<unsigned long long>(s.pkts_c2s),
                 static_cast<unsigned long long>(s.bytes_c2s));
    std::fprintf(out, "  s2c          : %llu packets, %llu bytes\n",
                 static_cast<unsigned long long>(s.pkts_s2c),
                 static_cast<unsigned long long>(s.bytes_s2c));
    std::fprintf(out, "  duration     : %.6f s\n",
                 static_cast<double>(s.last_seen_us - s.first_seen_us) / 1e6);
}

void print_stats(std::FILE* out, const Engine& e) {
    const Counters& c = e.counters();

    std::fprintf(out, "packets            %10llu\n",
                 static_cast<unsigned long long>(c.packets));
    line_if(out, "ipv4", c.ipv4);
    line_if(out, "arp", c.arp);
    line_if(out, "ipv6", c.ipv6);
    line_if(out, "vlan", c.vlan);
    line_if(out, "other-l3", c.other_l3);
    line_if(out, "other-l4", c.other_l4);
    line_if(out, "fragments", c.fragments);

    std::fprintf(out, "malformed          %10llu\n",
                 static_cast<unsigned long long>(c.malformed()));
    line_if(out, "short-header", c.short_header);
    line_if(out, "bad-version", c.bad_version);
    line_if(out, "bad-ihl", c.bad_ihl);
    line_if(out, "bad-length", c.bad_length);

    // Deliberately outside the malformed total: a bad checksum is corruption in
    // transit, not a structural parse failure, and captures taken on a host with
    // checksum offload are full of them by design.
    line_if(out, "bad-checksum", c.bad_checksum);

    std::fprintf(out, "sessions           %10llu  (active %llu, retired %llu)\n",
                 static_cast<unsigned long long>(c.sessions_created),
                 static_cast<unsigned long long>(e.flows().active()),
                 static_cast<unsigned long long>(c.sessions_retired));
    line_if(out, "out-of-state", c.out_of_state);

    std::fprintf(out, "verdicts           allow %llu  deny %llu  drop %llu\n",
                 static_cast<unsigned long long>(c.allowed),
                 static_cast<unsigned long long>(c.denied),
                 static_cast<unsigned long long>(c.dropped));
    line_if(out, "app-id shifts", c.app_shifts);
}

}  // namespace nano
