#include <string>
#include <vector>

#include "decode.h"
#include "engine.h"
#include "harness.h"
#include "pcap.h"
#include "tcp_state.h"

using namespace nano;

namespace {

std::string cap(const char* name) { return std::string(NANO_CAPTURES_DIR) + "/" + name; }

/// Runs a whole capture through the engine.
bool run(Engine& e, const char* name) {
    PcapReader  r;
    std::string err;
    if (!r.open(cap(name), err)) return false;

    ByteView frame;
    uint64_t ts = 0;
    while (r.next(frame, ts)) e.process(frame, ts);
    return true;
}

// --- the state machine in isolation ---------------------------------------

Session fresh() {
    Session s;
    s.state = SessionState::New;
    return s;
}

constexpr bool kFromInitiator = false;  // to_initiator == false
constexpr bool kToInitiator   = true;

void test_three_way_handshake() {
    Session s = fresh();

    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    CHECK(s.state == SessionState::SynSeen);

    tcp_advance(s, tcp_flag::kSyn | tcp_flag::kAck, kToInitiator);
    CHECK(s.state == SessionState::SynAckSeen);

    tcp_advance(s, tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::Established);

    // Data does not move an established session.
    tcp_advance(s, tcp_flag::kPsh | tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::Established);
}

void test_four_way_close() {
    Session s = fresh();
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    tcp_advance(s, tcp_flag::kSyn | tcp_flag::kAck, kToInitiator);
    tcp_advance(s, tcp_flag::kAck, kFromInitiator);

    tcp_advance(s, tcp_flag::kFin | tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::FinSeen);
    CHECK(s.fin_from_initiator);

    tcp_advance(s, tcp_flag::kFin | tcp_flag::kAck, kToInitiator);
    CHECK(s.state == SessionState::Closing);

    tcp_advance(s, tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::Closed);
}

/// Either end may close first. The machine must not assume it is the client.
void test_server_closes_first() {
    Session s = fresh();
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    tcp_advance(s, tcp_flag::kSyn | tcp_flag::kAck, kToInitiator);
    tcp_advance(s, tcp_flag::kAck, kFromInitiator);

    tcp_advance(s, tcp_flag::kFin | tcp_flag::kAck, kToInitiator);
    CHECK(s.state == SessionState::FinSeen);
    CHECK(!s.fin_from_initiator);

    tcp_advance(s, tcp_flag::kFin | tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::Closing);
}

/// A repeated FIN from the side that already closed is a retransmit, not the
/// other end closing. Getting this wrong reaches Closed a full leg early --
/// which is exactly why the session remembers who went first.
void test_repeated_fin_from_same_side_does_not_advance() {
    Session s = fresh();
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    tcp_advance(s, tcp_flag::kSyn | tcp_flag::kAck, kToInitiator);
    tcp_advance(s, tcp_flag::kAck, kFromInitiator);

    tcp_advance(s, tcp_flag::kFin | tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::FinSeen);

    tcp_advance(s, tcp_flag::kFin | tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::FinSeen);
}

void test_rst_closes_from_any_state() {
    for (auto start : {SessionState::SynSeen, SessionState::SynAckSeen,
                       SessionState::Established, SessionState::FinSeen,
                       SessionState::Closing}) {
        Session s = fresh();
        s.state   = start;
        tcp_advance(s, tcp_flag::kRst, kFromInitiator);
        CHECK(s.state == SessionState::Closed);
    }
}

void test_syn_retransmit_is_absorbed() {
    Session s = fresh();
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);
    CHECK(s.state == SessionState::SynSeen);
}

/// A SYN+ACK arriving from the wrong direction must not complete a handshake.
void test_direction_matters() {
    Session s = fresh();
    tcp_advance(s, tcp_flag::kSyn, kFromInitiator);

    tcp_advance(s, tcp_flag::kSyn | tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::SynSeen);   // unchanged

    tcp_advance(s, tcp_flag::kSyn | tcp_flag::kAck, kToInitiator);
    CHECK(s.state == SessionState::SynAckSeen);

    // The final ACK must come from the initiator too.
    tcp_advance(s, tcp_flag::kAck, kToInitiator);
    CHECK(s.state == SessionState::SynAckSeen);
    tcp_advance(s, tcp_flag::kAck, kFromInitiator);
    CHECK(s.state == SessionState::Established);
}

void test_udp_has_no_handshake() {
    Session s = fresh();
    udp_advance(s);
    CHECK(s.state == SessionState::Established);
    udp_advance(s);
    CHECK(s.state == SessionState::Established);
}

// --- the machine driven by real captures ----------------------------------

void test_capture_clean_handshake() {
    Engine e;
    CHECK(run(e, "handshake_clean.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    CHECK_EQ(e.counters().sessions_created, 1ull);
    CHECK_EQ(e.counters().out_of_state, 0ull);

    const Session& s = e.flows().get(0);
    CHECK(s.state == SessionState::Closed);
    CHECK_EQ(s.pkts_c2s, 5ull);   // SYN, ACK, GET, FIN, final ACK
    CHECK_EQ(s.pkts_s2c, 3ull);   // SYN+ACK, response, FIN
}

void test_capture_rst_midstream() {
    Engine e;
    CHECK(run(e, "rst_midstream.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    CHECK(e.flows().get(0).state == SessionState::Closed);
}

/// Three identical SYNs, one session.
void test_capture_syn_retransmit() {
    Engine e;
    CHECK(run(e, "syn_retransmit.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    CHECK_EQ(e.counters().sessions_created, 1ull);
    CHECK(e.flows().get(0).state == SessionState::SynSeen);
}

void test_capture_fin_both_ways() {
    Engine e;
    CHECK(run(e, "fin_both_ways.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    const Session& s = e.flows().get(0);
    CHECK(s.state == SessionState::Closed);
    CHECK(!s.fin_from_initiator);   // the server closed first in this fixture
}

/// The stateful decision, end to end: a bare ACK for a session nobody saw open
/// is refused, and no session is created.
void test_capture_out_of_state_is_refused() {
    Engine e;
    CHECK(run(e, "out_of_state.pcap"));
    CHECK_EQ(e.flows().size(), 0u);
    CHECK_EQ(e.counters().out_of_state, 1ull);
    CHECK_EQ(e.counters().sessions_created, 0ull);
}

/// The same packet, with midstream pickup on, is adopted instead.
void test_capture_midstream_pickup() {
    Engine e;
    e.set_midstream(true);
    CHECK(run(e, "out_of_state.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    CHECK_EQ(e.counters().out_of_state, 0ull);
    CHECK(e.flows().get(0).state == SessionState::Established);
}

void test_capture_udp_flow() {
    Engine e;
    CHECK(run(e, "udp_dns.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    const Session& s = e.flows().get(0);
    CHECK(s.state == SessionState::Established);
    CHECK_EQ(s.pkts_c2s, 1ull);
    CHECK_EQ(s.pkts_s2c, 1ull);
}

void test_counters_classify_non_ipv4() {
    Engine e;
    CHECK(run(e, "non_ipv4.pcap"));
    CHECK_EQ(e.counters().packets, 2ull);
    CHECK_EQ(e.counters().arp, 1ull);
    CHECK_EQ(e.counters().ipv6, 1ull);
    CHECK_EQ(e.counters().ipv4, 0ull);
    CHECK_EQ(e.flows().size(), 0u);
}

void test_counters_notice_a_bad_checksum() {
    Engine e;
    CHECK(run(e, "bad_ip_checksum.pcap"));
    CHECK_EQ(e.counters().bad_checksum, 1ull);
    CHECK_EQ(e.counters().malformed(), 0ull);   // corruption, not a parse failure
}

}  // namespace

int main() {
    test_three_way_handshake();
    test_four_way_close();
    test_server_closes_first();
    test_repeated_fin_from_same_side_does_not_advance();
    test_rst_closes_from_any_state();
    test_syn_retransmit_is_absorbed();
    test_direction_matters();
    test_udp_has_no_handshake();

    test_capture_clean_handshake();
    test_capture_rst_midstream();
    test_capture_syn_retransmit();
    test_capture_fin_both_ways();
    test_capture_out_of_state_is_refused();
    test_capture_midstream_pickup();
    test_capture_udp_flow();
    test_counters_classify_non_ipv4();
    test_counters_notice_a_bad_checksum();
    return nano::test::summary("tcp_state");
}
