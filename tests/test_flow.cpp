#include <cstdint>
#include <string>
#include <unordered_set>

#include "flow.h"
#include "harness.h"

using namespace nano;

namespace {

constexpr uint8_t kTcp = 6;

PacketMeta pkt(uint32_t sip, uint16_t sp, uint32_t dip, uint16_t dp,
               uint64_t ts = 0, uint32_t bytes = 60) {
    PacketMeta m;
    m.src_ip = sip; m.src_port = sp;
    m.dst_ip = dip; m.dst_port = dp;
    m.proto  = kTcp;
    m.ts_us  = ts;
    m.bytes  = bytes;
    return m;
}

void test_key_is_direction_agnostic() {
    const auto forward = FiveTuple::make(0x0a000001u, 52341, 0x0a000002u, 80, kTcp);
    const auto reverse = FiveTuple::make(0x0a000002u, 80, 0x0a000001u, 52341, kTcp);
    CHECK(forward == reverse);
    CHECK_EQ(FiveTupleHash{}(forward), FiveTupleHash{}(reverse));
}

/// The bug the pairwise sort exists to prevent. Sorting addresses and ports
/// independently would give these two conversations the same key.
void test_address_and_port_sort_together() {
    const auto a = FiveTuple::make(0x0a000001u, 80,  0x0a000002u, 443, kTcp);
    const auto b = FiveTuple::make(0x0a000001u, 443, 0x0a000002u, 80,  kTcp);
    CHECK(!(a == b));
}

void test_same_hosts_different_ports_are_distinct() {
    const auto a = FiveTuple::make(0x0a000001u, 52341, 0x0a000002u, 80, kTcp);
    const auto b = FiveTuple::make(0x0a000001u, 52342, 0x0a000002u, 80, kTcp);
    CHECK(!(a == b));
}

void test_protocol_separates_keys() {
    const auto tcp = FiveTuple::make(0x0a000001u, 53, 0x0a000002u, 53, 6);
    const auto udp = FiveTuple::make(0x0a000001u, 53, 0x0a000002u, 53, 17);
    CHECK(!(tcp == udp));
}

/// Symmetric keys plus an XOR combine would collapse mirrored conversations into
/// one bucket. This is a coarse smoke test that distinct conversations mostly
/// land on distinct hashes -- not a statistical claim, just a guard against the
/// obvious catastrophic version.
void test_hash_spreads() {
    std::unordered_set<size_t> seen;
    int collisions = 0;
    for (uint16_t port = 1024; port < 1024 + 500; ++port) {
        const auto   t = FiveTuple::make(0x0a000001u, port, 0x0a000002u, 80, kTcp);
        const size_t h = FiveTupleHash{}(t);
        if (!seen.insert(h).second) ++collisions;
    }
    CHECK(collisions < 5);
}

void test_lookup_miss_on_empty_table() {
    FlowTable table;
    bool      to_init = true;
    CHECK_EQ(table.lookup(pkt(1, 100, 2, 200), to_init), FlowTable::kNoSession);
    CHECK_EQ(table.size(), 0u);
}

void test_create_then_find_both_directions() {
    FlowTable table;
    const auto forward = pkt(0xc0a8010au, 52341, 0x5db8d822u, 80, 1000);

    const uint32_t id = table.create(forward);
    CHECK_EQ(id, 0u);
    CHECK_EQ(table.size(), 1u);

    bool to_init = true;
    CHECK_EQ(table.lookup(forward, to_init), id);
    CHECK(!to_init);   // initiator -> responder

    const auto reverse = pkt(0x5db8d822u, 80, 0xc0a8010au, 52341, 1010);
    CHECK_EQ(table.lookup(reverse, to_init), id);
    CHECK(to_init);    // return traffic

    const Session& s = table.get(id);
    CHECK_EQ(s.init_ip, 0xc0a8010au);
    CHECK_EQ(s.init_port, 52341u);
    CHECK_EQ(s.resp_port, 80u);
    CHECK_EQ(s.first_seen_us, 1000ull);
}

void test_counters_split_by_direction() {
    FlowTable  table;
    const auto forward = pkt(0xc0a8010au, 52341, 0x5db8d822u, 80, 1000, 74);
    const auto reverse = pkt(0x5db8d822u, 80, 0xc0a8010au, 52341, 2000, 512);

    const uint32_t id = table.create(forward);
    bool           to_init = false;

    table.lookup(forward, to_init);
    table.touch(id, forward, to_init);
    table.lookup(reverse, to_init);
    table.touch(id, reverse, to_init);
    table.lookup(reverse, to_init);
    table.touch(id, reverse, to_init);

    const Session& s = table.get(id);
    CHECK_EQ(s.pkts_c2s, 1ull);
    CHECK_EQ(s.pkts_s2c, 2ull);
    CHECK_EQ(s.bytes_c2s, 74ull);
    CHECK_EQ(s.bytes_s2c, 1024ull);
    CHECK_EQ(s.last_seen_us, 2000ull);
}

void test_sessions_stay_addressable_as_the_table_grows() {
    // The reason indices are stored instead of pointers. Grow the table well past
    // any initial capacity and confirm the earliest session is still intact and
    // still findable -- a Session* held across these insertions would dangle.
    FlowTable table;
    const auto first = pkt(0x0a000001u, 1024, 0x0a000002u, 80, 1);
    const uint32_t first_id = table.create(first);

    for (uint16_t i = 1; i < 2000; ++i) {
        table.create(pkt(0x0a000001u, static_cast<uint16_t>(1024 + i), 0x0a000002u, 80, i));
    }

    CHECK_EQ(table.size(), 2000u);
    CHECK_EQ(table.get(first_id).init_port, 1024u);

    bool to_init = true;
    CHECK_EQ(table.lookup(first, to_init), first_id);
    CHECK(!to_init);
}

void test_state_names() {
    CHECK_EQ(std::string(to_string(SessionState::Established)), std::string("ESTABLISHED"));
    CHECK_EQ(std::string(to_string(SessionState::Closed)), std::string("CLOSED"));
}

}  // namespace

int main() {
    test_key_is_direction_agnostic();
    test_address_and_port_sort_together();
    test_same_hosts_different_ports_are_distinct();
    test_protocol_separates_keys();
    test_hash_spreads();
    test_lookup_miss_on_empty_table();
    test_create_then_find_both_directions();
    test_counters_split_by_direction();
    test_sessions_stay_addressable_as_the_table_grows();
    test_state_names();
    return nano::test::summary("flow");
}
