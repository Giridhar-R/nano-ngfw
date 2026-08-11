#include <cstdint>
#include <string>
#include <vector>

#include "decode.h"
#include "harness.h"
#include "pcap.h"

using namespace nano;

namespace {

std::string cap(const char* name) { return std::string(NANO_CAPTURES_DIR) + "/" + name; }

/// Pulls record `index` out of a capture into owned storage, so the bytes stay
/// valid after the reader has moved on.
std::vector<uint8_t> nth_frame(const char* name, size_t index) {
    PcapReader  r;
    std::string err;
    if (!r.open(cap(name), err)) return {};

    ByteView frame;
    uint64_t ts = 0;
    for (size_t i = 0; r.next(frame, ts); ++i) {
        if (i == index) return std::vector<uint8_t>(frame.data(), frame.data() + frame.size());
    }
    return {};
}

ByteView view_of(const std::vector<uint8_t>& v) { return ByteView(v.data(), v.size()); }

void test_ethernet() {
    const auto bytes = nth_frame("handshake_clean.pcap", 0);
    CHECK(!bytes.empty());

    EthHeader eth;
    ByteView  payload;
    CHECK(decode_eth(view_of(bytes), eth, payload) == DecodeStatus::Ok);
    CHECK_EQ(eth.ethertype, static_cast<uint16_t>(EtherType::Ipv4));
    CHECK_EQ(payload.size(), bytes.size() - 14);
    CHECK_EQ(eth.src[0], 0x00u);   // MAC_CLIENT from the fixture generator
    CHECK_EQ(eth.dst[0], 0x66u);   // MAC_ROUTER
}

void test_runt_frame_is_rejected() {
    const uint8_t runt[8] = {0};
    EthHeader     eth;
    ByteView      payload;
    CHECK(decode_eth(ByteView(runt, sizeof runt), eth, payload) == DecodeStatus::ShortHeader);
}

void test_ipv4_fields() {
    const auto bytes = nth_frame("handshake_clean.pcap", 0);
    EthHeader  eth;
    ByteView   l3;
    CHECK(decode_eth(view_of(bytes), eth, l3) == DecodeStatus::Ok);

    Ipv4Header ip;
    ByteView   l4;
    CHECK(decode_ipv4(l3, ip, l4) == DecodeStatus::Ok);

    CHECK_EQ(ip.ihl_bytes, 20u);
    CHECK_EQ(ip.protocol, static_cast<uint8_t>(IpProto::Tcp));
    CHECK_EQ(ip.ttl, 64u);
    CHECK_EQ(ipv4_to_string(ip.src), std::string("192.168.1.10"));
    CHECK_EQ(ipv4_to_string(ip.dst), std::string("93.184.216.34"));
    CHECK(ip.checksum_ok);
    CHECK(!ip.fragmented());
    CHECK_EQ(l4.size(), 20u);      // bare SYN, no options, no payload
}

/// IHL = 6. The whole point of the fixture: a decoder that assumes 20 bytes finds
/// the TCP header four bytes to the left of where it actually is.
void test_ipv4_options_shift_the_payload() {
    const auto bytes = nth_frame("ipv4_options.pcap", 0);
    EthHeader  eth;
    ByteView   l3;
    CHECK(decode_eth(view_of(bytes), eth, l3) == DecodeStatus::Ok);

    Ipv4Header ip;
    ByteView   l4;
    CHECK(decode_ipv4(l3, ip, l4) == DecodeStatus::Ok);
    CHECK_EQ(ip.ihl_bytes, 24u);
    CHECK(ip.checksum_ok);

    // If IHL were ignored, this would read into the option bytes instead.
    CHECK_EQ(l4.u16(0), 52341u);   // TCP source port
    CHECK_EQ(l4.u16(2), 80u);      // TCP destination port
}

/// A corrupted checksum must not stop structural decoding -- it is counted, not
/// treated as a parse failure.
void test_bad_checksum_is_reported_not_fatal() {
    const auto bytes = nth_frame("bad_ip_checksum.pcap", 0);
    EthHeader  eth;
    ByteView   l3;
    CHECK(decode_eth(view_of(bytes), eth, l3) == DecodeStatus::Ok);

    Ipv4Header ip;
    ByteView   l4;
    CHECK(decode_ipv4(l3, ip, l4) == DecodeStatus::Ok);
    CHECK(!ip.checksum_ok);
    CHECK_EQ(ip.protocol, 6u);
}

void test_non_ipv4_is_identified() {
    const auto arp = nth_frame("non_ipv4.pcap", 0);
    const auto v6  = nth_frame("non_ipv4.pcap", 1);

    EthHeader eth;
    ByteView  payload;
    CHECK(decode_eth(view_of(arp), eth, payload) == DecodeStatus::Ok);
    CHECK_EQ(eth.ethertype, static_cast<uint16_t>(EtherType::Arp));

    CHECK(decode_eth(view_of(v6), eth, payload) == DecodeStatus::Ok);
    CHECK_EQ(eth.ethertype, static_cast<uint16_t>(EtherType::Ipv6));
}

/// Ethernet pads frames below 60 bytes. The padding is not IP payload, and
/// clipping to total_length is what keeps it from being handed to the L4 decoder
/// as application data that nobody sent.
void test_ethernet_padding_is_clipped() {
    std::vector<uint8_t> pkt(20 + 6, 0);
    pkt[0] = 0x45;      // version 4, IHL 5
    pkt[2] = 0x00;      // total_length = 20: header only, no payload
    pkt[3] = 0x14;
    pkt[9] = 6;         // TCP

    Ipv4Header ip;
    ByteView   l4;
    CHECK(decode_ipv4(view_of(pkt), ip, l4) == DecodeStatus::Ok);
    CHECK_EQ(ip.total_length, 20u);
    CHECK_EQ(l4.size(), 0u);   // the six padding bytes are not payload
}

void test_malformed_ipv4() {
    // IHL of 4 is below the legal minimum of 5.
    std::vector<uint8_t> bad_ihl(20, 0);
    bad_ihl[0] = 0x44;
    Ipv4Header ip;
    ByteView   l4;
    CHECK(decode_ipv4(view_of(bad_ihl), ip, l4) == DecodeStatus::BadIhl);

    // Version 6 in an IPv4 slot.
    std::vector<uint8_t> bad_ver(20, 0);
    bad_ver[0] = 0x65;
    CHECK(decode_ipv4(view_of(bad_ver), ip, l4) == DecodeStatus::BadVersion);

    // IHL claims 60 bytes, frame holds 20.
    std::vector<uint8_t> lying_ihl(20, 0);
    lying_ihl[0] = 0x4f;
    CHECK(decode_ipv4(view_of(lying_ihl), ip, l4) == DecodeStatus::BadIhl);

    // total_length smaller than the header it describes.
    std::vector<uint8_t> short_total(20, 0);
    short_total[0] = 0x45;
    short_total[2] = 0x00;
    short_total[3] = 0x0a;   // 10 < 20
    CHECK(decode_ipv4(view_of(short_total), ip, l4) == DecodeStatus::BadLength);

    // Anything shorter than the fixed header.
    std::vector<uint8_t> stub(12, 0);
    stub[0] = 0x45;
    CHECK(decode_ipv4(view_of(stub), ip, l4) == DecodeStatus::ShortHeader);
}

/// Walks a capture down to L4 so the TCP tests read as one line each.
bool l4_of(const char* file, size_t index, Ipv4Header& ip, ByteView& l4,
           std::vector<uint8_t>& storage) {
    storage = nth_frame(file, index);
    if (storage.empty()) return false;

    EthHeader eth;
    ByteView  l3;
    if (decode_eth(view_of(storage), eth, l3) != DecodeStatus::Ok) return false;
    return decode_ipv4(l3, ip, l4) == DecodeStatus::Ok;
}

void test_tcp_fields_and_flags() {
    std::vector<uint8_t> storage;
    Ipv4Header           ip;
    ByteView             l4;

    // Packet 0 is the SYN, packet 1 the SYN+ACK, packet 2 the bare ACK.
    CHECK(l4_of("handshake_clean.pcap", 0, ip, l4, storage));
    TcpHeader tcp;
    ByteView  payload;
    CHECK(decode_tcp(l4, tcp, payload) == DecodeStatus::Ok);
    CHECK_EQ(tcp.src_port, 52341u);
    CHECK_EQ(tcp.dst_port, 80u);
    CHECK_EQ(tcp.seq, 1000u);
    CHECK(tcp.syn());
    CHECK(!tcp.ack_set());
    CHECK(tcp.pure_syn());
    CHECK_EQ(tcp.data_offset, 20u);
    CHECK_EQ(payload.size(), 0u);
    CHECK_EQ(tcp_flags_to_string(tcp.flags), std::string("SYN"));

    CHECK(l4_of("handshake_clean.pcap", 1, ip, l4, storage));
    CHECK(decode_tcp(l4, tcp, payload) == DecodeStatus::Ok);
    CHECK(tcp.syn());
    CHECK(tcp.ack_set());
    CHECK(!tcp.pure_syn());          // a SYN+ACK must never open a session
    CHECK_EQ(tcp.ack, 1001u);
    CHECK_EQ(tcp_flags_to_string(tcp.flags), std::string("SYN,ACK"));
}

/// Data offset = 8 words. The trap that mirrors IHL one layer up.
void test_tcp_options_shift_the_payload() {
    std::vector<uint8_t> storage;
    Ipv4Header           ip;
    ByteView             l4;
    CHECK(l4_of("tcp_options.pcap", 0, ip, l4, storage));

    TcpHeader tcp;
    ByteView  payload;
    CHECK(decode_tcp(l4, tcp, payload) == DecodeStatus::Ok);
    CHECK_EQ(tcp.data_offset, 40u);
    CHECK_EQ(payload.size(), 0u);   // all options, no data
    CHECK(tcp.pure_syn());
}

void test_tcp_payload_is_exact() {
    std::vector<uint8_t> storage;
    Ipv4Header           ip;
    ByteView             l4;
    CHECK(l4_of("http_get.pcap", 3, ip, l4, storage));

    TcpHeader tcp;
    ByteView  payload;
    CHECK(decode_tcp(l4, tcp, payload) == DecodeStatus::Ok);
    CHECK(payload.size() > 0u);
    CHECK_EQ(payload.u8(0), static_cast<uint8_t>('G'));
    CHECK_EQ(payload.u8(1), static_cast<uint8_t>('E'));
    CHECK_EQ(payload.u8(2), static_cast<uint8_t>('T'));
}

void test_malformed_tcp() {
    TcpHeader tcp;
    ByteView  payload;

    std::vector<uint8_t> stub(12, 0);
    CHECK(decode_tcp(view_of(stub), tcp, payload) == DecodeStatus::ShortHeader);

    // Data offset of 4 words is below the 20-byte minimum.
    std::vector<uint8_t> small_offset(20, 0);
    small_offset[12] = 0x40;
    CHECK(decode_tcp(view_of(small_offset), tcp, payload) == DecodeStatus::BadLength);

    // Data offset of 15 words = 60 bytes, but only 20 are present.
    std::vector<uint8_t> lying_offset(20, 0);
    lying_offset[12] = 0xf0;
    CHECK(decode_tcp(view_of(lying_offset), tcp, payload) == DecodeStatus::BadLength);
}

void test_udp() {
    std::vector<uint8_t> storage;
    Ipv4Header           ip;
    ByteView             l4;
    CHECK(l4_of("udp_dns.pcap", 0, ip, l4, storage));

    UdpHeader udp;
    ByteView  payload;
    CHECK(decode_udp(l4, udp, payload) == DecodeStatus::Ok);
    CHECK_EQ(udp.src_port, 53122u);
    CHECK_EQ(udp.dst_port, 53u);
    CHECK_EQ(payload.size(), static_cast<size_t>(udp.length) - 8u);

    // A length field below the header size is impossible.
    std::vector<uint8_t> bad(8, 0);
    bad[5] = 4;
    CHECK(decode_udp(view_of(bad), udp, payload) == DecodeStatus::BadLength);

    std::vector<uint8_t> stub(4, 0);
    CHECK(decode_udp(view_of(stub), udp, payload) == DecodeStatus::ShortHeader);
}

void test_flag_formatting() {
    CHECK_EQ(tcp_flags_to_string(0), std::string("-"));
    CHECK_EQ(tcp_flags_to_string(tcp_flag::kRst), std::string("RST"));
    CHECK_EQ(tcp_flags_to_string(tcp_flag::kFin | tcp_flag::kAck), std::string("ACK,FIN"));
}

void test_address_formatting() {
    CHECK_EQ(ipv4_to_string(0xc0a8010au), std::string("192.168.1.10"));
    CHECK_EQ(ipv4_to_string(0u), std::string("0.0.0.0"));
    CHECK_EQ(ipv4_to_string(0xffffffffu), std::string("255.255.255.255"));
}

}  // namespace

int main() {
    test_ethernet();
    test_runt_frame_is_rejected();
    test_ipv4_fields();
    test_ipv4_options_shift_the_payload();
    test_bad_checksum_is_reported_not_fatal();
    test_non_ipv4_is_identified();
    test_ethernet_padding_is_clipped();
    test_malformed_ipv4();
    test_tcp_fields_and_flags();
    test_tcp_options_shift_the_payload();
    test_tcp_payload_is_exact();
    test_malformed_tcp();
    test_udp();
    test_flag_formatting();
    test_address_formatting();
    return nano::test::summary("decode");
}
