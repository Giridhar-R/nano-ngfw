// Fuzz target for the full L2/L3/L4 decode chain.
//
// A packet decoder is an attacker-controlled input parser, which is the bug class
// behind thirty years of middlebox CVEs. Every field this code reads is a number
// somebody else chose, several of them are lengths, and the whole design rests on
// the claim that ByteView::has() is called before every read. That claim is worth
// checking mechanically rather than by inspection.
//
// The target is deliberately shallow: hand the chain arbitrary bytes and require
// that it neither crashes nor reads out of bounds. Correctness of the decoded
// values is the unit tests' job. What the fuzzer proves is that no input, however
// malformed, gets past the bounds checks -- which is exactly the property that
// makes it safe to point this at hostile traffic.
//
// Built with clang and libFuzzer, run under ASan and UBSan in CI. Anything the
// fuzzer finds becomes a NANO_ASSERT abort or a sanitizer report, both of which
// carry a file and line.

#include <cstddef>
#include <cstdint>

#include "decode.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const nano::ByteView frame(data, size);

    nano::EthHeader eth;
    nano::ByteView  l3;
    if (nano::decode_eth(frame, eth, l3) != nano::DecodeStatus::Ok) return 0;

    // Only IPv4 goes further, mirroring the real pipeline.
    if (eth.ethertype != static_cast<uint16_t>(nano::EtherType::Ipv4)) return 0;

    nano::Ipv4Header ip;
    nano::ByteView   l4;
    if (nano::decode_ipv4(l3, ip, l4) != nano::DecodeStatus::Ok) return 0;

    // A later fragment carries no L4 header. The pipeline stops here for those,
    // and so does the fuzzer -- feeding fragment payload to the TCP decoder would
    // exercise a path production never takes.
    if (ip.later_fragment()) return 0;

    switch (static_cast<nano::IpProto>(ip.protocol)) {
        case nano::IpProto::Tcp: {
            nano::TcpHeader tcp;
            nano::ByteView  payload;
            if (nano::decode_tcp(l4, tcp, payload) == nano::DecodeStatus::Ok) {
                // Touch the payload so a bad slice shows up as a read rather than
                // an unused value the optimiser deletes.
                for (size_t i = 0; i < payload.size(); ++i) {
                    volatile uint8_t byte = payload.u8(i);
                    (void)byte;
                }
            }
            break;
        }
        case nano::IpProto::Udp: {
            nano::UdpHeader udp;
            nano::ByteView  payload;
            if (nano::decode_udp(l4, udp, payload) == nano::DecodeStatus::Ok) {
                for (size_t i = 0; i < payload.size(); ++i) {
                    volatile uint8_t byte = payload.u8(i);
                    (void)byte;
                }
            }
            break;
        }
        default:
            break;
    }

    return 0;
}
