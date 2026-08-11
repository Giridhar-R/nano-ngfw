#include "decode.h"

#include <cstdio>

namespace nano {
namespace {

/// One's complement sum over a 16-bit word sequence, folding carries.
///
/// A correct IPv4 header sums to 0xffff when the checksum field is included as
/// it stands, which is why nothing here has to zero the field first.
uint16_t ones_complement_sum(ByteView v, size_t len) {
    uint32_t total = 0;
    size_t   i     = 0;
    for (; i + 1 < len; i += 2) {
        total += v.u16(i);
    }
    if (i < len) {
        // Odd trailing byte is padded on the right. An IPv4 header is always a
        // whole number of 32-bit words, so this cannot fire here -- it is kept
        // because the function is the obvious one to reuse for L4 checksums.
        total += static_cast<uint32_t>(v.u8(i)) << 8;
    }
    while (total >> 16) {
        total = (total & 0xffffu) + (total >> 16);
    }
    return static_cast<uint16_t>(total);
}

}  // namespace

const char* to_string(DecodeStatus s) {
    switch (s) {
        case DecodeStatus::Ok:          return "ok";
        case DecodeStatus::ShortHeader: return "short-header";
        case DecodeStatus::BadVersion:  return "bad-version";
        case DecodeStatus::BadIhl:      return "bad-ihl";
        case DecodeStatus::BadLength:   return "bad-length";
    }
    return "unknown";
}

DecodeStatus decode_eth(ByteView frame, EthHeader& out, ByteView& payload) {
    if (!frame.has(0, EthHeader::kSize)) return DecodeStatus::ShortHeader;

    out.dst       = frame.data();
    out.src       = frame.data() + 6;
    out.ethertype = frame.u16(12);
    payload       = frame.from(EthHeader::kSize);
    return DecodeStatus::Ok;
}

DecodeStatus decode_ipv4(ByteView pkt, Ipv4Header& out, ByteView& payload) {
    // The fixed part of the header is 20 bytes; options extend it.
    if (!pkt.has(0, 20)) return DecodeStatus::ShortHeader;

    const uint8_t vhl = pkt.u8(0);
    if ((vhl >> 4) != 4) return DecodeStatus::BadVersion;

    // IHL counts 32-bit words, not bytes.
    //
    // This is the classic trap. Hardcoding 20 works on the majority of traffic
    // and then silently reads the TCP header four bytes early the moment a
    // packet carries a Router Alert or a timestamp option. captures/ipv4_options
    // exists to make that failure loud.
    const uint8_t ihl_words = vhl & 0x0f;
    if (ihl_words < 5) return DecodeStatus::BadIhl;

    const size_t ihl_bytes = static_cast<size_t>(ihl_words) * 4;
    if (!pkt.has(0, ihl_bytes)) return DecodeStatus::BadIhl;

    out.ihl_bytes    = static_cast<uint8_t>(ihl_bytes);
    out.total_length = pkt.u16(2);
    out.ident        = pkt.u16(4);

    const uint16_t flags_frag = pkt.u16(6);
    out.dont_fragment   = (flags_frag & 0x4000u) != 0;
    out.more_fragments  = (flags_frag & 0x2000u) != 0;
    // The offset field counts 8-byte units. Stored in bytes so callers never
    // have to remember the multiplier.
    out.frag_offset     = static_cast<uint16_t>((flags_frag & 0x1fffu) * 8u);

    out.ttl      = pkt.u8(8);
    out.protocol = pkt.u8(9);
    out.src      = pkt.u32(12);
    out.dst      = pkt.u32(16);

    out.checksum_ok = ones_complement_sum(pkt, ihl_bytes) == 0xffffu;

    if (out.total_length < ihl_bytes) return DecodeStatus::BadLength;

    // Clip to total_length rather than trusting the frame to end where the packet
    // does. Ethernet pads frames shorter than 60 bytes, so a bare ACK arrives with
    // several bytes of zeroes after the TCP header; handing those to the L4
    // decoder as payload would invent application data that was never sent.
    //
    // The other direction -- total_length larger than the captured frame -- is a
    // truncated capture, common and harmless. Take whatever is actually present.
    const size_t l4_claimed   = out.total_length - ihl_bytes;
    const size_t l4_available = pkt.size() - ihl_bytes;
    payload = pkt.slice(ihl_bytes, l4_claimed < l4_available ? l4_claimed : l4_available);

    return DecodeStatus::Ok;
}

std::string ipv4_to_string(uint32_t addr) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u",
                  (addr >> 24) & 0xffu, (addr >> 16) & 0xffu,
                  (addr >> 8) & 0xffu, addr & 0xffu);
    return std::string(buf);
}

}  // namespace nano
