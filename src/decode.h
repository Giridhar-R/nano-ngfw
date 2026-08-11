#pragma once

#include <cstdint>
#include <string>

#include "byteview.h"

namespace nano {

// ---------------------------------------------------------------------------
// Why this file parses by offset instead of casting a struct over the buffer
//
// The tempting version is a #pragma pack struct and a reinterpret_cast. It is
// wrong three ways: the cast violates strict aliasing and assumes an alignment
// the buffer does not promise, it does nothing about byte order so every field
// needs swapping anyway, and it hides the offsets -- which are the thing worth
// knowing. Reading fields explicitly costs a few lines and is correct on every
// compiler in the CI matrix.
//
// Every decoder is total: it either reports a structured failure or produces a
// header whose payload view is guaranteed in range. Nothing here can read past
// the end of the frame, which is the property the fuzzer exists to check.
// ---------------------------------------------------------------------------

enum class EtherType : uint16_t {
    Ipv4 = 0x0800,
    Arp  = 0x0806,
    Vlan = 0x8100,
    Ipv6 = 0x86DD,
};

enum class IpProto : uint8_t {
    Icmp = 1,
    Tcp  = 6,
    Udp  = 17,
};

/// Ethernet II. MAC pointers alias the frame rather than copying it -- they are
/// only used for display, and they inherit the frame's lifetime.
struct EthHeader {
    static constexpr size_t kSize = 14;

    const uint8_t* dst       = nullptr;  ///< 6 bytes
    const uint8_t* src       = nullptr;  ///< 6 bytes
    uint16_t       ethertype = 0;
};

struct Ipv4Header {
    uint8_t  ihl_bytes    = 0;   ///< header length including options, in bytes
    uint8_t  ttl          = 0;
    uint8_t  protocol     = 0;
    uint16_t total_length = 0;
    uint16_t ident        = 0;
    uint16_t frag_offset  = 0;   ///< in bytes, not the raw 8-byte units
    bool     dont_fragment = false;
    bool     more_fragments = false;
    uint32_t src = 0;
    uint32_t dst = 0;

    /// True for every fragment except the first.
    ///
    /// It matters because a non-first fragment carries no L4 header: the bytes
    /// where a TCP source port would be are payload from the middle of a
    /// segment. A decoder that misses this classifies noise as ports, which is
    /// the basis of a whole family of fragment evasion attacks. The pipeline
    /// stops at L3 for these -- reassembly is an explicit non-goal.
    bool later_fragment() const { return frag_offset > 0; }

    bool fragmented() const { return more_fragments || frag_offset > 0; }

    /// Checksum verification is reported, not enforced.
    ///
    /// Structural decoding succeeds regardless, because the distinction is worth
    /// counting separately: a malformed header is a parser problem, a bad
    /// checksum is a corruption problem, and captures taken on a host with
    /// checksum offload are full of the latter by design.
    bool checksum_ok = false;
};

/// TCP flag bits, in the order they sit in the byte at offset 13.
namespace tcp_flag {
constexpr uint8_t kFin = 0x01;
constexpr uint8_t kSyn = 0x02;
constexpr uint8_t kRst = 0x04;
constexpr uint8_t kPsh = 0x08;
constexpr uint8_t kAck = 0x10;
constexpr uint8_t kUrg = 0x20;
}  // namespace tcp_flag

struct TcpHeader {
    static constexpr size_t kMinSize = 20;

    uint16_t src_port    = 0;
    uint16_t dst_port    = 0;
    uint32_t seq         = 0;
    uint32_t ack         = 0;
    uint8_t  data_offset = 0;  ///< header length including options, in bytes
    uint8_t  flags       = 0;
    uint16_t window      = 0;

    bool fin() const { return (flags & tcp_flag::kFin) != 0; }
    bool syn() const { return (flags & tcp_flag::kSyn) != 0; }
    bool rst() const { return (flags & tcp_flag::kRst) != 0; }
    bool psh() const { return (flags & tcp_flag::kPsh) != 0; }
    bool ack_set() const { return (flags & tcp_flag::kAck) != 0; }
    bool urg() const { return (flags & tcp_flag::kUrg) != 0; }

    /// A SYN with no ACK: the first packet of a connection, and the only thing
    /// that may create a session when the firewall is running strict.
    bool pure_syn() const { return syn() && !ack_set(); }
};

struct UdpHeader {
    static constexpr size_t kSize = 8;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t length   = 0;  ///< header + payload, as claimed by the sender
};

/// Why an enum rather than bool: each failure is counted separately in the stats
/// output, and a spike in one of them is diagnostic. A jump in ShortHeader on
/// real traffic means the snaplen cut frames short; a jump in BadIhl means the
/// parser is walking off the rails.
enum class DecodeStatus : uint8_t {
    Ok,
    ShortHeader,   ///< fewer bytes than the fixed header needs
    BadVersion,    ///< IP version nibble was not 4
    BadIhl,        ///< IHL below 5, or claiming more than the frame holds
    BadLength,     ///< total_length/data offset inconsistent with what we have
};

const char* to_string(DecodeStatus s);

/// Decodes an Ethernet II frame. `payload` is set to everything after the
/// 14-byte header. Returns ShortHeader for a runt.
DecodeStatus decode_eth(ByteView frame, EthHeader& out, ByteView& payload);

/// Decodes an IPv4 packet. `payload` is the L4 segment, clipped to total_length
/// when the frame carries trailing padding -- Ethernet pads anything under 60
/// bytes, and a decoder that forgets hands four bytes of zeroes to the TCP layer.
DecodeStatus decode_ipv4(ByteView pkt, Ipv4Header& out, ByteView& payload);

/// Decodes a TCP segment. `payload` is everything past the header, options
/// included in the header as the data offset describes.
DecodeStatus decode_tcp(ByteView seg, TcpHeader& out, ByteView& payload);

/// Decodes a UDP datagram. `payload` is clipped to the length field when that is
/// shorter than what was captured.
DecodeStatus decode_udp(ByteView seg, UdpHeader& out, ByteView& payload);

/// Dotted quad, for display only.
std::string ipv4_to_string(uint32_t addr);

/// "SYN,ACK" / "FIN,ACK" / "-" -- for session and trace output.
std::string tcp_flags_to_string(uint8_t flags);

}  // namespace nano
