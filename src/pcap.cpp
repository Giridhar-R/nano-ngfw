#include "pcap.h"

namespace nano {
namespace {

// The four magic numbers a classic pcap file can start with. The value tells us
// two things at once: whether the writer's byte order matches ours, and whether
// the fractional timestamp field counts microseconds or nanoseconds.
constexpr uint32_t kMagicUsSame = 0xa1b2c3d4u;
constexpr uint32_t kMagicUsSwap = 0xd4c3b2a1u;
constexpr uint32_t kMagicNsSame = 0xa1b23c4du;
constexpr uint32_t kMagicNsSwap = 0x4d3cb2a1u;

constexpr size_t kGlobalHeader = 24;
constexpr size_t kRecordHeader = 16;

/// Reads a host-order u32 out of a byte buffer. The global header is read before
/// we know the file's byte order, so it is loaded raw and interpreted after.
uint32_t load32le(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | static_cast<uint32_t>(p[1]) << 8 |
           static_cast<uint32_t>(p[2]) << 16 | static_cast<uint32_t>(p[3]) << 24;
}

uint32_t bswap32(uint32_t v) {
    return (v >> 24) | ((v >> 8) & 0x0000ff00u) | ((v << 8) & 0x00ff0000u) | (v << 24);
}

uint16_t bswap16(uint16_t v) {
    return static_cast<uint16_t>(static_cast<unsigned>(v) >> 8 |
                                 (static_cast<unsigned>(v) & 0xffu) << 8);
}

}  // namespace

uint16_t PcapReader::fix16(uint16_t v) const { return swap_ ? bswap16(v) : v; }
uint32_t PcapReader::fix32(uint32_t v) const { return swap_ ? bswap32(v) : v; }

bool PcapReader::read_exact(size_t n) {
    buf_.resize(n);
    if (n == 0) return true;
    in_.read(reinterpret_cast<char*>(buf_.data()), static_cast<std::streamsize>(n));
    return static_cast<size_t>(in_.gcount()) == n;
}

bool PcapReader::open(const std::string& path, std::string& err) {
    in_.open(path, std::ios::binary);
    if (!in_) {
        err = "cannot open " + path;
        return false;
    }

    if (!read_exact(kGlobalHeader)) {
        err = "file shorter than a pcap global header (24 bytes)";
        return false;
    }

    // Load the magic in a fixed order first; its *value* tells us how to read
    // everything that follows. This is the one place in the project where byte
    // order is discovered rather than known, which is exactly why ByteView has no
    // little-endian accessor -- the ambiguity is resolved here and nowhere else.
    const uint32_t magic = load32le(buf_.data());
    switch (magic) {
        case kMagicUsSame: swap_ = false; nanos_ = false; break;
        case kMagicUsSwap: swap_ = true;  nanos_ = false; break;
        case kMagicNsSame: swap_ = false; nanos_ = true;  break;
        case kMagicNsSwap: swap_ = true;  nanos_ = true;  break;
        default:
            err = "not a pcap file (bad magic number)";
            return false;
    }

    // Bytes 4..19 are version, timezone offset and sigfigs. Nothing downstream
    // uses them: the timezone field was always written as zero in practice, and
    // no version of the format changes the layout we care about.
    snaplen_ = fix32(load32le(buf_.data() + 16));

    const uint32_t net = fix32(load32le(buf_.data() + 20));
    switch (net) {
        case 1:   link_ = LinkType::Ethernet; break;
        case 101: link_ = LinkType::RawIp;    break;
        default:  link_ = LinkType::Other;    break;
    }

    return true;
}

bool PcapReader::next(ByteView& frame, uint64_t& ts_us) {
    if (!read_exact(kRecordHeader)) {
        // Zero bytes here is a clean EOF; anything between 1 and 15 means the
        // file was cut off mid-header.
        if (in_.gcount() != 0) truncated_ = true;
        return false;
    }

    const uint32_t ts_sec  = fix32(load32le(buf_.data()));
    const uint32_t ts_frac = fix32(load32le(buf_.data() + 4));
    const uint32_t incl    = fix32(load32le(buf_.data() + 8));
    // Bytes 12..15 are orig_len, the length on the wire before snaplen truncation.
    // We classify what was actually captured, so incl_len is the one that matters.

    if (incl > kMaxRecord) {
        // Not a length we will honour. Treated as corruption rather than clamped:
        // silently reading a prefix of a bogus record would hand the decoders a
        // frame that never existed.
        truncated_ = true;
        return false;
    }

    if (!read_exact(incl)) {
        truncated_ = true;
        return false;
    }

    ts_us = static_cast<uint64_t>(ts_sec) * 1000000ull +
            (nanos_ ? ts_frac / 1000u : ts_frac);
    frame = ByteView(buf_.data(), buf_.size());
    ++records_;
    return true;
}

}  // namespace nano
