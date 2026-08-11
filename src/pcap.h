#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "byteview.h"

namespace nano {

/// Link-layer types we recognise. The full list is large; these are the two a
/// capture of ordinary traffic will actually carry.
enum class LinkType : uint32_t {
    Ethernet = 1,    ///< LINKTYPE_ETHERNET -- frames start with a 14-byte header
    RawIp    = 101,  ///< LINKTYPE_RAW -- frames start straight at the IP header
    Other    = 0xffffffffu,
};

/// Streaming reader for the classic libpcap file format.
///
/// Why hand-rolled rather than libpcap: the format is a 24-byte global header
/// followed by length-prefixed records, and writing that is a twenty-minute job
/// which happens to teach the two things the rest of the project depends on --
/// where byte order comes from, and what a length field taken off disk can do to
/// you if you trust it.
///
/// Streaming, not slurping
/// -----------------------
/// One record is read at a time into a buffer this object owns and reuses. next()
/// hands out a ByteView over that buffer, so the view is invalidated by the
/// following call to next(). A real dataplane cannot buffer the whole capture,
/// and the lifetime discipline this forces is the point -- see docs/design.md.
///
/// Hostile input
/// -------------
/// incl_len is a 32-bit length read off disk. A corrupt or malicious file can set
/// it to 4 GiB and invite us to allocate that. kMaxRecord caps it: anything larger
/// is treated as corruption and stops the read, rather than being honoured.
class PcapReader {
public:
    /// Largest record we will accept. Well above any real snaplen (a jumbo frame
    /// is ~9 KiB) and far below anything that would hurt to allocate.
    static constexpr uint32_t kMaxRecord = 1u << 20;  // 1 MiB

    PcapReader() = default;

    PcapReader(const PcapReader&)            = delete;
    PcapReader& operator=(const PcapReader&) = delete;

    /// Opens `path` and consumes the global header.
    /// On failure returns false and puts a human-readable reason in `err`.
    bool open(const std::string& path, std::string& err);

    /// Reads the next record.
    ///
    /// Returns false at clean end-of-file and at the first sign of corruption --
    /// use truncated() to tell the two apart afterwards. `frame` is a view over
    /// this object's buffer and stays valid only until the next call.
    /// `ts_us` is microseconds since the Unix epoch, normalised from whichever
    /// resolution the file uses.
    bool next(ByteView& frame, uint64_t& ts_us);

    LinkType link_type() const { return link_; }
    uint32_t snaplen() const { return snaplen_; }

    /// True when the file ended mid-record, i.e. the capture was cut short. Not
    /// an error in itself -- a capture killed with Ctrl-C ends exactly this way --
    /// but the count belongs in the stats output.
    bool     truncated() const { return truncated_; }
    uint64_t records_read() const { return records_; }

private:
    /// Reads `n` bytes into `buf_`, returning false if the file is short.
    bool read_exact(size_t n);

    uint16_t fix16(uint16_t v) const;
    uint32_t fix32(uint32_t v) const;

    std::ifstream        in_;
    std::vector<uint8_t> buf_;
    LinkType             link_      = LinkType::Other;
    uint32_t             snaplen_   = 0;
    bool                 swap_      = false;  ///< file endianness differs from ours
    bool                 nanos_     = false;  ///< fractional field is ns, not us
    bool                 truncated_ = false;
    uint64_t             records_   = 0;
};

}  // namespace nano
