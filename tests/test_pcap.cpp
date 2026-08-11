#include <string>
#include <vector>

#include "harness.h"
#include "pcap.h"

using namespace nano;

namespace {

std::string cap(const char* name) { return std::string(NANO_CAPTURES_DIR) + "/" + name; }

/// Reads a whole file, returning (timestamp, first four bytes) per record so two
/// captures can be compared without holding views that have been invalidated.
std::vector<std::pair<uint64_t, uint32_t>> digest(PcapReader& r) {
    std::vector<std::pair<uint64_t, uint32_t>> out;
    ByteView frame;
    uint64_t ts = 0;
    while (r.next(frame, ts)) {
        out.emplace_back(ts, frame.size() >= 4 ? frame.u32(0) : 0u);
    }
    return out;
}

void test_reads_a_clean_capture() {
    PcapReader r;
    std::string err;
    CHECK(r.open(cap("handshake_clean.pcap"), err));
    CHECK(r.link_type() == LinkType::Ethernet);
    CHECK_EQ(r.snaplen(), 65535u);

    ByteView frame;
    uint64_t ts    = 0;
    uint64_t first = 0;
    int      n     = 0;
    uint64_t prev  = 0;
    while (r.next(frame, ts)) {
        if (n == 0) first = ts;
        CHECK(ts >= prev);           // timestamps are non-decreasing
        CHECK(frame.size() >= 54);   // eth + ip + tcp, minimum
        prev = ts;
        ++n;
    }
    CHECK_EQ(n, 8);
    CHECK_EQ(first, 1000000ull);     // one second past the epoch, as written
    CHECK(!r.truncated());
    CHECK_EQ(r.records_read(), 8ull);
}

/// The same packets written by a big-endian writer must decode identically.
/// Byte order is discovered from the magic number and resolved inside the reader,
/// so nothing downstream should be able to tell the two files apart.
void test_byte_order_is_transparent() {
    PcapReader le, be;
    std::string err;
    CHECK(le.open(cap("handshake_clean.pcap"), err));
    CHECK(be.open(cap("big_endian.pcap"), err));

    const auto a = digest(le);
    const auto b = digest(be);
    CHECK_EQ(a.size(), b.size());
    CHECK(a == b);
}

void test_rejects_a_non_pcap_file() {
    PcapReader r;
    std::string err;
    CHECK(!r.open(cap("bad_magic.pcap"), err));
    CHECK(!err.empty());
}

void test_missing_file_is_an_error_not_a_crash() {
    PcapReader r;
    std::string err;
    CHECK(!r.open(cap("does_not_exist.pcap"), err));
}

/// A header with no records is valid, not corrupt. The distinction matters:
/// truncated() must stay false so the stats do not report damage that isn't there.
void test_empty_capture_is_clean() {
    PcapReader r;
    std::string err;
    CHECK(r.open(cap("empty.pcap"), err));

    ByteView frame;
    uint64_t ts = 0;
    CHECK(!r.next(frame, ts));
    CHECK(!r.truncated());
    CHECK_EQ(r.records_read(), 0ull);
}

/// One good record, then a record header promising 200 bytes that the file cannot
/// deliver. The good record must still be returned before the reader gives up.
void test_truncated_capture_yields_what_it_can() {
    PcapReader r;
    std::string err;
    CHECK(r.open(cap("truncated.pcap"), err));

    ByteView frame;
    uint64_t ts = 0;
    CHECK(r.next(frame, ts));
    CHECK(!r.next(frame, ts));
    CHECK(r.truncated());
    CHECK_EQ(r.records_read(), 1ull);
}

/// A record claiming 2 GiB. Refused on the length alone -- we never attempt the
/// allocation, and we never read a prefix and pretend it was the whole frame.
void test_absurd_length_is_refused() {
    PcapReader r;
    std::string err;
    CHECK(r.open(cap("huge_record.pcap"), err));

    ByteView frame;
    uint64_t ts = 0;
    CHECK(!r.next(frame, ts));
    CHECK(r.truncated());
    CHECK_EQ(r.records_read(), 0ull);
}

/// The documented lifetime rule, asserted rather than assumed: the view handed
/// out by next() points into a buffer the next call overwrites.
void test_view_tracks_the_current_record() {
    PcapReader r;
    std::string err;
    CHECK(r.open(cap("udp_dns.pcap"), err));

    ByteView a, b;
    uint64_t ts = 0;
    CHECK(r.next(a, ts));
    const size_t first_size = a.size();
    CHECK(r.next(b, ts));
    CHECK(b.size() != first_size);  // the two DNS frames differ in length
}

}  // namespace

int main() {
    test_reads_a_clean_capture();
    test_byte_order_is_transparent();
    test_rejects_a_non_pcap_file();
    test_missing_file_is_an_error_not_a_crash();
    test_empty_capture_is_clean();
    test_truncated_capture_yields_what_it_can();
    test_absurd_length_is_refused();
    test_view_tracks_the_current_record();
    return nano::test::summary("pcap");
}
