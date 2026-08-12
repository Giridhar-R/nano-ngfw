#include <cstdint>
#include <string>
#include <vector>

#include "appid.h"
#include "engine.h"
#include "harness.h"
#include "pcap.h"

using namespace nano;

namespace {

constexpr uint8_t kTcp = 6;
constexpr uint8_t kUdp = 17;

std::string cap(const char* name) { return std::string(NANO_CAPTURES_DIR) + "/" + name; }

ByteView view_of(const std::vector<uint8_t>& v) { return ByteView(v.data(), v.size()); }

std::vector<uint8_t> bytes_of(const char* s) {
    std::vector<uint8_t> out;
    for (const char* p = s; *p != '\0'; ++p) out.push_back(static_cast<uint8_t>(*p));
    return out;
}

bool run(Engine& e, const char* name) {
    PcapReader  r;
    std::string err;
    if (!r.open(cap(name), err)) return false;

    ByteView frame;
    uint64_t ts = 0, last = 0;
    while (r.next(frame, ts)) { e.process(frame, ts); last = ts; }
    e.finish(last);
    return true;
}

// --- classification in isolation ------------------------------------------

void test_http_is_recognised_by_its_request_line() {
    for (const char* request : {"GET / HTTP/1.1\r\n", "POST /x HTTP/1.1\r\n",
                                "HEAD / HTTP/1.0\r\n"}) {
        const auto payload = bytes_of(request);
        // Note the port: 8080, not 80. Identification is by content.
        const auto result = classify(view_of(payload), kTcp, 8080);
        CHECK_EQ(result.application, std::string(app::kWebBrowsing));
    }
}

void test_ssh_is_recognised_by_its_banner() {
    const auto payload = bytes_of("SSH-2.0-OpenSSH_9.6p1\r\n");
    const auto result  = classify(view_of(payload), kTcp, 443);
    CHECK_EQ(result.application, std::string(app::kSsh));
}

/// DNS is the weakest signature here and the only one still gated on a port.
///
/// A query has no magic bytes, so classification checks structural plausibility
/// instead -- one question, a sane opcode, and a QNAME that parses as
/// length-prefixed labels. That is not strong enough to claim on an arbitrary
/// port without inviting false positives on anything binary, which is why the
/// port still matters here and nowhere else.
void test_dns_is_shape_plus_port() {
    std::vector<uint8_t> query = {
        0x12, 0x34,              // transaction id
        0x01, 0x00,              // standard query, recursion desired
        0x00, 0x01,              // one question
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 'w', 'w', 'w',
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        0x03, 'c', 'o', 'm',
        0x00,                    // end of name
        0x00, 0x01, 0x00, 0x01,  // qtype A, qclass IN
    };

    CHECK_EQ(classify(view_of(query), kUdp, 53).application, std::string(app::kDns));

    // Same bytes, non-standard port: not claimed.
    CHECK(classify(view_of(query), kUdp, 9999).application.empty());

    // Right port, payload that is not a DNS message.
    const auto junk = bytes_of("this is not dns");
    CHECK(classify(view_of(junk), kUdp, 53).application.empty());
}

void test_unrecognised_payload_is_exhausted_not_pending() {
    const auto payload = bytes_of("\x01\x02\x03 random bytes that are nothing");
    const auto result  = classify(view_of(payload), kTcp, 9999);
    CHECK(result.application.empty());
    CHECK(result.exhausted);   // more bytes will not help
}

void test_empty_payload_is_pending() {
    const auto result = classify(ByteView(), kTcp, 443);
    CHECK(result.application.empty());
    CHECK(!result.exhausted);  // nothing seen yet; keep waiting
}

// --- the TLS ClientHello walk ---------------------------------------------

/// Builds a minimal ClientHello carrying one SNI extension, matching what
/// tests/make_fixtures.py emits.
std::vector<uint8_t> client_hello(const std::string& host) {
    std::vector<uint8_t> sni_ext;
    sni_ext.push_back(0x00);                                          // host_name
    sni_ext.push_back(static_cast<uint8_t>(host.size() >> 8));
    sni_ext.push_back(static_cast<uint8_t>(host.size() & 0xff));
    for (char c : host) sni_ext.push_back(static_cast<uint8_t>(c));

    std::vector<uint8_t> ext_body;
    ext_body.push_back(static_cast<uint8_t>(sni_ext.size() >> 8));
    ext_body.push_back(static_cast<uint8_t>(sni_ext.size() & 0xff));
    ext_body.insert(ext_body.end(), sni_ext.begin(), sni_ext.end());

    std::vector<uint8_t> extensions;
    extensions.push_back(0x00); extensions.push_back(0x00);           // type 0
    extensions.push_back(static_cast<uint8_t>(ext_body.size() >> 8));
    extensions.push_back(static_cast<uint8_t>(ext_body.size() & 0xff));
    extensions.insert(extensions.end(), ext_body.begin(), ext_body.end());

    std::vector<uint8_t> body;
    body.push_back(0x03); body.push_back(0x03);                       // TLS 1.2
    for (int i = 0; i < 32; ++i) body.push_back(static_cast<uint8_t>(i));
    body.push_back(0x00);                                             // session id
    body.push_back(0x00); body.push_back(0x02);                       // cipher len
    body.push_back(0x13); body.push_back(0x01);
    body.push_back(0x01); body.push_back(0x00);                       // compression
    body.push_back(static_cast<uint8_t>(extensions.size() >> 8));
    body.push_back(static_cast<uint8_t>(extensions.size() & 0xff));
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<uint8_t> handshake;
    handshake.push_back(0x01);                                        // ClientHello
    handshake.push_back(0x00);
    handshake.push_back(static_cast<uint8_t>(body.size() >> 8));
    handshake.push_back(static_cast<uint8_t>(body.size() & 0xff));
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<uint8_t> record;
    record.push_back(0x16); record.push_back(0x03); record.push_back(0x01);
    record.push_back(static_cast<uint8_t>(handshake.size() >> 8));
    record.push_back(static_cast<uint8_t>(handshake.size() & 0xff));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

void test_sni_extraction() {
    const auto  hello = client_hello("www.example.com");
    std::string sni;
    CHECK(extract_sni(view_of(hello), sni));
    CHECK_EQ(sni, std::string("www.example.com"));

    const auto result = classify(view_of(hello), kTcp, 443);
    CHECK_EQ(result.application, std::string(app::kSsl));
    CHECK_EQ(result.sni, std::string("www.example.com"));
}

/// Every truncation of a valid ClientHello must fail cleanly rather than read
/// past the end. This is the unit-test companion to the fuzz target: the fuzzer
/// explores arbitrary bytes, this pins the specific shape that matters.
void test_truncated_client_hello_never_overreads() {
    const auto hello = client_hello("www.example.com");
    for (size_t len = 0; len < hello.size(); ++len) {
        std::string sni;
        extract_sni(ByteView(hello.data(), len), sni);   // must not crash
    }
}

/// A length field claiming more than the record holds. The archetypal bug in
/// this shape of parser.
void test_lying_extension_length_is_refused() {
    auto hello = client_hello("www.example.com");

    // Find the extensions block and inflate the SNI extension's length.
    // Byte layout puts the extension type two bytes before its length.
    for (size_t i = 0; i + 4 < hello.size(); ++i) {
        if (hello[i] == 0x00 && hello[i + 1] == 0x00 &&
            hello[i + 2] == 0x00 && hello[i + 3] > 0x00 && hello[i + 3] < 0x40) {
            hello[i + 2] = 0x7f;   // extension length now vastly exceeds the record
            hello[i + 3] = 0xff;
            break;
        }
    }

    std::string sni;
    CHECK(!extract_sni(view_of(hello), sni));
}

void test_non_ascii_hostname_is_refused() {
    auto hello = client_hello("www.example.com");
    for (size_t i = 0; i + 3 < hello.size(); ++i) {
        if (hello[i] == 'w' && hello[i + 1] == 'w' && hello[i + 2] == 'w') {
            hello[i] = 0x01;   // a control byte where a hostname character belongs
            break;
        }
    }
    std::string sni;
    CHECK(!extract_sni(view_of(hello), sni));
}

void test_not_a_client_hello() {
    std::string sni;
    const auto  application_data = bytes_of("\x17\x03\x03\x00\x10 encrypted");
    CHECK(!extract_sni(view_of(application_data), sni));
    CHECK(!extract_sni(ByteView(), sni));
}

// --- driven by captures ----------------------------------------------------

void test_capture_http() {
    Engine e;
    CHECK(run(e, "http_get.pcap"));
    CHECK_EQ(e.flows().size(), 1u);
    CHECK_EQ(std::string(e.flows().get(0).app_display()), std::string(app::kWebBrowsing));
}

void test_capture_tls_sni() {
    Engine e;
    CHECK(run(e, "tls_sni.pcap"));
    const Session& s = e.flows().get(0);
    CHECK_EQ(std::string(s.app_display()), std::string(app::kSsl));
    CHECK_EQ(s.sni, std::string("www.google.com"));
}

void test_capture_dns() {
    Engine e;
    CHECK(run(e, "udp_dns.pcap"));
    CHECK_EQ(std::string(e.flows().get(0).app_display()), std::string(app::kDns));
}

/// A handshake that never completed carries no payload, so there is nothing to
/// classify -- and "incomplete" is the honest answer rather than "unknown".
void test_incomplete_session_reports_incomplete() {
    Engine e;
    CHECK(run(e, "syn_retransmit.pcap"));
    CHECK_EQ(std::string(e.flows().get(0).app_display()), std::string(app::kIncomplete));
}

/// The whole point. Admitted on port 443 by a rule for web traffic, identified as
/// ssh once the banner arrives, re-judged, and torn down.
void test_app_id_shift() {
    Engine      e;
    std::string err;
    CHECK(e.policy().parse(R"(
zone trust   192.168.0.0/16
zone untrust 0.0.0.0/0
rule allow-web from trust to untrust service tcp/80,tcp/443 application web-browsing,ssl action allow
)",
                           err));

    CHECK(run(e, "ssh_on_443.pcap"));

    const Session& s = e.flows().get(0);
    CHECK_EQ(std::string(s.app_display()), std::string(app::kSsh));
    CHECK(s.app_shifted);
    CHECK(s.verdict == Verdict::Deny);
    CHECK_EQ(s.matched_rule, Policy::kDefaultDeny);
    CHECK(s.state == SessionState::Closed);
    CHECK_EQ(e.counters().app_shifts, 1ull);
}

/// The control: genuine TLS on the same port, under the same rule, keeps it.
void test_no_shift_for_real_tls() {
    Engine      e;
    std::string err;
    CHECK(e.policy().parse(R"(
zone trust   192.168.0.0/16
zone untrust 0.0.0.0/0
rule allow-web from trust to untrust service tcp/80,tcp/443 application web-browsing,ssl action allow
)",
                           err));

    CHECK(run(e, "tls_sni.pcap"));

    const Session& s = e.flows().get(0);
    CHECK(!s.app_shifted);
    CHECK(s.verdict == Verdict::Allow);
    CHECK_EQ(e.counters().app_shifts, 0ull);
}

}  // namespace

int main() {
    test_http_is_recognised_by_its_request_line();
    test_ssh_is_recognised_by_its_banner();
    test_dns_is_shape_plus_port();
    test_unrecognised_payload_is_exhausted_not_pending();
    test_empty_payload_is_pending();

    test_sni_extraction();
    test_truncated_client_hello_never_overreads();
    test_lying_extension_length_is_refused();
    test_non_ascii_hostname_is_refused();
    test_not_a_client_hello();

    test_capture_http();
    test_capture_tls_sni();
    test_capture_dns();
    test_incomplete_session_reports_incomplete();
    test_app_id_shift();
    test_no_shift_for_real_tls();
    return nano::test::summary("appid");
}
