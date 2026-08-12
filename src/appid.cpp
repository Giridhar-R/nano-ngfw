#include "appid.h"

#include "decode.h"

namespace nano {
namespace {

bool starts_with(ByteView v, const char* literal) {
    size_t n = 0;
    while (literal[n] != '\0') ++n;
    if (!v.has(0, n)) return false;
    for (size_t i = 0; i < n; ++i) {
        if (v.u8(i) != static_cast<uint8_t>(literal[i])) return false;
    }
    return true;
}

/// HTTP is recognised by its request line, not by port 80.
bool looks_like_http(ByteView v) {
    static const char* kMethods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
                                     "OPTIONS ", "PATCH ", "CONNECT "};
    for (const char* method : kMethods) {
        if (starts_with(v, method)) return true;
    }
    return false;
}

/// A DNS message has no magic number, so this checks shape instead: a sane flags
/// field, exactly one question, and a question name that parses as a sequence of
/// length-prefixed labels ending in a zero byte.
///
/// The weakest signature here, which is why it is also the only one gated on a
/// port. Claiming to identify DNS on an arbitrary port from these bytes alone
/// would produce false positives on anything binary.
bool looks_like_dns(ByteView v) {
    if (!v.has(0, 12)) return false;

    const uint16_t flags     = v.u16(2);
    const uint16_t questions = v.u16(4);
    if (questions != 1) return false;

    // Opcode must be one of the defined values; the reserved Z bits must be zero.
    const uint16_t opcode = static_cast<uint16_t>((flags >> 11) & 0x0f);
    if (opcode > 5) return false;

    size_t offset = 12;
    for (int label = 0; label < 128; ++label) {
        if (!v.has(offset, 1)) return false;
        const uint8_t len = v.u8(offset);
        if (len == 0) return v.has(offset + 1, 4);  // qtype + qclass follow
        if (len > 63) return false;                 // compression pointer or junk
        offset += static_cast<size_t>(len) + 1;
    }
    return false;
}

}  // namespace

bool extract_sni(ByteView payload, std::string& sni) {
    // TLS record header: content type, version, length.
    if (!payload.has(0, 5)) return false;
    if (payload.u8(0) != 0x16) return false;  // handshake

    const size_t record_len = payload.u16(3);
    // Bound the walk by the record length or the bytes we actually have,
    // whichever is smaller. Trusting record_len alone is the bug this whole
    // function is a lesson in.
    const size_t available = payload.size() - 5;
    const size_t limit     = 5 + (record_len < available ? record_len : available);

    size_t off = 5;
    if (off + 4 > limit) return false;
    if (payload.u8(off) != 0x01) return false;  // ClientHello

    // 24-bit handshake length, then the body.
    off += 4;

    // client_version (2) + random (32)
    if (off + 34 > limit) return false;
    off += 34;

    // session_id
    if (off + 1 > limit) return false;
    const size_t session_id_len = payload.u8(off);
    off += 1 + session_id_len;

    // cipher_suites
    if (off + 2 > limit) return false;
    const size_t cipher_len = payload.u16(off);
    off += 2 + cipher_len;

    // compression_methods
    if (off + 1 > limit) return false;
    const size_t compression_len = payload.u8(off);
    off += 1 + compression_len;

    // extensions block
    if (off + 2 > limit) return false;
    const size_t extensions_len = payload.u16(off);
    off += 2;

    const size_t extensions_end =
        (off + extensions_len < limit) ? off + extensions_len : limit;

    while (off + 4 <= extensions_end) {
        const uint16_t ext_type = payload.u16(off);
        const size_t   ext_len  = payload.u16(off + 2);
        off += 4;

        if (off + ext_len > extensions_end) return false;

        if (ext_type == 0x0000) {  // server_name
            // server_name_list length (2), then entries of
            // type (1) + length (2) + name.
            if (ext_len < 5) return false;

            size_t p = off + 2;  // skip the list length
            const size_t list_end = off + ext_len;

            while (p + 3 <= list_end) {
                const uint8_t name_type = payload.u8(p);
                const size_t  name_len  = payload.u16(p + 1);
                p += 3;

                if (p + name_len > list_end) return false;

                if (name_type == 0) {  // host_name
                    sni.clear();
                    sni.reserve(name_len);
                    for (size_t i = 0; i < name_len; ++i) {
                        const uint8_t c = payload.u8(p + i);
                        // Hostnames are ASCII. Anything else is either an
                        // encoding trick or corruption; refuse rather than
                        // copy control bytes into a string that gets printed.
                        if (c < 0x20 || c > 0x7e) return false;
                        sni.push_back(static_cast<char>(c));
                    }
                    return !sni.empty();
                }
                p += name_len;
            }
            return false;
        }

        off += ext_len;
    }

    return false;
}

AppIdResult classify(ByteView payload, uint8_t proto, uint16_t dst_port) {
    AppIdResult result;
    if (payload.empty()) return result;

    if (proto == static_cast<uint8_t>(IpProto::Udp)) {
        if ((dst_port == 53 || dst_port == 5353) && looks_like_dns(payload)) {
            result.application = app::kDns;
            return result;
        }
        result.exhausted = true;
        return result;
    }

    // --- TCP ---------------------------------------------------------------

    if (looks_like_http(payload)) {
        result.application = app::kWebBrowsing;
        return result;
    }

    // SSH announces itself in cleartext before anything is negotiated, which is
    // what makes captures/ssh_on_443 identifiable at all.
    if (starts_with(payload, "SSH-")) {
        result.application = app::kSsh;
        return result;
    }

    if (payload.u8(0) == 0x16) {  // TLS handshake record
        result.application = app::kSsl;
        extract_sni(payload, result.sni);  // absence is not a failure
        return result;
    }

    if (dst_port == 53 && looks_like_dns(payload)) {
        result.application = app::kDns;
        return result;
    }

    // A payload we have seen and cannot place. Distinct from "no payload yet":
    // more bytes will not help, so the caller can stop waiting.
    result.exhausted = true;
    return result;
}

}  // namespace nano
