#pragma once

#include <string>

#include "byteview.h"

namespace nano {

// ---------------------------------------------------------------------------
// App-ID: identify the application from the payload, not the port.
//
// This is the feature that separates a next-generation firewall from a packet
// filter, and it is the idea Palo Alto was founded on. Port-based filtering
// answers "is this traffic to 443?" -- a question anyone can lie about by moving
// a service. App-ID answers "what protocol is actually being spoken?", which is
// much harder to fake because it requires speaking the protocol.
//
// Classification is latched rather than recomputed. Once the application is
// decided it stays decided, because re-deciding on every packet would let a
// session flip identity mid-stream -- a real evasion, and an easy one if the
// classifier is stateless.
// ---------------------------------------------------------------------------

/// Applications this classifier knows, using the names PAN-OS uses.
namespace app {
constexpr const char* kWebBrowsing = "web-browsing";
constexpr const char* kSsl         = "ssl";
constexpr const char* kDns         = "dns";
constexpr const char* kSsh         = "ssh";
constexpr const char* kUnknown     = "unknown";

/// The handshake never completed, so no payload was ever seen.
constexpr const char* kIncomplete = "incomplete";

/// Established, but too few payload bytes so far to decide. Both of these are
/// real PAN-OS session states, and they are worth reproducing because "what does
/// your firewall show before it knows?" has a specific answer.
constexpr const char* kInsufficientData = "insufficient-data";
}  // namespace app

/// What one classification attempt produced.
struct AppIdResult {
    /// Empty when this attempt could not decide and more data may help.
    std::string application;

    /// Server Name Indication, when the payload was a TLS ClientHello. Copied out
    /// of the packet because it must outlive the frame.
    std::string sni;

    /// True when the payload is definitively not something we recognise, so
    /// waiting for more bytes is pointless.
    bool exhausted = false;
};

/// Classifies a payload.
///
/// `dst_port` is used only as a tiebreak for protocols with no distinctive
/// preamble -- DNS being the obvious one, since a query has no magic bytes.
/// Everything else is decided on content, which is what makes the ssh-on-443
/// case work.
AppIdResult classify(ByteView payload, uint8_t proto, uint16_t dst_port);

/// Extracts the SNI hostname from a TLS ClientHello.
///
/// Broken out because it is the fiddliest parsing in the project and gets its own
/// fuzz target. The shape -- read a length, trust it, jump -- is the single most
/// reliably exploitable pattern in network code, and this function walks four
/// nested length-prefixed structures to reach the hostname.
///
/// Returns false if the payload is not a ClientHello or carries no SNI extension.
bool extract_sni(ByteView payload, std::string& sni);

}  // namespace nano
