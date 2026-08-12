// Fuzz target for the TLS ClientHello / SNI extension walk.
//
// Separate from fuzz_decode because this is the most dangerous parser in the
// project by some distance. extract_sni walks four nested length-prefixed
// structures -- record, handshake, extension list, server_name list -- and at
// every level the pattern is: read a length somebody else chose, and use it to
// decide where to look next. That shape is the single most reliably exploitable
// thing in network code.
//
// Giving it its own target means libFuzzer spends its whole budget on this
// function rather than on the ninety percent of inputs that never get past the
// Ethernet header.

#include <cstddef>
#include <cstdint>
#include <string>

#include "appid.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    const nano::ByteView payload(data, size);

    std::string sni;
    nano::extract_sni(payload, sni);

    // Also drive the full classifier, which reaches the HTTP, SSH and DNS
    // signatures as well. dst_port is taken from the input so the port-gated
    // paths are reachable rather than dead.
    const uint16_t port = size >= 2
                              ? static_cast<uint16_t>((data[0] << 8) | data[1])
                              : uint16_t{443};
    nano::classify(payload, 6, port);
    nano::classify(payload, 17, port);

    return 0;
}
