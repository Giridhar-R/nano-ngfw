#include <cstdio>
#include <string>

#include "pcap.h"
#include "version.h"

namespace {

int usage() {
    std::printf("nano-ngfw %s\n\n", nano::version());
    std::printf("usage: nano-ngfw <capture.pcap>\n");
    return 2;
}

const char* link_name(nano::LinkType t) {
    switch (t) {
        case nano::LinkType::Ethernet: return "ethernet";
        case nano::LinkType::RawIp:    return "raw-ip";
        default:                       return "unsupported";
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) return usage();

    nano::PcapReader reader;
    std::string      err;
    if (!reader.open(argv[1], err)) {
        std::fprintf(stderr, "nano-ngfw: %s\n", err.c_str());
        return 1;
    }

    nano::ByteView frame;
    uint64_t       ts = 0, first = 0, last = 0;
    uint64_t       bytes = 0;

    while (reader.next(frame, ts)) {
        if (reader.records_read() == 1) first = ts;
        last = ts;
        bytes += frame.size();
    }

    std::printf("file        %s\n", argv[1]);
    std::printf("link type   %s\n", link_name(reader.link_type()));
    std::printf("snaplen     %u\n", reader.snaplen());
    std::printf("packets     %llu\n", static_cast<unsigned long long>(reader.records_read()));
    std::printf("bytes       %llu\n", static_cast<unsigned long long>(bytes));
    if (reader.records_read() > 0) {
        std::printf("duration    %.6f s\n", static_cast<double>(last - first) / 1e6);
    }
    if (reader.truncated()) {
        std::printf("warning     capture ends mid-record\n");
    }
    return 0;
}
