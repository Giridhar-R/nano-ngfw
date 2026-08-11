#include <cstdio>
#include <cstring>
#include <string>

#include "cli.h"
#include "engine.h"
#include "pcap.h"
#include "version.h"

namespace {

int usage() {
    std::printf("nano-ngfw %s\n\n", nano::version());
    std::printf("usage: nano-ngfw [options] <capture.pcap>\n\n");
    std::printf("  --midstream        adopt sessions from non-SYN packets\n");
    std::printf("  --session <id>     print one session in detail\n");
    std::printf("  --stats-only       suppress the session table\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    const char* path        = nullptr;
    bool        midstream   = false;
    bool        stats_only  = false;
    long        detail_id   = -1;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (std::strcmp(arg, "--midstream") == 0) {
            midstream = true;
        } else if (std::strcmp(arg, "--stats-only") == 0) {
            stats_only = true;
        } else if (std::strcmp(arg, "--session") == 0 && i + 1 < argc) {
            detail_id = std::strtol(argv[++i], nullptr, 10);
        } else if (arg[0] == '-') {
            return usage();
        } else {
            path = arg;
        }
    }
    if (path == nullptr) return usage();

    nano::PcapReader reader;
    std::string      err;
    if (!reader.open(path, err)) {
        std::fprintf(stderr, "nano-ngfw: %s\n", err.c_str());
        return 1;
    }

    nano::Engine engine;
    engine.set_midstream(midstream);

    nano::ByteView frame;
    uint64_t       ts = 0, last = 0;
    while (reader.next(frame, ts)) {
        engine.process(frame, ts);
        last = ts;
    }
    engine.finish(last);

    if (detail_id >= 0) {
        nano::print_session_detail(stdout, engine, static_cast<uint32_t>(detail_id));
        return 0;
    }

    if (!stats_only) {
        nano::print_sessions(stdout, engine);
        std::printf("\n");
    }
    nano::print_stats(stdout, engine);

    if (reader.truncated()) {
        std::printf("\nwarning: capture ends mid-record\n");
    }
    return 0;
}
