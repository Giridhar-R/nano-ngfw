#include <cstdio>
#include <cstring>
#include <string>

#include "cli.h"
#include "engine.h"
#include "pcap.h"
#include "report.h"
#include "version.h"

namespace {

int usage() {
    std::printf("nano-ngfw %s\n\n", nano::version());
    std::printf("usage: nano-ngfw [options] <capture.pcap>\n\n");
    std::printf("  --policy <file>    load a rule base (default: built-in)\n");
    std::printf("  --nat <ip>         source-NAT allowed trust->untrust sessions\n");
    std::printf("  --midstream        adopt sessions from non-SYN packets\n");
    std::printf("  --session <id>     print one session in detail\n");
    std::printf("  --stats-only       suppress the session table\n");
    std::printf("  --html <file>      write a self-contained HTML session report\n");
    return 2;
}

/// Dotted quad to host-order u32. Returns 0 on anything malformed, which the
/// caller treats as "no NAT". Hand-parsed rather than via sscanf, which MSVC
/// deprecates and this build treats as an error.
uint32_t parse_ip(const char* text) {
    uint32_t addr = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (octet > 0) {
            if (*text != '.') return 0;
            ++text;
        }
        if (*text < '0' || *text > '9') return 0;

        unsigned value = 0;
        while (*text >= '0' && *text <= '9') {
            value = value * 10 + static_cast<unsigned>(*text - '0');
            if (value > 255) return 0;
            ++text;
        }
        addr = (addr << 8) | value;
    }
    return *text == '\0' ? addr : 0;
}

}  // namespace

int main(int argc, char** argv) {
    const char* path        = nullptr;
    const char* policy_path = nullptr;
    const char* html_path   = nullptr;
    uint32_t    nat_ip      = 0;
    bool        midstream   = false;
    bool        stats_only  = false;
    long        detail_id   = -1;

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (std::strcmp(arg, "--midstream") == 0) {
            midstream = true;
        } else if (std::strcmp(arg, "--stats-only") == 0) {
            stats_only = true;
        } else if (std::strcmp(arg, "--policy") == 0 && i + 1 < argc) {
            policy_path = argv[++i];
        } else if (std::strcmp(arg, "--nat") == 0 && i + 1 < argc) {
            nat_ip = parse_ip(argv[++i]);
        } else if (std::strcmp(arg, "--html") == 0 && i + 1 < argc) {
            html_path = argv[++i];
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

    if (policy_path != nullptr) {
        std::string policy_err;
        if (!engine.policy().load_file(policy_path, policy_err)) {
            std::fprintf(stderr, "nano-ngfw: %s\n", policy_err.c_str());
            return 1;
        }
    }
    if (nat_ip != 0) {
        engine.set_nat(nano::NatPool(nat_ip));
    }

    nano::ByteView frame;
    uint64_t       ts = 0, last = 0;
    while (reader.next(frame, ts)) {
        engine.process(frame, ts);
        last = ts;
    }
    engine.finish(last);

    if (html_path != nullptr) {
        if (!nano::write_html_report(html_path, engine, path,
                                     policy_path != nullptr ? policy_path : "")) {
            std::fprintf(stderr, "nano-ngfw: cannot write %s\n", html_path);
            return 1;
        }
        std::printf("wrote %s\n", html_path);
        return 0;
    }

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
