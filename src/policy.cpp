#include "policy.h"

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace nano {
namespace {

std::vector<std::string> split(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::string              item;
    std::istringstream       in(s);
    while (std::getline(in, item, sep)) {
        if (!item.empty()) out.push_back(item);
    }
    return out;
}

/// "192.168.1.0/24" -> network and prefix length.
bool parse_cidr(const std::string& text, uint32_t& network, uint8_t& prefix) {
    const size_t slash = text.find('/');
    if (slash == std::string::npos) return false;

    const auto octets = split(text.substr(0, slash), '.');
    if (octets.size() != 4) return false;

    uint32_t addr = 0;
    for (const auto& octet : octets) {
        const long value = std::strtol(octet.c_str(), nullptr, 10);
        if (value < 0 || value > 255) return false;
        addr = (addr << 8) | static_cast<uint32_t>(value);
    }

    const long bits = std::strtol(text.substr(slash + 1).c_str(), nullptr, 10);
    if (bits < 0 || bits > 32) return false;

    network = addr;
    prefix  = static_cast<uint8_t>(bits);
    return true;
}

/// "tcp/443" or "udp/53" or "any".
bool parse_service(const std::string& text, Service& out) {
    if (text == "any") {
        out.proto = 0;
        out.port  = 0;
        return true;
    }

    const size_t slash = text.find('/');
    if (slash == std::string::npos) return false;

    const std::string proto = text.substr(0, slash);
    if (proto == "tcp")      out.proto = 6;
    else if (proto == "udp") out.proto = 17;
    else                     return false;

    const std::string port = text.substr(slash + 1);
    if (port == "any") {
        out.port = 0;
        return true;
    }

    const long value = std::strtol(port.c_str(), nullptr, 10);
    if (value <= 0 || value > 65535) return false;
    out.port = static_cast<uint16_t>(value);
    return true;
}

}  // namespace

const char* to_string(Zone z) {
    switch (z) {
        case Zone::Trust:   return "trust";
        case Zone::Untrust: return "untrust";
        case Zone::Dmz:     return "dmz";
        case Zone::Any:     return "any";
    }
    return "any";
}

bool zone_from_string(const std::string& s, Zone& out) {
    if (s == "trust")        out = Zone::Trust;
    else if (s == "untrust") out = Zone::Untrust;
    else if (s == "dmz")     out = Zone::Dmz;
    else if (s == "any")     out = Zone::Any;
    else return false;
    return true;
}

const char* to_string(Verdict v) {
    switch (v) {
        case Verdict::Allow: return "allow";
        case Verdict::Deny:  return "deny";
        case Verdict::Drop:  return "drop";
    }
    return "?";
}

bool verdict_from_string(const std::string& s, Verdict& out) {
    if (s == "allow")      out = Verdict::Allow;
    else if (s == "deny")  out = Verdict::Deny;
    else if (s == "drop")  out = Verdict::Drop;
    else return false;
    return true;
}

void Policy::load_default() {
    std::string err;
    parse(R"(
# Built-in policy. RFC 1918 is trusted, everything else is not.
zone trust   10.0.0.0/8
zone trust   172.16.0.0/12
zone trust   192.168.0.0/16
zone untrust 0.0.0.0/0

rule allow-outbound  from trust to untrust  service any  action allow
rule deny-inbound    from untrust to trust  service any  action drop
)",
          err);
}

bool Policy::load_file(const std::string& path, std::string& err) {
    std::ifstream in(path);
    if (!in) {
        err = "cannot open policy file " + path;
        return false;
    }
    std::ostringstream text;
    text << in.rdbuf();
    return parse(text.str(), err);
}

bool Policy::parse(const std::string& text, std::string& err) {
    rules_.clear();
    zones_.clear();

    std::istringstream in(text);
    std::string        line;
    int                lineno = 0;

    while (std::getline(in, line)) {
        ++lineno;

        // Strip comments and skip blanks.
        const size_t hash = line.find('#');
        if (hash != std::string::npos) line = line.substr(0, hash);

        std::istringstream        fields(line);
        std::vector<std::string>  token;
        std::string               word;
        while (fields >> word) token.push_back(word);
        if (token.empty()) continue;

        const auto fail = [&](const std::string& why) {
            err = "policy line " + std::to_string(lineno) + ": " + why;
            return false;
        };

        if (token[0] == "zone") {
            if (token.size() != 3) return fail("expected: zone <name> <cidr>");
            ZoneRoute route;
            if (!zone_from_string(token[1], route.zone)) return fail("unknown zone " + token[1]);
            if (!parse_cidr(token[2], route.network, route.prefix))
                return fail("bad cidr " + token[2]);
            zones_.push_back(route);
            continue;
        }

        if (token[0] != "rule") return fail("unexpected keyword " + token[0]);
        if (token.size() < 2) return fail("rule needs a name");

        Rule rule;
        rule.name = token[1];

        for (size_t i = 2; i + 1 < token.size(); i += 2) {
            const std::string& key   = token[i];
            const std::string& value = token[i + 1];

            if (key == "from") {
                if (!zone_from_string(value, rule.from)) return fail("unknown zone " + value);
            } else if (key == "to") {
                if (!zone_from_string(value, rule.to)) return fail("unknown zone " + value);
            } else if (key == "service") {
                if (value != "any") {
                    for (const auto& spec : split(value, ',')) {
                        Service svc;
                        if (!parse_service(spec, svc)) return fail("bad service " + spec);
                        rule.services.push_back(svc);
                    }
                }
            } else if (key == "application") {
                if (value != "any") {
                    for (const auto& app : split(value, ',')) rule.applications.push_back(app);
                }
            } else if (key == "action") {
                if (!verdict_from_string(value, rule.action)) return fail("bad action " + value);
            } else {
                return fail("unknown keyword " + key);
            }
        }

        rules_.push_back(rule);
    }

    return true;
}

Zone Policy::zone_for(uint32_t ip) const {
    Zone best_zone   = Zone::Any;
    int  best_prefix = -1;

    // Longest prefix wins, so declaration order does not matter and a specific
    // subnet always beats the catch-all.
    for (const ZoneRoute& route : zones_) {
        if (route.contains(ip) && static_cast<int>(route.prefix) > best_prefix) {
            best_prefix = static_cast<int>(route.prefix);
            best_zone   = route.zone;
        }
    }
    return best_zone;
}

int Policy::evaluate(Zone from, Zone to, uint8_t proto, uint16_t dst_port,
                     const std::string& app, Verdict& verdict) const {
    for (size_t i = 0; i < rules_.size(); ++i) {
        const Rule& rule = rules_[i];

        if (rule.from != Zone::Any && rule.from != from) continue;
        if (rule.to != Zone::Any && rule.to != to) continue;

        if (!rule.services.empty()) {
            bool matched = false;
            for (const Service& svc : rule.services) {
                if (svc.matches(proto, dst_port)) { matched = true; break; }
            }
            if (!matched) continue;
        }

        if (!rule.applications.empty()) {
            // Provisional match while the application is unknown.
            //
            // This is the subtle one, and getting it backwards breaks everything.
            // The tempting reading is that a rule naming applications cannot match
            // until the application is known -- but a firewall that denied every
            // session until it had identified it would never identify anything.
            // You cannot learn the application without first letting enough
            // packets through to carry a payload. It is a bootstrap problem, and
            // the resolution is that every other criterion decides the first
            // evaluation: zones and service match, so the rule claims the session
            // provisionally.
            //
            // The second evaluation, once App-ID has latched, is strict. That is
            // where a session admitted on "tcp/443 could be web traffic" is
            // re-judged as "this is ssh" and loses the rule.
            if (app.empty()) {
                verdict = rule.action;
                return static_cast<int>(i);
            }

            bool matched = false;
            for (const std::string& name : rule.applications) {
                if (name == app) { matched = true; break; }
            }
            if (!matched) continue;
        }

        verdict = rule.action;
        return static_cast<int>(i);
    }

    // Nothing matched. The implicit deny is what makes this a whitelist.
    verdict = Verdict::Deny;
    return kDefaultDeny;
}

const Rule* Policy::rule_at(int index) const {
    if (index < 0 || static_cast<size_t>(index) >= rules_.size()) return nullptr;
    return &rules_[static_cast<size_t>(index)];
}

}  // namespace nano
