#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nano {

/// Security zones. Interfaces are grouped into zones and policy is written
/// between them rather than between addresses -- the model PAN-OS is built on,
/// and the reason a rule base stays readable as a network grows.
enum class Zone : uint8_t { Any, Trust, Untrust, Dmz };

const char* to_string(Zone z);
bool        zone_from_string(const std::string& s, Zone& out);

/// Allow, or one of the two ways to say no.
///
/// Deny and drop are not the same answer and the difference is operational. Deny
/// is polite: the sender is told, via RST or ICMP unreachable, and fails fast.
/// Drop is silent: the sender waits for a timeout and learns nothing. Silence is
/// preferred on an internet-facing zone precisely because it tells a scanner
/// nothing -- a closed port that answers confirms the host exists.
enum class Verdict : uint8_t { Allow, Deny, Drop };

const char* to_string(Verdict v);
bool        verdict_from_string(const std::string& s, Verdict& out);

/// A protocol/port pair a rule matches. Port 0 means "any port for this protocol".
struct Service {
    uint8_t  proto = 0;
    uint16_t port  = 0;

    bool matches(uint8_t p, uint16_t dst_port) const {
        return proto == p && (port == 0 || port == dst_port);
    }
};

struct Rule {
    std::string name;
    Zone        from = Zone::Any;
    Zone        to   = Zone::Any;

    /// Empty means any service.
    std::vector<Service> services;

    /// Empty means any application.
    ///
    /// A rule that names applications cannot match until App-ID has decided what
    /// the session is -- which is the whole reason policy has to be evaluated a
    /// second time. See Policy::evaluate.
    std::vector<std::string> applications;

    Verdict action = Verdict::Deny;
};

/// A zone assignment: every address inside this prefix belongs to this zone.
struct ZoneRoute {
    uint32_t network = 0;
    uint8_t  prefix  = 0;
    Zone     zone    = Zone::Any;

    bool contains(uint32_t ip) const {
        if (prefix == 0) return true;  // 0.0.0.0/0, and a 32-bit shift is UB
        const uint32_t mask = 0xffffffffu << (32 - prefix);
        return (ip & mask) == (network & mask);
    }
};

/// The rule base.
///
/// Evaluation is first-match-wins with an implicit deny at the bottom. Both
/// halves matter: first-match is what lets a specific exception sit above a
/// general rule, and the implicit deny is what makes the policy a whitelist. A
/// firewall whose default is allow is a router with extra steps.
class Policy {
public:
    /// The rule index meaning "nothing matched, implicit default deny".
    static constexpr int kDefaultDeny = -1;

    /// Loads the built-in policy: trust is RFC 1918, everything else untrust,
    /// outbound allowed, inbound denied. Enough to run against a capture without
    /// writing a rule file first.
    void load_default();

    bool load_file(const std::string& path, std::string& err);
    bool parse(const std::string& text, std::string& err);

    /// Longest-prefix match, so a /24 beats the 0.0.0.0/0 catch-all regardless of
    /// the order they were declared in.
    Zone zone_for(uint32_t ip) const;

    /// Finds the first rule matching this traffic.
    ///
    /// `app` is the identified application, or empty when App-ID has not decided
    /// yet. That distinction drives the whole App-ID shift mechanism: on the first
    /// packet the application is unknown, so rules that name applications are
    /// skipped and the session matches on zone and service alone. Once the
    /// application latches, this is called again with it filled in, and the answer
    /// can change -- a session allowed as web traffic can turn out to be ssh and
    /// lose its rule.
    ///
    /// Returns the rule index, or kDefaultDeny.
    int evaluate(Zone from, Zone to, uint8_t proto, uint16_t dst_port,
                 const std::string& app, Verdict& verdict) const;

    const std::vector<Rule>& rules() const { return rules_; }
    const Rule*              rule_at(int index) const;

private:
    std::vector<Rule>      rules_;
    std::vector<ZoneRoute> zones_;
};

}  // namespace nano
