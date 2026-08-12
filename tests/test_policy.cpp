#include <string>

#include "harness.h"
#include "policy.h"

using namespace nano;

namespace {

constexpr uint8_t kTcp = 6;
constexpr uint8_t kUdp = 17;

constexpr uint32_t kInternal = 0xc0a8010au;  // 192.168.1.10
constexpr uint32_t kExternal = 0x5db8d822u;  // 93.184.216.34

Policy parsed(const char* text) {
    Policy      p;
    std::string err;
    const bool  ok = p.parse(text, err);
    CHECK(ok);
    if (!ok) std::fprintf(stderr, "      parse error: %s\n", err.c_str());
    return p;
}

void test_zone_longest_prefix_wins() {
    const Policy p = parsed(R"(
zone untrust 0.0.0.0/0
zone trust   192.168.0.0/16
zone dmz     192.168.5.0/24
)");

    // Declaration order deliberately puts the catch-all first; the /24 must still
    // beat the /16, which must still beat the /0.
    CHECK(p.zone_for(0xc0a80505u) == Zone::Dmz);      // 192.168.5.5  -> /24
    CHECK(p.zone_for(kInternal) == Zone::Trust);      // 192.168.1.10 -> /16
    CHECK(p.zone_for(kExternal) == Zone::Untrust);    //              -> /0
}

void test_first_match_wins() {
    const Policy p = parsed(R"(
zone trust   192.168.0.0/16
zone untrust 0.0.0.0/0

rule block-telnet from any to any service tcp/23 action deny
rule allow-all    from any to any service any    action allow
)");

    Verdict v = Verdict::Allow;
    const int rule = p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 23, std::string(), v);
    CHECK_EQ(rule, 0);
    CHECK(v == Verdict::Deny);

    // Anything else falls through to the permissive rule below it.
    CHECK_EQ(p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 80, std::string(), v), 1);
    CHECK(v == Verdict::Allow);
}

/// The implicit deny is what makes the rule base a whitelist.
void test_no_match_is_denied() {
    const Policy p = parsed(R"(
rule allow-web from trust to untrust service tcp/80 action allow
)");

    Verdict v = Verdict::Allow;
    CHECK_EQ(p.evaluate(Zone::Untrust, Zone::Trust, kTcp, 22, std::string(), v),
             Policy::kDefaultDeny);
    CHECK(v == Verdict::Deny);
}

void test_zone_direction_matters() {
    const Policy p = parsed(R"(
rule outbound from trust to untrust service any action allow
)");

    Verdict v = Verdict::Deny;
    CHECK_EQ(p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 443, std::string(), v), 0);
    CHECK(v == Verdict::Allow);

    // The same rule must not admit the reverse direction.
    CHECK_EQ(p.evaluate(Zone::Untrust, Zone::Trust, kTcp, 443, std::string(), v),
             Policy::kDefaultDeny);
    CHECK(v == Verdict::Deny);
}

void test_service_matching() {
    const Policy p = parsed(R"(
rule web from any to any service tcp/80,tcp/443 action allow
rule dns from any to any service udp/53         action allow
)");

    Verdict v = Verdict::Deny;
    CHECK_EQ(p.evaluate(Zone::Any, Zone::Any, kTcp, 443, std::string(), v), 0);
    CHECK_EQ(p.evaluate(Zone::Any, Zone::Any, kUdp, 53, std::string(), v), 1);

    // Right port, wrong protocol.
    CHECK_EQ(p.evaluate(Zone::Any, Zone::Any, kUdp, 443, std::string(), v),
             Policy::kDefaultDeny);
}

/// The bootstrap problem, and the reason the first evaluation is permissive.
///
/// A rule naming applications must still claim a session on its first packet,
/// when the application is unknown -- because you cannot learn the application
/// without letting packets through to carry a payload. Deny first and nothing is
/// ever identified.
void test_unknown_application_matches_provisionally() {
    const Policy p = parsed(R"(
rule allow-web from trust to untrust service tcp/443 application web-browsing,ssl action allow
)");

    Verdict v = Verdict::Deny;
    CHECK_EQ(p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 443, std::string(), v), 0);
    CHECK(v == Verdict::Allow);
}

/// The second evaluation is strict, and this is where the shift happens.
void test_known_application_is_judged_strictly() {
    const Policy p = parsed(R"(
rule allow-web from trust to untrust service tcp/443 application web-browsing,ssl action allow
)");

    Verdict v = Verdict::Deny;

    // A genuine TLS session keeps the rule.
    CHECK_EQ(p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 443, "ssl", v), 0);
    CHECK(v == Verdict::Allow);

    // ssh on the same port loses it.
    CHECK_EQ(p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 443, "ssh", v),
             Policy::kDefaultDeny);
    CHECK(v == Verdict::Deny);
}

void test_deny_and_drop_are_distinct() {
    const Policy p = parsed(R"(
rule tell-them   from any to any service tcp/23 action deny
rule say-nothing from any to any service tcp/22 action drop
)");

    Verdict v = Verdict::Allow;
    p.evaluate(Zone::Any, Zone::Any, kTcp, 23, std::string(), v);
    CHECK(v == Verdict::Deny);
    p.evaluate(Zone::Any, Zone::Any, kTcp, 22, std::string(), v);
    CHECK(v == Verdict::Drop);
}

void test_comments_and_blank_lines() {
    const Policy p = parsed(R"(
# a comment

zone trust 10.0.0.0/8      # trailing comment

rule allow from trust to any service any action allow
)");
    CHECK_EQ(p.rules().size(), 1u);
    CHECK(p.zone_for(0x0a000001u) == Zone::Trust);
}

void test_parse_errors_are_reported() {
    Policy      p;
    std::string err;

    CHECK(!p.parse("zone trust not-a-cidr", err));
    CHECK(!err.empty());

    CHECK(!p.parse("rule r from nowhere to any action allow", err));
    CHECK(!p.parse("rule r from trust to any service tcp/99999 action allow", err));
    CHECK(!p.parse("rule r from trust to any action explode", err));
    CHECK(!p.parse("wibble", err));
}

void test_builtin_policy() {
    Policy p;
    p.load_default();

    CHECK(p.zone_for(kInternal) == Zone::Trust);
    CHECK(p.zone_for(0x0a000001u) == Zone::Trust);       // 10.0.0.1
    CHECK(p.zone_for(0xac100001u) == Zone::Trust);       // 172.16.0.1
    CHECK(p.zone_for(kExternal) == Zone::Untrust);

    Verdict v = Verdict::Deny;
    p.evaluate(Zone::Trust, Zone::Untrust, kTcp, 443, std::string(), v);
    CHECK(v == Verdict::Allow);
    p.evaluate(Zone::Untrust, Zone::Trust, kTcp, 443, std::string(), v);
    CHECK(v == Verdict::Drop);
}

}  // namespace

int main() {
    test_zone_longest_prefix_wins();
    test_first_match_wins();
    test_no_match_is_denied();
    test_zone_direction_matters();
    test_service_matching();
    test_unknown_application_matches_provisionally();
    test_known_application_is_judged_strictly();
    test_deny_and_drop_are_distinct();
    test_comments_and_blank_lines();
    test_parse_errors_are_reported();
    test_builtin_policy();
    return nano::test::summary("policy");
}
