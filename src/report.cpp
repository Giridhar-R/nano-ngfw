#include "report.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#include "decode.h"

namespace nano {
namespace {

/// Escapes text that came off the wire before it reaches the page.
///
/// Not decoration. An SNI hostname is attacker-controlled input, and this report
/// is the one place in the project where such a string is embedded in a document
/// a browser will parse. `extract_sni` already refuses anything outside printable
/// ASCII, so this is the second of two independent barriers rather than the only
/// one -- which is the right number for the boundary between a packet and a DOM.
std::string escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char c : in) {
        switch (c) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&#39;";  break;
            default:   out += c;        break;
        }
    }
    return out;
}

std::string endpoint(uint32_t ip, uint16_t port) {
    return ipv4_to_string(ip) + ":" + std::to_string(port);
}

const char* proto_name(uint8_t proto) {
    switch (static_cast<IpProto>(proto)) {
        case IpProto::Tcp:  return "tcp";
        case IpProto::Udp:  return "udp";
        case IpProto::Icmp: return "icmp";
    }
    return "ip";
}

/// Sessions still carrying a pre-decision placeholder get a muted style, so the
/// eye goes to the ones the classifier actually resolved.
bool is_placeholder(const Session& s) { return !s.app_latched; }

const char* verdict_class(Verdict v) {
    switch (v) {
        case Verdict::Allow: return "allow";
        case Verdict::Deny:  return "deny";
        case Verdict::Drop:  return "drop";
    }
    return "deny";
}

void write_head(std::ostream& out) {
    // A console for a security appliance is dark. This commits to one palette
    // deliberately rather than tracking the viewer's theme -- the report is
    // meant to look like an instrument readout, and inverting it to a white
    // page would make the verdict colours mean less.
    out << R"(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>nano-ngfw session report</title>
<style>
  :root {
    --bg:        #0b1014;
    --panel:     #121a20;
    --panel-2:   #16212a;
    --line:      #22323d;
    --text:      #d6e4ec;
    --muted:     #6f8899;
    --accent:    #35d6c4;
    --accent-dim:#1d7f76;
    --allow:     #3fb950;
    --deny:      #f85149;
    --drop:      #d29922;
    --shift:     #bc8cff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--text);
    font: 14px/1.55 ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
    padding: 32px 20px 64px;
  }
  .wrap { max-width: 1180px; margin: 0 auto; }

  header { border-bottom: 1px solid var(--line); padding-bottom: 18px; margin-bottom: 26px; }
  h1 { margin: 0; font-size: 19px; letter-spacing: .06em; font-weight: 600; }
  h1 .dim { color: var(--accent); }
  .meta { margin-top: 8px; color: var(--muted); font-size: 12.5px; }
  .meta span { margin-right: 18px; white-space: nowrap; }
  .meta b { color: var(--text); font-weight: 500; }

  .tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(132px, 1fr));
           gap: 10px; margin-bottom: 30px; }
  .tile { background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
          padding: 12px 14px; }
  .tile .n { font-size: 23px; font-weight: 600; letter-spacing: -.01em; }
  .tile .k { color: var(--muted); font-size: 11px; text-transform: uppercase;
             letter-spacing: .09em; margin-top: 3px; }
  .tile.ok  .n { color: var(--allow); }
  .tile.bad .n { color: var(--deny); }
  .tile.hot .n { color: var(--shift); }

  h2 { font-size: 12px; text-transform: uppercase; letter-spacing: .11em;
       color: var(--muted); font-weight: 600; margin: 34px 0 12px; }

  .scroll { overflow-x: auto; border: 1px solid var(--line); border-radius: 6px; }
  table { border-collapse: collapse; width: 100%; min-width: 900px; }
  thead th { background: var(--panel-2); color: var(--muted); text-align: left;
             font-weight: 600; font-size: 11px; text-transform: uppercase;
             letter-spacing: .08em; padding: 9px 12px; white-space: nowrap;
             border-bottom: 1px solid var(--line); }
  tbody td { padding: 9px 12px; border-bottom: 1px solid rgba(34,50,61,.55);
             white-space: nowrap; }
  tbody tr:last-child td { border-bottom: 0; }
  tbody tr:hover { background: rgba(53,214,196,.045); }
  tr.shifted { background: rgba(188,140,255,.075); }
  tr.shifted:hover { background: rgba(188,140,255,.11); }

  .id { color: var(--muted); }
  .app { color: var(--accent); font-weight: 600; }
  .app.placeholder { color: var(--muted); font-weight: 400; font-style: italic; }
  .zone { color: var(--muted); font-size: 12.5px; }

  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px;
           font-size: 11px; font-weight: 600; letter-spacing: .05em;
           text-transform: uppercase; }
  .badge.allow { color: var(--allow); background: rgba(63,185,80,.13);
                 border: 1px solid rgba(63,185,80,.32); }
  .badge.deny  { color: var(--deny);  background: rgba(248,81,73,.13);
                 border: 1px solid rgba(248,81,73,.32); }
  .badge.drop  { color: var(--drop);  background: rgba(210,153,34,.13);
                 border: 1px solid rgba(210,153,34,.32); }
  .flag { color: var(--shift); font-size: 11px; font-weight: 600;
          letter-spacing: .05em; }

  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr));
           gap: 14px; }
  .card { background: var(--panel); border: 1px solid var(--line);
          border-radius: 6px; padding: 15px 17px; }
  .card.hot { border-color: rgba(188,140,255,.42); }
  .card h3 { margin: 0 0 4px; font-size: 13px; letter-spacing: .04em; }
  .card .why { color: var(--muted); font-size: 12px; margin: 0 0 12px;
               line-height: 1.5; white-space: normal; }
  .kv { display: grid; grid-template-columns: 86px 1fr; gap: 3px 12px; font-size: 12.5px; }
  .kv dt { color: var(--muted); }
  .kv dd { margin: 0; overflow-wrap: anywhere; }

  footer { margin-top: 42px; padding-top: 16px; border-top: 1px solid var(--line);
           color: var(--muted); font-size: 11.5px; line-height: 1.7; }
  footer code { color: var(--accent-dim); }
</style>
</head>
<body>
<div class="wrap">
)";
}

void write_tiles(std::ostream& out, const Engine& e) {
    const Counters& c = e.counters();

    const auto tile = [&](const char* cls, unsigned long long n, const char* label) {
        out << "  <div class=\"tile " << cls << "\"><div class=\"n\">" << n
            << "</div><div class=\"k\">" << label << "</div></div>\n";
    };

    // Counters of bad things are only coloured when there are some. A red zero
    // reads as an alarm at a glance, when it is the opposite -- and a dashboard
    // that cries wolf on a clean run trains you to stop looking at it.
    const auto when_nonzero = [](const char* cls, uint64_t n) {
        return n != 0 ? cls : "";
    };

    out << "<div class=\"tiles\">\n";
    tile("", static_cast<unsigned long long>(c.packets), "packets");
    tile("", static_cast<unsigned long long>(c.sessions_created), "sessions");
    tile(when_nonzero("ok", c.allowed),
         static_cast<unsigned long long>(c.allowed), "allowed");
    tile(when_nonzero("bad", c.denied + c.dropped),
         static_cast<unsigned long long>(c.denied + c.dropped), "denied / dropped");
    tile(when_nonzero("hot", c.app_shifts),
         static_cast<unsigned long long>(c.app_shifts), "app-id shifts");
    tile(when_nonzero("bad", c.out_of_state),
         static_cast<unsigned long long>(c.out_of_state), "out of state");
    tile(when_nonzero("bad", c.malformed()),
         static_cast<unsigned long long>(c.malformed()), "malformed");
    out << "</div>\n";
}

void write_table(std::ostream& out, const Engine& e) {
    out << "<h2>Session browser</h2>\n<div class=\"scroll\"><table>\n"
        << "<thead><tr>"
        << "<th>ID</th><th>Application</th><th>From</th><th>To</th>"
        << "<th>Source</th><th>Destination</th><th>State</th><th>Rule</th>"
        << "<th>Action</th><th></th>"
        << "</tr></thead>\n<tbody>\n";

    for (const Session& s : e.flows().all()) {
        const Rule* rule = e.policy().rule_at(s.matched_rule);

        out << "<tr" << (s.app_shifted ? " class=\"shifted\"" : "") << ">"
            << "<td class=\"id\">" << s.id << "</td>"
            << "<td class=\"app" << (is_placeholder(s) ? " placeholder" : "") << "\">"
            << escape(s.app_display()) << "</td>"
            << "<td class=\"zone\">" << to_string(s.from_zone) << "</td>"
            << "<td class=\"zone\">" << to_string(s.to_zone) << "</td>"
            << "<td>" << escape(endpoint(s.init_ip, s.init_port)) << "</td>"
            << "<td>" << escape(endpoint(s.resp_ip, s.resp_port)) << "</td>"
            << "<td class=\"zone\">" << to_string(s.state) << "</td>"
            << "<td class=\"zone\">"
            << (rule != nullptr ? escape(rule->name) : "default deny") << "</td>"
            << "<td><span class=\"badge " << verdict_class(s.verdict) << "\">"
            << to_string(s.verdict) << "</span></td>"
            << "<td>" << (s.app_shifted ? "<span class=\"flag\">APP-ID SHIFT</span>" : "")
            << "</td>"
            << "</tr>\n";
    }

    out << "</tbody>\n</table></div>\n";
}

/// Detail cards for the sessions worth explaining -- anything that shifted, and
/// anything carrying an SNI. A card for every session would be a wall; the point
/// is to put the interesting two or three at eye level.
void write_cards(std::ostream& out, const Engine& e) {
    bool any = false;
    std::ostringstream body;

    for (const Session& s : e.flows().all()) {
        if (!s.app_shifted && s.sni.empty()) continue;
        any = true;

        const Rule* rule = e.policy().rule_at(s.matched_rule);

        body << "  <div class=\"card" << (s.app_shifted ? " hot" : "") << "\">\n"
             << "    <h3>Session " << s.id << " &middot; " << escape(s.app_display())
             << "</h3>\n";

        if (s.app_shifted) {
            body << "    <p class=\"why\">Admitted on its first packet, when the only thing "
                    "known about it was a destination port. Once the payload arrived, App-ID "
                    "identified it as <b>" << escape(s.app)
                 << "</b>, policy was evaluated a second time against the application, and the "
                    "session lost the rule that had admitted it.</p>\n";
        } else {
            body << "    <p class=\"why\">Identified by payload rather than port. The server "
                    "name is readable because it travels in the clear in the TLS ClientHello, "
                    "before encryption begins.</p>\n";
        }

        body << "    <dl class=\"kv\">\n"
             << "      <dt>protocol</dt><dd>" << proto_name(s.proto) << "</dd>\n"
             << "      <dt>initiator</dt><dd>" << escape(endpoint(s.init_ip, s.init_port))
             << " (" << to_string(s.from_zone) << ")</dd>\n"
             << "      <dt>responder</dt><dd>" << escape(endpoint(s.resp_ip, s.resp_port))
             << " (" << to_string(s.to_zone) << ")</dd>\n";

        if (!s.sni.empty()) {
            body << "      <dt>sni</dt><dd>" << escape(s.sni) << "</dd>\n";
        }
        if (s.nat_applied) {
            body << "      <dt>nat</dt><dd>" << escape(endpoint(s.nat_ip, s.nat_port))
                 << " (source PAT)</dd>\n";
        }

        body << "      <dt>state</dt><dd>" << to_string(s.state) << "</dd>\n"
             << "      <dt>rule</dt><dd>"
             << (rule != nullptr ? escape(rule->name) : "implicit default deny") << "</dd>\n"
             << "      <dt>action</dt><dd><span class=\"badge " << verdict_class(s.verdict)
             << "\">" << to_string(s.verdict) << "</span></dd>\n"
             << "      <dt>traffic</dt><dd>" << s.pkts_c2s << " &rarr; / " << s.pkts_s2c
             << " &larr; packets, " << (s.bytes_c2s + s.bytes_s2c) << " bytes</dd>\n"
             << "    </dl>\n  </div>\n";
    }

    if (!any) return;
    out << "<h2>Sessions worth a second look</h2>\n<div class=\"cards\">\n"
        << body.str() << "</div>\n";
}

}  // namespace

bool write_html_report(const std::string& path, const Engine& engine,
                       const std::string& capture, const std::string& policy) {
    std::ofstream out(path);
    if (!out) return false;

    write_head(out);

    out << "<header>\n"
        << "  <h1>nano&#8209;ngfw <span class=\"dim\">session report</span></h1>\n"
        << "  <div class=\"meta\">"
        << "<span>capture <b>" << escape(capture) << "</b></span>"
        << "<span>policy <b>" << escape(policy.empty() ? "built-in" : policy) << "</b></span>"
        << "<span>rules <b>" << engine.policy().rules().size() << "</b></span>"
        << "</div>\n</header>\n";

    write_tiles(out, engine);
    write_table(out, engine);
    write_cards(out, engine);

    out << "<footer>\n"
           "Generated by <code>nano-ngfw --html</code>. Static: one rendering of one replay, "
           "with no server behind it and no script in the page.<br>\n"
           "Every timestamp derives from the capture rather than a wall clock, so re-running "
           "the same file reproduces this report byte for byte.\n"
           "</footer>\n"
           "</div>\n</body>\n</html>\n";

    return true;
}

}  // namespace nano
