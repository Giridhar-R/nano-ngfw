# Findings

What running the tool actually showed, and what it did not.

---

## Scope of what has been run

Everything below comes from the **synthetic fixture corpus** in `tests/make_fixtures.py` —
twenty captures, each hand-assembled to isolate one behaviour.

**Real-world traffic has not been run through this yet.** That matters and is stated plainly
rather than glossed: synthetic fixtures test what the author already thought to test, which is
exactly the blind spot they cannot cover. A capture of genuine browsing, or one of the mixed
traffic samples from malware-traffic-analysis.net, would exercise retransmission patterns, out-of-
order delivery, TLS session resumption, HTTP/2 over TLS, and QUIC-on-UDP — none of which the
fixtures contain, and several of which this classifier will get wrong.

That run is the obvious next step, and `tests/diff_tshark.py` exists to make it cheap: point both
at the same capture and the disagreements are the findings.

---

## What the corpus shows

### Identification works on content, not port

`ssh_on_443.pcap` carries an SSH banner to port 443. It is identified as `ssh`, not `ssl`, and
under `rules/policy.conf` it loses the rule that admitted it. `tls_sni.pcap` — same port, same
rule — is identified as `ssl`, keeps the rule, and yields `www.google.com` from the ClientHello.

The gap between those two runs is the entire argument for App-ID over port filtering, and it is
reproducible in two commands.

### The provisional-match rule is load-bearing

The first implementation skipped application-constrained rules while the application was unknown,
which is the intuitive reading and is wrong. It denied every session on its first packet — and a
session denied on packet 1 never sends payload, so it is never identified, so the second
evaluation never happens. Nothing in the corpus was ever classified as anything.

This did not show up in unit tests of `Policy::evaluate`, which were passing: each rule matched or
didn't exactly as specified. It showed up in the golden output, where every session in every
capture read `insufficient-data`. A whole-pipeline assertion caught what component assertions
structurally could not.

### Malformed input is counted, not conflated

`bad_ip_checksum.pcap` decodes structurally and increments `bad-checksum` while leaving
`malformed` at zero. That separation is deliberate — a corrupt checksum is a transit problem, a
malformed header is a parser problem — and on real traffic it will matter more than it does here:
captures taken on a host with checksum offload are full of the former by design, and folding them
into one number would make the counter useless.

### Fragments and non-IPv4 are visibly skipped

`non_ipv4.pcap` produces `arp 1, ipv6 1` and zero sessions. Later fragments increment `fragments`
and stop at L3. Neither is silently dropped, which is the point: an unexplained gap between packet
count and session count is how you discover a parser is wrong.

---

## Limitations found while building

Not bugs — consequences of the design, worth naming before someone else does.

**No sequence validation.** The state machine trusts the RST flag. An off-path attacker who can
guess a 5-tuple can tear down any session with one forged packet. A real firewall checks the RST's
sequence number against the receive window.

**No reassembly, so App-ID sees only the first payload segment.** A ClientHello split across two
TCP segments will not be classified — `extract_sni` sees a fragment and gives up. This is rare on
real networks but not absent, and it is a straightforward evasion for anyone deliberately splitting
records.

**The DNS signature is the weakest one.** HTTP, TLS and SSH all have distinctive preambles; a DNS
query has none, so `looks_like_dns` checks structural plausibility and is additionally gated on
port 53. On a non-standard port, DNS will read as `unknown`. That is the correct trade — the
alternative is false positives on anything binary — but it is a real hole in the
identify-by-content claim, and the only application here where the port still matters.

**Port allocation in the NAT pool is linear with wraparound** rather than tracking free ports, so a
released port is not immediately reusable. Fine at fixture scale, wrong under sustained load.

---

## Numbers

| | |
|---|---|
| Fixtures | 20 captures |
| Test binaries | 7 unit + golden + tshark differential |
| Golden cases | 20 |
| Fuzz targets | 2, 60s each per push, no crashes to date |
| Toolchains | MSVC, gcc, clang — sanitizers on both Linux legs |

No performance number yet. The corpus is too small to measure anything meaningful — every capture
is under a kilobyte — so packets/sec awaits the real-traffic run above.
