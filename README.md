# nano-ngfw

A stateful packet filter with L7 application identification, in C++17 with no third-party
dependencies. It reads pcap files, tracks TCP conversations through a session state machine,
identifies applications by payload rather than port, and enforces a zone-based security policy.

---

## What it does that a packet filter cannot

Two captures. Same destination port, same rule, opposite outcomes.

```
$ nano-ngfw --policy rules/policy.conf --session 0 captures/ssh_on_443.pcap
Session 0
  application  : ssh
  protocol     : tcp
  initiator    : 192.168.1.10:55000 (trust)
  responder    : 203.0.113.9:443 (untrust)
  state        : CLOSED
  rule         : (implicit default deny)
  action       : deny
  app-id shift : yes -- re-evaluated as ssh after identification
```

```
$ nano-ngfw --policy rules/policy.conf --session 0 captures/tls_sni.pcap
Session 0
  application  : ssl
  sni          : www.google.com
  protocol     : tcp
  initiator    : 192.168.1.10:52344 (trust)
  responder    : 142.250.183.14:443 (untrust)
  state        : ESTABLISHED
  rule         : allow-web
  action       : allow
```

The rule that admitted both:

```
rule allow-web from trust to untrust service tcp/80,tcp/443 application web-browsing,ssl action allow
```

A port-based filter sees two identical sessions to 443 and permits both. This one admits the
session on its first packet, watches the payload, discovers that one of them is SSH wearing
port 443, re-evaluates the policy against the identified application, and tears it down.

The same contrast for statefulness, from a single packet — a bare ACK for a conversation that
was never opened:

```
$ nano-ngfw captures/out_of_state.pcap              $ nano-ngfw --midstream captures/out_of_state.pcap
sessions  0  (active 0, retired 0)                  sessions  1  (active 1, retired 0)
  out-of-state  1                                   0  ...  ESTABLISHED  allow
```

Both pairs are committed as golden files, so neither claim can quietly stop being true.

---

## Pipeline

```
capture.pcap
   │
   ├─ pcap reader ......... byte order from the magic number; length fields capped, not trusted
   ├─ ethernet ............ ipv4 only; arp / ipv6 / vlan counted and skipped
   ├─ ipv4 ................ IHL honoured, checksum verified, payload clipped to total_length
   ├─ tcp / udp ........... data offset honoured; later fragments stopped at L3
   │
   ├─ flow table .......... direction-agnostic 5-tuple → session, index handles
   ├─ state machine ....... SYN-SEEN → SYNACK-SEEN → ESTABLISHED → FIN-SEEN → CLOSING → CLOSED
   ├─ policy .............. zones, first match wins, implicit deny        ← evaluated once
   ├─ app-id .............. http · tls+sni · dns · ssh, by payload        ← then policy again
   ├─ nat ................. source PAT for allowed trust → untrust
   └─ aging ............... per-state idle timeouts, capture clock
```

## Build

Needs CMake 3.20+, a C++17 compiler, and Python 3 for the test fixtures.

```bash
cmake -S . -B build
cmake --build build
ctest --test-dir build --output-on-failure
```

```bash
./build/nano-ngfw --policy rules/policy.conf captures/handshake_clean.pcap
```

```
--policy <file>    load a rule base (default: built-in)
--nat <ip>         source-NAT allowed trust->untrust sessions
--midstream        adopt sessions from non-SYN packets
--session <id>     print one session in detail
--stats-only       suppress the session table
```

---

## Design decisions

The four that shape everything else. Longer versions in [`docs/design.md`](docs/design.md).

**Policy is evaluated once, at session creation — not per packet.** This is what stateful
means. A stateless ACL asks "is this packet allowed?" for every packet; here the question is
asked once, of the session. Every later packet, including the entire return direction, is
forwarded because the session exists. That is why no inbound rule is needed for the server's
SYN+ACK. `Policy::evaluate` has exactly one call site in the packet path, and a second in the
App-ID shift below.

**One observed session state, not two RFC 793 endpoint machines.** RFC 793 describes an
*endpoint*: it owns half a connection, retransmits, reassembles, and lingers in TIME_WAIT. A
middlebox needs none of that — only enough state to decide whether a packet belongs to a
conversation it already authorised. Seven states, driven by flags and direction alone. PAN-OS
makes the same reduction for the same reason. The cost is stated rather than hidden: without
sequence tracking, a forged off-path RST tears a session down, and without reassembly,
sequence-overlap evasion is invisible.

**App-ID latches late, so policy is re-evaluated when it does.** The application is not knowable
on packet 1 — you need payload, which arrives several packets later. So a rule naming
applications matches *provisionally* on its other criteria first (deny until identified and
nothing is ever identified: a session needs to live long enough to speak). Once App-ID decides,
policy runs again, strictly. That second pass is the SSH-on-443 teardown above.

**The clock comes from pcap timestamps, never wall time.** Replay is deterministic, so two runs
byte-match and golden tests are possible at all. A one-hour capture replays in milliseconds with
timeouts still firing correctly.

Supporting these: **views for parsing, owned copies for storage** — decoders slice non-owning
`ByteView`s and copy nothing; an SNI hostname that must outlive its packet is copied onto the
session. And **sessions live in a vector addressed by index, never by pointer**, because a
vector reallocates and would dangle every stored pointer intermittently under load.

---

## Traps this code is built around

Each of these has a fixture named after it, because each is a bug that works on most traffic and
fails on the rest.

| Trap | Fixture | What goes wrong |
|---|---|---|
| IPv4 **IHL** is a word count | `ipv4_options` | Hardcode 20 bytes and the TCP header is read four bytes early the first time a Router Alert appears |
| TCP **data offset** is a word count | `tcp_options` | Same bug one layer up; a normal SYN carries 40 bytes of header, so TLS parsing reads a window scale value as a record type |
| Ethernet **pads** frames under 60 bytes | unit test | Padding handed downstream becomes application data nobody sent |
| A **later fragment** has no L4 header | — | Its payload parsed as ports is the basis of fragment evasion |
| `off + n` **overflows** | `test_byteview` | The obvious bounds check wraps on a hostile length and passes |
| Symmetric key + **XOR** hash | `test_flow` | `ip_a ^ ip_b` cancels for mirrored conversations, collapsing them into one bucket — an algorithmic complexity attack, not just a slowdown |
| Sorting IP and port **separately** | `test_flow` | Two unrelated conversations merge onto one session key |

Three bugs the guardrails caught while this was being written: `-Wconversion -Werror` rejected an
`sscanf` in the argument parser (MSVC deprecates it); the golden tests caught the App-ID
provisional-match rule being backwards, which denied every session before it could be identified;
and a test using `0xc0a80105` for "192.168.5.5" failed loudly rather than silently asserting the
wrong subnet.

---

## Validation

- **9 test binaries** — byteview, pcap, decode, flow, tcp_state, policy, appid, plus golden and
  differential harnesses.
- **Fuzzing.** `fuzz/fuzz_decode.cpp` runs the L2/L3/L4 chain over arbitrary bytes;
  `fuzz/fuzz_tls.cpp` targets the ClientHello walk specifically, because four nested
  length-prefixed structures each trusting a peer-chosen length is the most exploitable shape in
  network code. Both run 60s per push under libFuzzer with ASan and UBSan.
- **Golden output.** 20 cases pinning the whole pipeline — table ordering, stats formatting,
  session counting — which catches the class of refactor that leaves every unit test green.
- **Differential against tshark.** Session counts checked against `-z conv,tcp`, and every
  extracted SNI against `-e tls.handshake.extensions_server_name`. Skips when tshark is absent.
- **CI** on MSVC, gcc and clang, with sanitizers on the Linux legs. `-Wall -Wextra -Wpedantic
  -Wshadow -Wconversion -Wsign-conversion -Werror`.
- **Fixtures are generated, not committed.** `tests/make_fixtures.py` hand-assembles every pcap
  from raw bytes with no scapy, so a fixture can be read as code rather than opened in Wireshark.

---

## Non-goals

Stated so the scope reads as chosen rather than abandoned. IPv6 · VLAN and QinQ tag walking · IP
fragment reassembly · TCP stream reassembly and out-of-order handling · TLS decryption · live
capture · sequence-number validation · IPS signature matching over reassembled streams ·
timer-wheel aging · any actual packet forwarding. This classifies and decides; it does not move
traffic.

## Licence

MIT.
