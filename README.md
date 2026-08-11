# nano-ngfw

A stateful packet filter with layer-7 application identification, in C++17 with no third-party
dependencies. It reads pcap files, tracks sessions, evaluates a zone-based security policy,
identifies applications from payload rather than port number, and applies source NAT.

> **Status: in progress.** Scaffold and byte-level primitives are in. The pcap reader, decoders,
> flow table, state machine, policy engine, App-ID and NAT land over the following commits — see
> [Roadmap](#roadmap).

---

## The idea

Identifying an application by its port number stopped working a long time ago. The intended
demonstration is a session carrying SSH over port 443: allowed on the first packet as
`web-browsing` because that is all a 5-tuple can tell you, reclassified as `ssh` once payload
arrives, policy re-evaluated against the new application, and the session torn down.

That round trip — decide early on incomplete information, then revise — is the interesting part
of an application-aware filter, and it is what this project is built around.

## Build

Requires CMake 3.20+ and a C++17 compiler. Tested on MSVC, gcc and clang.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --config Debug --parallel
ctest --test-dir build --build-config Debug --output-on-failure
```

Sanitizers, on gcc and clang:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DNANO_SANITIZE=ON
```

## Design

[`docs/design.md`](docs/design.md) covers the four decisions the implementation rests on:

1. **Policy is evaluated once per session, not per packet** — which is what makes it stateful,
   and why return traffic needs no rule of its own.
2. **One observed session state, not two RFC 793 endpoint machines** — a middlebox needs less
   state than an endpoint, and knowing how much less is the design.
3. **Application identification latches late, so policy is re-evaluated when it does** — the
   first packet cannot know the application.
4. **The clock comes from capture timestamps, never wall time** — which makes replay
   deterministic and golden-output tests free.

It also covers the memory model (non-owning views for parsing, owned copies for anything stored
on a session), the flow-key canonicalisation, and the state machine's transition table.

## Roadmap

- [x] Scaffold: CMake, CI on three toolchains, `ByteView` with overflow-safe bounds checking
- [ ] pcap reader — endianness detection, streaming record loop
- [ ] Ethernet / IPv4 decode, header checksum, malformed accounting
- [ ] TCP / UDP decode; libFuzzer targets over the decode path
- [ ] Flow table — symmetric 5-tuple key, index handles
- [ ] TCP session state machine
- [ ] Aging, per-state timeouts, golden-output tests
- [ ] Zone-based policy engine, default deny
- [ ] Verdicts: allow / deny / drop, out-of-state handling
- [ ] App-ID: HTTP, DNS, SSH
- [ ] App-ID: TLS ClientHello and SNI extraction
- [ ] App-ID shift — policy re-evaluation on reclassification
- [ ] Source NAT / PAT
- [ ] CLI, differential testing against tshark, findings write-up

## Non-goals

IPv6, VLAN, fragment reassembly, TCP stream reassembly, TLS decryption, live capture, and packet
forwarding are all deliberately out of scope. See the end of `docs/design.md`.

## Licence

MIT.
