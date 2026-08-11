# Design

## What this is

A stateful packet filter with layer-7 application identification. It reads pcap files, tracks
TCP and UDP sessions, evaluates a zone-based security policy, identifies applications from
payload rather than port number, and applies source NAT. It classifies and decides; it does not
forward packets.

C++17, no third-party dependencies, offline capture input only.

---

## Four load-bearing decisions

### 1. Policy is evaluated once, at session creation — not per packet

This is what "stateful" means. A stateless ACL asks *is this packet allowed?* for every packet.
A stateful filter asks *is this session allowed?* once, on the first packet, and then forwards
subsequent packets of an established session without consulting the rule base.

The visible consequence: return traffic is permitted **because the session exists**, not because
a rule allows it. No inbound rule is needed for the server's SYN+ACK.

Structurally this means `Policy::evaluate` has exactly one call site in the pipeline. If it ever
acquires a second, the design has drifted. The one deliberate exception is App-ID shift (§3).

### 2. One observed session state, not two endpoint state machines

RFC 793 describes an *endpoint*. This is a *middlebox*: it sees both directions and needs only
enough state to decide whether a packet belongs to a conversation it already authorised. It does
not need `TIME_WAIT`, and it does not need to reassemble a byte stream, because it is not
delivering data to an application.

So there is a single simplified session state — `New / SynSeen / SynAckSeen / Established /
FinSeen / Closing / Closed` — rather than a per-side RFC 793 machine. Commercial firewalls make
the same reduction for the same reason.

### 3. App-ID latches late, so policy is re-evaluated when it does

A timing problem that is real rather than academic:

| Packet | What is known |
|---|---|
| 1 — SYN | 5-tuple and ports. Session created, policy evaluated. |
| 2–3 — handshake | Still no payload. |
| 4+ — first payload | Only now can the application be identified. |

The policy decision on packet 1 was therefore made without knowing the application, which is the
one thing an application-aware filter claims to police.

Resolution: evaluate at creation, re-evaluate once when the application latches, and log the
change if the verdict flips. Until it latches, a session's app is `incomplete` (handshake never
finished) or `insufficient-data` (established, too few payload bytes seen).

### 4. The clock comes from the capture, never from wall time

Session aging needs a notion of *now*. It is taken from the pcap packet timestamp.

Two consequences, both wanted. Replay is deterministic, so a given capture always produces
byte-identical output and runs can be diffed — which is what makes debugging the state machine
tractable and golden-output tests free. And a one-hour capture replays in seconds with timeouts
still firing correctly.

A wall-clock call inside the dataplane is a bug.

---

## Memory model

> **Views for parsing. Owned copies for anything stored on a session.**

`PcapReader` streams one packet at a time into a reusable internal buffer and hands out a
non-owning `ByteView`, valid **until the next call to `next()`**. Decoders slice views out of
views; nothing copies. The moment a value must outlive the packet — an SNI hostname, an HTTP
`Host` header — it is copied into a `std::string` on the `Session`.

Streaming rather than mapping the whole file keeps memory flat regardless of capture size, and
imposes the lifetime discipline a real dataplane would have.

### Parse by offset, not by casting a packed struct

Casting a `#pragma pack` struct over the buffer is alignment- and aliasing-unsound, does not fix
byte order, and hides the field offsets. Fields are read explicitly through bounds-checked
accessors, and every decoder returns `bool`.

`false` means malformed: the packet is counted under a specific reason and dropped, never parsed
deeper. Truncated-header handling is where middlebox parser bugs live, so it is a first-class
behaviour rather than an afterthought.

Two traps this codebase treats as load-bearing:

- IPv4 **IHL** is a 4-bit word count; options make the header longer than 20 bytes.
- TCP **data offset** is likewise a 4-bit word count. Hardcoding 20 breaks TLS parsing in a way
  that looks like a TLS bug.

### Bounds checking without overflow

`ByteView::has(off, n)` is written `off <= len && n <= len - off` rather than `off + n <= len`.
The addition overflows: a length field taken off the wire close to `SIZE_MAX` wraps to a small
number and passes a check it should fail. Every input here is attacker-controlled.

Accessors are unchecked and document their precondition; `NANO_ASSERT` turns a violated
precondition into an abort in debug builds, which is the configuration the tests and the fuzzer
run against. `slice()` fails closed to an empty view instead, because slicing is the operation
decoders perform most often and an empty view fails every subsequent `has()` safely.

---

## Flow key

Both directions of a conversation must resolve to one session. The key canonicalises by sorting
the two endpoints, keeping each IP with its own port:

```
FiveTuple { ip_a, port_a, ip_b, port_b, proto }   // sorted so (ip_a,port_a) <= (ip_b,port_b)
```

Sorting the *pair* together is the whole trick. Sorted independently,
`10.0.0.1:80 ↔ 10.0.0.2:443` and `10.0.0.1:443 ↔ 10.0.0.2:80` collapse to the same key.
Direction is recovered from the session, which remembers who sent the first SYN.

The alternative — build the key as seen, retry flipped on a miss — costs two hash lookups per new
flow. Hash fields are combined with `hash_combine`; XOR-ing them raw collides heavily under a
symmetric layout, and a predictable flow-table hash is its own denial-of-service surface.

### Storage

Sessions live in a `std::vector<Session>`; the hash maps store `uint32_t` indices, **not
pointers**. A vector reallocation invalidates every pointer into it. Index handles are stable,
smaller, and double as the session ID shown in the CLI.

Two indices point at the same session — one keyed on the original tuple, one on the
NAT-translated tuple — which is how return traffic for a translated session resolves.

---

## TCP session state machine

Events are `(flags, direction)`, where direction is `c2s` (initiator → responder) or `s2c`.

| Current | Event | Next | Note |
|---|---|---|---|
| *(none)* | SYN, c2s | `SynSeen` | create session, **evaluate policy here** |
| *(none)* | non-SYN | — | drop, counted as out-of-state (see `--midstream`) |
| `SynSeen` | SYN, c2s | `SynSeen` | retransmit; refresh last-seen only |
| `SynSeen` | SYN+ACK, s2c | `SynAckSeen` | |
| `SynAckSeen` | ACK, c2s | `Established` | handshake complete |
| `Established` | FIN, either | `FinSeen` | record which side closed first |
| `FinSeen` | FIN, other side | `Closing` | |
| `FinSeen` | FIN, same side | `FinSeen` | retransmit |
| `Closing` | ACK | `Closed` | |
| *any* | RST | `Closed` | immediate teardown |
| *any* | idle timeout | `Closed` | per-state, below |

UDP has no handshake: the first packet creates the session directly in `Established`, and only
the idle timeout closes it. Statefulness for UDP is purely a timeout, because the protocol
carries nothing to track.

### Timeouts by state

| State | Timeout | Reason |
|---|---|---|
| `SynSeen` | 5 s | half-open; short on purpose — this is the SYN-flood defence |
| `Established` (TCP) | 3600 s | long-lived sessions are legitimate |
| `Established` (UDP) | 30 s | no close signal exists |
| `FinSeen` / `Closing` | 15 s | close in progress; do not hold the entry |
| `Closed` | 0 | reclaimed on the next sweep |

A `Session` is roughly 120 bytes; multiplied by table capacity, that is the filter's state
memory, and it is the resource a SYN flood exhausts — not bandwidth. Aging sweeps every N packets
rather than every packet; a timer wheel is a deliberate non-goal.

---

## Pipeline

```
PcapReader::next()        → ByteView frame, ts_us
  decode_eth              → drop and count non-IPv4 (ARP, IPv6, VLAN)
  decode_ipv4             → verify checksum, honour IHL
  decode_tcp / decode_udp → honour data offset
  build FiveTuple
  FlowTable::lookup_or_create
    if created:  Policy::evaluate     ← the only call site
                 Nat::apply
    always:      TcpState::advance
    if !latched: AppId::classify      → on latch, Policy::evaluate again
  update counters
  every N packets: FlowTable::age_out(ts_us)
```

Module headers do not include each other's internals: `appid.h` knows nothing of `policy.h`.

---

## Non-goals

Stated so that scope reads as chosen rather than abandoned.

IPv6 · VLAN and QinQ · IP fragment reassembly · TCP stream reassembly and out-of-order handling ·
TLS decryption · live capture · IPS signature matching over reassembled streams · timer-wheel
aging · packet forwarding.
