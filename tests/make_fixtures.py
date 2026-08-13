#!/usr/bin/env python3
"""Generate the pcap fixtures the test suite runs against.

Deliberately dependency-free -- no scapy. Two reasons. The project's own rule is
no third-party dependencies, and a fixture generator that hand-assembles the
bytes documents the wire format a second time, in a second language, which is a
useful cross-check on the C++ decoders reading the same fields back out.

Every fixture isolates one behaviour. None of them is "a capture of me browsing":
a test that fails should name the thing that broke.

    python tests/make_fixtures.py [outdir]      # default: captures/
"""

from __future__ import annotations

import os
import struct
import sys

# ---------------------------------------------------------------------------
# pcap container
# ---------------------------------------------------------------------------

MAGIC_US = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1


def write_pcap(path: str, packets: list[tuple[int, bytes]], endian: str = "<",
               linktype: int = LINKTYPE_ETHERNET, snaplen: int = 65535) -> None:
    """packets is a list of (timestamp_microseconds, frame_bytes)."""
    with open(path, "wb") as f:
        f.write(struct.pack(endian + "IHHiIII", MAGIC_US, 2, 4, 0, 0, snaplen, linktype))
        for ts_us, frame in packets:
            f.write(struct.pack(endian + "IIII",
                                ts_us // 1_000_000, ts_us % 1_000_000,
                                len(frame), len(frame)))
            f.write(frame)


# ---------------------------------------------------------------------------
# protocol builders
# ---------------------------------------------------------------------------

MAC_CLIENT = bytes.fromhex("001122334455")
MAC_ROUTER = bytes.fromhex("66778899aabb")

FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def checksum16(data: bytes) -> int:
    """One's complement sum, as used by both the IPv4 header and TCP/UDP."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def eth(payload: bytes, ethertype: int = 0x0800,
        src: bytes = MAC_CLIENT, dst: bytes = MAC_ROUTER) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ip4(payload: bytes, src: str, dst: str, proto: int,
        options: bytes = b"", ttl: int = 64, ident: int = 0,
        break_checksum: bool = False) -> bytes:
    assert len(options) % 4 == 0, "IPv4 options must be a whole number of words"
    ihl = 5 + len(options) // 4
    total = ihl * 4 + len(payload)
    header = struct.pack("!BBHHHBBH4s4s",
                         0x40 | ihl, 0, total, ident, 0, ttl, proto, 0,
                         bytes(int(o) for o in src.split(".")),
                         bytes(int(o) for o in dst.split("."))) + options
    csum = checksum16(header)
    if break_checksum:
        csum ^= 0xFFFF
    return header[:10] + struct.pack("!H", csum) + header[12:] + payload


def _l4_checksum(src: str, dst: str, proto: int, segment: bytes) -> int:
    pseudo = (bytes(int(o) for o in src.split(".")) +
              bytes(int(o) for o in dst.split(".")) +
              struct.pack("!BBH", 0, proto, len(segment)))
    return checksum16(pseudo + segment)


def tcp(payload: bytes, src: str, dst: str, sport: int, dport: int,
        seq: int, ack: int, flags: int, options: bytes = b"",
        window: int = 64240) -> bytes:
    assert len(options) % 4 == 0, "TCP options must be a whole number of words"
    offset = 5 + len(options) // 4
    header = struct.pack("!HHIIBBHHH", sport, dport, seq, ack,
                         offset << 4, flags, window, 0, 0) + options
    segment = header + payload
    csum = _l4_checksum(src, dst, 6, segment)
    segment = segment[:16] + struct.pack("!H", csum) + segment[18:]
    return ip4(segment, src, dst, 6)


def udp(payload: bytes, src: str, dst: str, sport: int, dport: int) -> bytes:
    header = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    segment = header + payload
    csum = _l4_checksum(src, dst, 17, segment)
    segment = segment[:6] + struct.pack("!H", csum) + segment[8:]
    return ip4(segment, src, dst, 17)


# ---------------------------------------------------------------------------
# application payloads
# ---------------------------------------------------------------------------

def http_get(host: str = "example.com") -> bytes:
    return (f"GET /index.html HTTP/1.1\r\nHost: {host}\r\n"
            f"User-Agent: nano-ngfw-fixture\r\n\r\n").encode()


def tls_client_hello(sni: str) -> bytes:
    """A ClientHello carrying exactly one extension: server_name.

    Built by hand because the extension walk is the fiddliest parsing in the
    project and its fixture should be readable rather than captured.
    """
    host = sni.encode()
    server_name = b"\x00" + struct.pack("!H", len(host)) + host      # type 0 + name
    sni_ext_body = struct.pack("!H", len(server_name)) + server_name  # list length
    extensions = struct.pack("!HH", 0x0000, len(sni_ext_body)) + sni_ext_body

    body = (b"\x03\x03" +                       # client_version TLS 1.2
            bytes(range(32)) +                  # random
            b"\x00" +                           # session_id length
            struct.pack("!H", 2) + b"\x13\x01" +  # one cipher suite
            b"\x01\x00" +                       # one compression method (null)
            struct.pack("!H", len(extensions)) + extensions)

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body  # type + u24 length
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


SSH_BANNER = b"SSH-2.0-OpenSSH_9.6p1\r\n"


def dns_query(name: str = "www.example.com") -> bytes:
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

C, S = "192.168.1.10", "93.184.216.34"
CP, SP = 52341, 80

US = 1_000_000  # one second, for readability below


def f_handshake_clean() -> list[tuple[int, bytes]]:
    """SYN / SYN+ACK / ACK, one request and response, then a clean four-way close."""
    p = []
    p.append((1 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))))
    p.append((1 * US + 10, eth(tcp(b"", S, C, SP, CP, 5000, 1001, SYN | ACK))))
    p.append((1 * US + 20, eth(tcp(b"", C, S, CP, SP, 1001, 5001, ACK))))
    p.append((2 * US, eth(tcp(http_get(), C, S, CP, SP, 1001, 5001, PSH | ACK))))
    body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    p.append((2 * US + 50, eth(tcp(body, S, C, SP, CP, 5001, 1001 + len(http_get()), PSH | ACK))))
    p.append((3 * US, eth(tcp(b"", C, S, CP, SP, 1001 + len(http_get()), 5001 + len(body), FIN | ACK))))
    p.append((3 * US + 10, eth(tcp(b"", S, C, SP, CP, 5001 + len(body), 1002 + len(http_get()), FIN | ACK))))
    p.append((3 * US + 20, eth(tcp(b"", C, S, CP, SP, 1002 + len(http_get()), 5002 + len(body), ACK))))
    return p


def f_rst_midstream() -> list[tuple[int, bytes]]:
    p = []
    p.append((1 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))))
    p.append((1 * US + 10, eth(tcp(b"", S, C, SP, CP, 5000, 1001, SYN | ACK))))
    p.append((1 * US + 20, eth(tcp(b"", C, S, CP, SP, 1001, 5001, ACK))))
    p.append((2 * US, eth(tcp(b"", S, C, SP, CP, 5001, 1001, RST))))
    return p


def f_syn_retransmit() -> list[tuple[int, bytes]]:
    """Three identical SYNs. Must produce one session, not three."""
    return [(1 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))),
            (2 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))),
            (4 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN)))]


def f_fin_both_ways() -> list[tuple[int, bytes]]:
    p = []
    p.append((1 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))))
    p.append((1 * US + 10, eth(tcp(b"", S, C, SP, CP, 5000, 1001, SYN | ACK))))
    p.append((1 * US + 20, eth(tcp(b"", C, S, CP, SP, 1001, 5001, ACK))))
    p.append((2 * US, eth(tcp(b"", S, C, SP, CP, 5001, 1001, FIN | ACK))))   # server closes first
    p.append((2 * US + 30, eth(tcp(b"", C, S, CP, SP, 1001, 5002, FIN | ACK))))
    p.append((2 * US + 40, eth(tcp(b"", S, C, SP, CP, 5002, 1002, ACK))))
    return p


def f_ipv4_options() -> list[tuple[int, bytes]]:
    """IHL = 6. A decoder that hardcodes 20 bytes reads the TCP header four bytes early."""
    # 0x94 = Router Alert, length 4, value 0.
    opts = bytes([0x94, 0x04, 0x00, 0x00])
    seg = struct.pack("!HHIIBBHHH", CP, SP, 1000, 0, 5 << 4, SYN, 64240, 0, 0)
    csum = _l4_checksum(C, S, 6, seg)
    seg = seg[:16] + struct.pack("!H", csum) + seg[18:]
    return [(1 * US, eth(ip4(seg, C, S, 6, options=opts)))]


def f_tcp_options() -> list[tuple[int, bytes]]:
    """Data offset = 8. A decoder that hardcodes 20 bytes finds options where payload should be."""
    # MSS 1460, SACK permitted, timestamps, nop, window scale -- a normal SYN.
    opts = (bytes([0x02, 0x04, 0x05, 0xB4]) + bytes([0x04, 0x02]) +
            bytes([0x08, 0x0A]) + struct.pack("!II", 12345, 0) +
            bytes([0x01]) + bytes([0x03, 0x03, 0x07]))
    return [(1 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN, options=opts)))]


def f_truncated() -> bytes:
    """Written directly: a valid header, one good record, then a record cut short."""
    good = eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))
    blob = struct.pack("<IHHiIII", MAGIC_US, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    blob += struct.pack("<IIII", 1, 0, len(good), len(good)) + good
    blob += struct.pack("<IIII", 2, 0, 200, 200) + b"\xde\xad\xbe\xef"  # claims 200, gives 4
    return blob


def f_bad_magic() -> bytes:
    return b"\x00\x01\x02\x03" + b"\x00" * 40


def f_huge_record() -> bytes:
    """A record header claiming 2 GiB of payload.

    The invitation a length field extends to anyone who trusts it. The reader must
    refuse rather than allocate, which is why PcapReader::kMaxRecord exists.
    """
    blob = struct.pack("<IHHiIII", MAGIC_US, 2, 4, 0, 0, 65535, LINKTYPE_ETHERNET)
    blob += struct.pack("<IIII", 1, 0, 0x80000000, 0x80000000)
    return blob


def f_udp_dns() -> list[tuple[int, bytes]]:
    q = dns_query()
    return [(1 * US, eth(udp(q, C, "8.8.8.8", 53122, 53))),
            (1 * US + 800, eth(udp(q + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22",
                                   "8.8.8.8", C, 53, 53122)))]


def f_out_of_state() -> list[tuple[int, bytes]]:
    """A bare ACK for a session we never saw open. Strict mode must drop and count it."""
    return [(1 * US, eth(tcp(b"", C, S, 44444, SP, 9999, 1, ACK)))]


def f_http_get() -> list[tuple[int, bytes]]:
    p = []
    p.append((1 * US, eth(tcp(b"", C, S, CP, SP, 1000, 0, SYN))))
    p.append((1 * US + 10, eth(tcp(b"", S, C, SP, CP, 5000, 1001, SYN | ACK))))
    p.append((1 * US + 20, eth(tcp(b"", C, S, CP, SP, 1001, 5001, ACK))))
    p.append((1 * US + 30, eth(tcp(http_get(), C, S, CP, SP, 1001, 5001, PSH | ACK))))
    return p


def f_tls_sni() -> list[tuple[int, bytes]]:
    p = []
    p.append((1 * US, eth(tcp(b"", C, "142.250.183.14", 52344, 443, 2000, 0, SYN))))
    p.append((1 * US + 10, eth(tcp(b"", "142.250.183.14", C, 443, 52344, 7000, 2001, SYN | ACK))))
    p.append((1 * US + 20, eth(tcp(b"", C, "142.250.183.14", 52344, 443, 2001, 7001, ACK))))
    p.append((1 * US + 30, eth(tcp(tls_client_hello("www.google.com"), C, "142.250.183.14",
                                   52344, 443, 2001, 7001, PSH | ACK))))
    return p


def f_ssh_on_443() -> list[tuple[int, bytes]]:
    """The evasion demo: SSH speaking on 443. Port says web, payload says ssh."""
    p = []
    p.append((1 * US, eth(tcp(b"", C, "203.0.113.9", 55000, 443, 3000, 0, SYN))))
    p.append((1 * US + 10, eth(tcp(b"", "203.0.113.9", C, 443, 55000, 9000, 3001, SYN | ACK))))
    p.append((1 * US + 20, eth(tcp(b"", C, "203.0.113.9", 55000, 443, 3001, 9001, ACK))))
    p.append((1 * US + 30, eth(tcp(SSH_BANNER, "203.0.113.9", C, 443, 55000, 9001, 3001, PSH | ACK))))
    return p


def f_bad_ip_checksum() -> list[tuple[int, bytes]]:
    seg = struct.pack("!HHIIBBHHH", CP, SP, 1000, 0, 5 << 4, SYN, 64240, 0, 0)
    return [(1 * US, eth(ip4(seg, C, S, 6, break_checksum=True)))]


def f_non_ipv4() -> list[tuple[int, bytes]]:
    """ARP and IPv6 frames. Counted and skipped, never decoded."""
    arp = bytes.fromhex("0001080006040001") + MAC_CLIENT + bytes([192, 168, 1, 10]) + \
          bytes(6) + bytes([192, 168, 1, 1])
    return [(1 * US, eth(arp, ethertype=0x0806)),
            (2 * US, eth(bytes(40), ethertype=0x86DD))]


def f_big_endian() -> list[tuple[int, bytes]]:
    """Same content as handshake_clean, written by a big-endian writer."""
    return f_handshake_clean()


def f_demo() -> list[tuple[int, bytes]]:
    """Everything interesting in one capture, for the HTML report.

    Eight conversations chosen so the session table shows every verdict and both
    of the behaviours that distinguish this from a packet filter: an App-ID shift
    tearing down a session admitted by port, and an out-of-state packet refused
    for belonging to no session at all.

    Timestamps are spread over a few seconds so the report's durations look like
    traffic rather than like a test.
    """
    p: list[tuple[int, bytes]] = []

    def handshake(cip, cport, sip, sport, t, cseq=1000, sseq=5000):
        p.append((t, eth(tcp(b"", cip, sip, cport, sport, cseq, 0, SYN))))
        p.append((t + 8000, eth(tcp(b"", sip, cip, sport, cport, sseq, cseq + 1, SYN | ACK))))
        p.append((t + 15000, eth(tcp(b"", cip, sip, cport, sport, cseq + 1, sseq + 1, ACK))))

    # 1. Ordinary web browsing -- identified as web-browsing, allowed.
    handshake(C, 52341, S, 80, 1 * US)
    p.append((1 * US + 22000, eth(tcp(http_get("example.com"), C, S, 52341, 80, 1001, 5001, PSH | ACK))))
    body = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    p.append((1 * US + 60000, eth(tcp(body, S, C, 80, 52341, 5001, 1001 + len(http_get("example.com")), PSH | ACK))))

    # 2. Genuine TLS -- identified as ssl, SNI extracted, allowed.
    G = "142.250.183.14"
    handshake(C, 52344, G, 443, 2 * US, cseq=2000, sseq=7000)
    p.append((2 * US + 21000, eth(tcp(tls_client_hello("www.google.com"), C, G, 52344, 443, 2001, 7001, PSH | ACK))))

    # 3. THE DEMO. SSH speaking on 443. Admitted by the port, then identified by
    #    payload, re-judged against the application, and torn down.
    X = "203.0.113.9"
    handshake(C, 55000, X, 443, 3 * US, cseq=3000, sseq=9000)
    p.append((3 * US + 24000, eth(tcp(SSH_BANNER, X, C, 443, 55000, 9001, 3001, PSH | ACK))))

    # 4. DNS -- the one application still gated on a port, and honest about it.
    p.append((4 * US, eth(udp(dns_query("www.example.com"), C, "8.8.8.8", 53122, 53))))
    p.append((4 * US + 12000, eth(udp(dns_query("www.example.com") +
                                      b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x5d\xb8\xd8\x22",
                                      "8.8.8.8", C, 53, 53122))))

    # 5. Telnet outbound -- matched by an explicit block rule, denied.
    p.append((5 * US, eth(tcp(b"", "192.168.1.22", "198.51.100.7", 41000, 23, 4000, 0, SYN))))

    # 6. Unsolicited inbound to SMB -- dropped silently rather than refused, so a
    #    scanner learns nothing about whether the host exists.
    p.append((6 * US, eth(tcp(b"", "203.0.113.44", C, 40000, 445, 6000, 0, SYN))))

    # 7. A bare ACK for a conversation nobody saw open. No session, counted.
    p.append((7 * US, eth(tcp(b"", C, S, 44444, 80, 9999, 1, ACK))))

    # 8. A second web session, closed cleanly, so the table shows a CLOSED row
    #    next to the live ones.
    handshake(C, 52400, S, 80, 8 * US, cseq=1500, sseq=5500)
    p.append((8 * US + 20000, eth(tcp(http_get("example.com"), C, S, 52400, 80, 1501, 5501, PSH | ACK))))
    seq = 1501 + len(http_get("example.com"))
    p.append((8 * US + 90000, eth(tcp(b"", C, S, 52400, 80, seq, 5501, FIN | ACK))))
    p.append((8 * US + 95000, eth(tcp(b"", S, C, 80, 52400, 5501, seq + 1, FIN | ACK))))
    p.append((8 * US + 99000, eth(tcp(b"", C, S, 52400, 80, seq + 1, 5502, ACK))))

    return p


def main() -> int:
    outdir = sys.argv[1] if len(sys.argv) > 1 else "captures"
    os.makedirs(outdir, exist_ok=True)

    simple = {
        "handshake_clean": f_handshake_clean(),
        "rst_midstream":   f_rst_midstream(),
        "syn_retransmit":  f_syn_retransmit(),
        "fin_both_ways":   f_fin_both_ways(),
        "ipv4_options":    f_ipv4_options(),
        "tcp_options":     f_tcp_options(),
        "udp_dns":         f_udp_dns(),
        "out_of_state":    f_out_of_state(),
        "http_get":        f_http_get(),
        "tls_sni":         f_tls_sni(),
        "ssh_on_443":      f_ssh_on_443(),
        "bad_ip_checksum": f_bad_ip_checksum(),
        "non_ipv4":        f_non_ipv4(),
        "demo":            f_demo(),
    }
    for name, packets in simple.items():
        write_pcap(os.path.join(outdir, name + ".pcap"), packets)

    # Byte order is discovered at runtime, so one fixture exercises the other path.
    write_pcap(os.path.join(outdir, "big_endian.pcap"), f_big_endian(), endian=">")

    # Two files that are not valid captures at all.
    with open(os.path.join(outdir, "truncated.pcap"), "wb") as f:
        f.write(f_truncated())
    with open(os.path.join(outdir, "bad_magic.pcap"), "wb") as f:
        f.write(f_bad_magic())
    with open(os.path.join(outdir, "huge_record.pcap"), "wb") as f:
        f.write(f_huge_record())
    write_pcap(os.path.join(outdir, "empty.pcap"), [])

    count = len(simple) + 5
    print(f"wrote {count} fixtures to {outdir}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
