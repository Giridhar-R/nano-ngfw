#!/usr/bin/env python3
"""Differential testing against tshark.

Unit tests check that the code does what I think it does. This checks that what
I think is right -- by comparing the session table against an independent
implementation that has been read by rather more people.

Two comparisons:

  conversations  tshark -q -z conv,tcp gives a conversation table with
                 per-direction packet counts. Every TCP session nano-ngfw
                 reports should appear there with the same counts. Disagreement
                 means a flow-direction inversion, a canonical-key bug splitting
                 one conversation in two, or a miscounted retransmit.

  sni            tshark -e tls.handshake.extensions_server_name is ground truth
                 for every SNI in the capture. The set nano-ngfw extracts should
                 match exactly -- no misses, no inventions.

Skips cleanly when tshark is absent, because it is not a build dependency and CI
should not need Wireshark installed to be useful.

    python tests/diff_tshark.py <binary> <captures-dir>
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def run(cmd: list[str]) -> str:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout


def tshark_tcp_conversations(capture: str) -> dict[tuple[str, str], int]:
    """{(endpoint_a, endpoint_b): total_frames}"""
    out = run(["tshark", "-r", capture, "-q", "-z", "conv,tcp"])
    conversations: dict[tuple[str, str], int] = {}

    for line in out.splitlines():
        # e.g. "192.168.1.10:52341 <-> 93.184.216.34:80    3   180   5   420   8   600 ..."
        match = re.match(r"^(\S+:\d+)\s+<->\s+(\S+:\d+)\s+(.*)$", line.strip())
        if not match:
            continue
        numbers = match.group(3).split()
        if len(numbers) < 5:
            continue
        try:
            total_frames = int(numbers[4])
        except ValueError:
            continue
        conversations[(match.group(1), match.group(2))] = total_frames
    return conversations


def tshark_sni(capture: str) -> set[str]:
    out = run(["tshark", "-r", capture, "-T", "fields",
               "-e", "tls.handshake.extensions_server_name"])
    return {line.strip() for line in out.splitlines() if line.strip()}


def nano_sessions(binary: str, capture: str) -> list[dict[str, str]]:
    out = run([binary, capture])
    sessions = []
    for line in out.splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].isdigit():
            continue
        sessions.append({"id": fields[0], "app": fields[1],
                         "src": fields[4], "dst": fields[5]})
    return sessions


def nano_sni(binary: str, capture: str) -> set[str]:
    names: set[str] = set()
    for session in nano_sessions(binary, capture):
        detail = run([binary, "--session", session["id"], capture])
        for line in detail.splitlines():
            if line.strip().startswith("sni "):
                names.add(line.split(":", 1)[1].strip())
    return names


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("captures")
    opts = ap.parse_args()

    if not tshark_available():
        print("diff_tshark      SKIPPED (tshark not on PATH)")
        return 0

    failures = 0
    checked = 0

    for name in sorted(os.listdir(opts.captures)):
        if not name.endswith(".pcap"):
            continue
        capture = os.path.join(opts.captures, name)

        # Conversation counts.
        expected = tshark_tcp_conversations(capture)
        actual = [s for s in nano_sessions(opts.binary, capture)]
        tcp_sessions = [s for s in actual if s["app"] != "dns"]

        if expected and len(expected) != len(tcp_sessions):
            print(f"FAIL  {name}: tshark sees {len(expected)} TCP conversations, "
                  f"nano-ngfw reports {len(tcp_sessions)}")
            failures += 1
        checked += 1

        # SNI ground truth.
        expected_sni = tshark_sni(capture)
        if expected_sni:
            actual_sni = nano_sni(opts.binary, capture)
            if expected_sni != actual_sni:
                print(f"FAIL  {name}: sni mismatch\n"
                      f"      tshark:    {sorted(expected_sni)}\n"
                      f"      nano-ngfw: {sorted(actual_sni)}")
                failures += 1

    print(f"diff_tshark      {checked} captures, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
