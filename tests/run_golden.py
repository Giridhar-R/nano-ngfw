#!/usr/bin/env python3
"""Golden-output tests: run the binary over every fixture, diff against expected.

Cheap because of a design decision made much earlier. The engine takes its clock
from the pcap timestamps rather than a wall clock, so two runs over the same
capture produce byte-identical output -- which makes a committed expected-output
file a valid assertion rather than a flaky one.

What this buys that unit tests do not: it pins the *whole pipeline* at once.
A refactor that quietly changes how a session is counted, or reorders the table,
or drops a stats line, fails here even when every unit test still passes.

    python tests/run_golden.py <binary> <captures-dir> [--update]

--update rewrites the expected files. Review the diff before committing it; the
point of a golden test is that changes to it are deliberate.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN_DIR = os.path.join(HERE, "golden")

# Captures that are not valid pcap files. They exercise the reader's error paths,
# which the unit tests already cover, and the binary exits non-zero on them.
SKIP = {"bad_magic.pcap", "huge_record.pcap"}

# A couple of fixtures are worth running twice, because the interesting behaviour
# is the difference between the two modes.
EXTRA_ARGS = {
    "out_of_state.pcap": [("midstream", ["--midstream"])],
}


def run_case(binary: str, capture: str, args: list[str]) -> str:
    result = subprocess.run([binary, *args, capture],
                            capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise SystemExit(f"{os.path.basename(capture)}: exit {result.returncode}\n"
                         f"{result.stderr}")
    # Normalise line endings so a Windows run and a Linux run agree.
    return result.stdout.replace("\r\n", "\n")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("captures")
    ap.add_argument("--update", action="store_true")
    opts = ap.parse_args()

    os.makedirs(GOLDEN_DIR, exist_ok=True)

    cases: list[tuple[str, str, list[str]]] = []
    for name in sorted(os.listdir(opts.captures)):
        if not name.endswith(".pcap") or name in SKIP:
            continue
        stem = name[:-5]
        cases.append((stem, name, []))
        for suffix, args in EXTRA_ARGS.get(name, []):
            cases.append((f"{stem}.{suffix}", name, args))

    failures = 0
    for label, name, args in cases:
        actual = run_case(opts.binary, os.path.join(opts.captures, name), args)
        expected_path = os.path.join(GOLDEN_DIR, label + ".txt")

        if opts.update:
            with open(expected_path, "w", newline="\n") as f:
                f.write(actual)
            continue

        if not os.path.exists(expected_path):
            print(f"MISSING  {label}.txt -- rerun with --update")
            failures += 1
            continue

        with open(expected_path, newline="") as f:
            expected = f.read().replace("\r\n", "\n")

        if actual != expected:
            failures += 1
            print(f"FAIL     {label}")
            import difflib
            for line in difflib.unified_diff(expected.splitlines(), actual.splitlines(),
                                             "expected", "actual", lineterm="", n=2):
                print("    " + line)

    if opts.update:
        print(f"updated {len(cases)} golden files")
        return 0

    print(f"golden           {len(cases)} cases, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
