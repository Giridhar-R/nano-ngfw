#pragma once

#include <cstdio>

#include "engine.h"

namespace nano {

// ---------------------------------------------------------------------------
// Output shaped after PAN-OS.
//
// Borrowing the vocabulary -- sessions, zones, App-ID names, a session table
// addressed by id -- is not decoration. It is the mental model the domain is
// actually organised around, and a session table reads far better than a packet
// log for anyone who has looked at a firewall before.
//
// Everything printed here is derived from the capture clock, so two runs over the
// same file produce byte-identical output. That is what makes the golden tests in
// tests/run_golden.py possible.
// ---------------------------------------------------------------------------

/// `show session all` -- one line per session, creation order.
void print_sessions(std::FILE* out, const Engine& e);

/// `show session id <n>` -- everything known about one session.
void print_session_detail(std::FILE* out, const Engine& e, uint32_t id);

/// `show stats` -- packet classification, decode failures, session totals.
void print_stats(std::FILE* out, const Engine& e);

}  // namespace nano
