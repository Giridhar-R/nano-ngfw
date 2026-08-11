#pragma once

#include <cstdint>

#include "flow.h"

namespace nano {

// ---------------------------------------------------------------------------
// The observed-session state machine.
//
// The design decision worth defending is in flow.h next to SessionState: this is
// not RFC 793. That document specifies an endpoint, which owns one half of a
// connection, must retransmit what it sent, reassemble what it receives, and
// linger in TIME_WAIT to absorb duplicates from the old incarnation. None of that
// is a middlebox's problem.
//
// A firewall sees both directions of the conversation and needs exactly one
// thing: enough state to decide whether an arriving packet belongs to a
// conversation it has already authorised. That is a much smaller machine --
// seven states rather than eleven, driven by flags and direction alone, with no
// sequence-number tracking and no timers beyond an idle clock.
//
// What that reduction costs, stated plainly because it is the obvious follow-up
// question: this machine cannot detect an off-path RST injection, because it does
// not check that the RST's sequence number falls in the receive window. It cannot
// detect a sequence-number-overlap evasion, because it does not reassemble. Both
// are deliberate non-goals -- see docs/design.md -- and both are exactly the
// features that separate a teaching implementation from a product.
// ---------------------------------------------------------------------------

/// Applies one TCP packet to a session.
///
/// `to_initiator` is true when the packet flows responder -> initiator. The pair
/// (flags, direction) is the entire event alphabet.
///
/// Retransmissions are absorbed rather than rejected: a duplicate SYN leaves the
/// state alone. A firewall that treated the second SYN as a new event would
/// either create a second session or tear the first one down, and ordinary
/// networks retransmit constantly.
void tcp_advance(Session& s, uint8_t flags, bool to_initiator);

/// Applies one UDP packet to a session.
///
/// UDP has no handshake and no close, so statefulness for it is purely a timeout:
/// the first packet establishes the session and only the idle clock ever closes
/// it. There is nothing in the protocol to track, which is worth saying out loud
/// because "how is a firewall stateful for UDP?" is a question with a short and
/// frequently fumbled answer.
void udp_advance(Session& s);

}  // namespace nano
