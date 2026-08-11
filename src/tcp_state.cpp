#include "tcp_state.h"

#include "decode.h"

namespace nano {

void tcp_advance(Session& s, uint8_t flags, bool to_initiator) {
    const bool syn = (flags & tcp_flag::kSyn) != 0;
    const bool ack = (flags & tcp_flag::kAck) != 0;
    const bool fin = (flags & tcp_flag::kFin) != 0;
    const bool rst = (flags & tcp_flag::kRst) != 0;

    // RST first, and from any state. A reset is not part of the graceful
    // sequence; it ends the conversation wherever it happened to be.
    //
    // Note what is *not* checked: whether the sequence number is inside the
    // receive window. A real firewall validates that, because otherwise an
    // off-path attacker who can guess the tuple can tear down sessions with a
    // forged RST. Sequence tracking is a non-goal here, so this machine trusts
    // the flag -- a limitation to name before someone else does.
    if (rst) {
        s.state = SessionState::Closed;
        return;
    }

    switch (s.state) {
        case SessionState::New:
            // A session is only ever created off a pure SYN in strict mode, so
            // this is the ordinary path. Midstream pickup lands here too, with a
            // packet that is not a SYN, and jumps straight to Established.
            if (syn && !ack && !to_initiator) {
                s.state = SessionState::SynSeen;
            } else {
                s.state = SessionState::Established;
            }
            break;

        case SessionState::SynSeen:
            if (syn && ack && to_initiator) {
                s.state = SessionState::SynAckSeen;
            }
            // A repeated SYN from the initiator is a retransmit. Deliberately no
            // state change and no complaint: the client is impatient, not hostile,
            // and captures/syn_retransmit asserts one session comes out of three
            // identical SYNs.
            break;

        case SessionState::SynAckSeen:
            // The third leg. Only an ACK from the initiator completes it; a
            // repeated SYN+ACK from the responder is another retransmit.
            if (ack && !syn && !to_initiator) {
                s.state = SessionState::Established;
            }
            break;

        case SessionState::Established:
            if (fin) {
                s.state              = SessionState::FinSeen;
                s.fin_from_initiator = !to_initiator;
            }
            break;

        case SessionState::FinSeen: {
            // Close is four-way: each direction shuts down independently. Only a
            // FIN from the *other* end advances the state. A FIN from the side
            // that already closed is a retransmit, which is why the machine has
            // to remember who went first.
            const bool from_initiator = !to_initiator;
            if (fin && from_initiator != s.fin_from_initiator) {
                s.state = SessionState::Closing;
            }
            break;
        }

        case SessionState::Closing:
            // The final ACK. After this the endpoints still owe each other a
            // TIME_WAIT, but that is an endpoint concern -- nothing more will
            // legitimately arrive on this conversation, so the entry can go.
            if (ack) {
                s.state = SessionState::Closed;
            }
            break;

        case SessionState::Closed:
            // Terminal. Late duplicates arriving after teardown change nothing;
            // the aging sweep will reap the entry.
            break;
    }
}

void udp_advance(Session& s) {
    if (s.state == SessionState::New) {
        s.state = SessionState::Established;
    }
}

}  // namespace nano
