#include "nat.h"

namespace nano {

bool NatPool::allocate(uint16_t& port) {
    if (!enabled()) return false;
    if (in_use_ >= last_port_ - first_port_) return false;  // pool drained

    port = next_port_;

    // Linear allocation with wraparound. A production implementation tracks which
    // ports are actually free so a released port is reusable immediately; here the
    // pool is large relative to any test capture, and the simpler version keeps
    // the interesting part -- that ports are the scarce resource -- visible.
    next_port_ = (next_port_ >= last_port_) ? first_port_
                                            : static_cast<uint16_t>(next_port_ + 1);
    ++in_use_;
    return true;
}

void NatPool::release(uint16_t) {
    if (in_use_ > 0) --in_use_;
}

}  // namespace nano
