#pragma once

#include <cstdint>

namespace nano {

// ---------------------------------------------------------------------------
// Source NAT with port translation.
//
// Two things worth being able to say about NAT, because both come up:
//
// It is not a security control. It is an address-conservation mechanism that
// happens to break unsolicited inbound connections as a side effect, and that
// side effect gets mistaken for a policy. The thing actually refusing inbound
// traffic is the session table -- there is no entry to match, so the packet is
// out of state. Turn the firewall's policy to allow-any and NAT will still
// "block" inbound traffic, which is exactly why relying on it is a mistake:
// nothing is enforcing anything.
//
// The translation table and the session table are the same table. A NAT binding
// is not a separate object with its own lifetime; it is two more fields on the
// session, created with it and reclaimed with it. That is why NAT bindings expire
// when sessions do, and why a firewall's NAT capacity and its session capacity
// are the same number.
// ---------------------------------------------------------------------------

/// Allocates translated source ports for outbound sessions.
///
/// PAT rather than one-to-one NAT: many internal hosts share one public address,
/// distinguished by the allocated source port. That is what makes a single
/// address serve a whole network, and it is why the port -- not the address -- is
/// the scarce resource.
class NatPool {
public:
    NatPool() = default;

    /// `public_ip` is the address outbound traffic is translated to.
    explicit NatPool(uint32_t public_ip, uint16_t first_port = 40000,
                     uint16_t last_port = 60000)
        : public_ip_(public_ip), first_port_(first_port), last_port_(last_port),
          next_port_(first_port) {}

    bool enabled() const { return public_ip_ != 0; }

    uint32_t public_ip() const { return public_ip_; }

    /// Takes the next free port. Returns false when the pool is exhausted --
    /// which is a real failure mode, not a theoretical one: a single host opening
    /// thousands of connections can drain a small pool and deny service to
    /// everyone else behind the same address.
    bool allocate(uint16_t& port);

    /// Returns a port to the pool when its session is retired.
    void release(uint16_t port);

    uint16_t in_use() const { return in_use_; }

private:
    uint32_t public_ip_  = 0;
    uint16_t first_port_ = 0;
    uint16_t last_port_  = 0;
    uint16_t next_port_  = 0;
    uint16_t in_use_     = 0;
};

}  // namespace nano
