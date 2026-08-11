#pragma once

#include <cstddef>
#include <cstdint>

#include "diag.h"

namespace nano {

/// A non-owning window into bytes owned by somebody else.
///
/// Lifetime
/// --------
/// A view handed out by PcapReader is valid only until the next call to
/// PcapReader::next(), which overwrites the shared read buffer. Decoders slice
/// views out of views and never copy. Anything that must outlive the packet --
/// an SNI hostname, an HTTP Host header -- is copied into owned storage on the
/// Session. See docs/design.md, "Memory model".
///
/// Byte order
/// ----------
/// Every multi-byte accessor reads big-endian, because every field this project
/// parses off the wire is specified that way. There is deliberately no
/// little-endian accessor: the one place byte order varies is the pcap file
/// header itself, and PcapReader resolves that internally rather than leaking
/// the choice into every call site.
class ByteView {
public:
    constexpr ByteView() noexcept = default;
    constexpr ByteView(const uint8_t* data, size_t len) noexcept
        : data_(data), len_(len) {}

    constexpr const uint8_t* data() const noexcept { return data_; }
    constexpr size_t         size() const noexcept { return len_; }
    constexpr bool           empty() const noexcept { return len_ == 0; }

    /// Are there `n` readable bytes starting at `off`?
    ///
    /// Written as two subtractions rather than the obvious `off + n <= len_`
    /// because that addition overflows. A length field taken off the wire can be
    /// close to SIZE_MAX; `off + n` then wraps to a small number and passes a
    /// check it should have failed. Every input to this class is attacker
    /// controlled, so the non-obvious form is the correct one.
    constexpr bool has(size_t off, size_t n) const noexcept {
        return off <= len_ && n <= len_ - off;
    }

    // Preconditions on the three accessors below are the caller's to establish
    // with has(). Violations abort in debug builds -- see diag.h.

    uint8_t u8(size_t off) const noexcept {
        NANO_ASSERT(has(off, 1));
        return data_[off];
    }

    uint16_t u16(size_t off) const noexcept {
        NANO_ASSERT(has(off, 2));
        return static_cast<uint16_t>(static_cast<unsigned>(data_[off]) << 8 |
                                     static_cast<unsigned>(data_[off + 1]));
    }

    uint32_t u32(size_t off) const noexcept {
        NANO_ASSERT(has(off, 4));
        return static_cast<uint32_t>(data_[off]) << 24 |
               static_cast<uint32_t>(data_[off + 1]) << 16 |
               static_cast<uint32_t>(data_[off + 2]) << 8 |
               static_cast<uint32_t>(data_[off + 3]);
    }

    /// Sub-window of `n` bytes at `off`.
    ///
    /// Returns an empty view when the range does not fit, so a caller who forgets
    /// to check gets a view that fails every subsequent has() rather than one
    /// pointing into memory that belongs to somebody else. Failing closed beats
    /// failing loudly here, because slicing is the operation decoders perform
    /// most often.
    constexpr ByteView slice(size_t off, size_t n) const noexcept {
        return has(off, n) ? ByteView(data_ + off, n) : ByteView();
    }

    /// Everything from `off` to the end. Empty if `off` is past the end.
    constexpr ByteView from(size_t off) const noexcept {
        return off <= len_ ? ByteView(data_ + off, len_ - off) : ByteView();
    }

private:
    const uint8_t* data_ = nullptr;
    size_t         len_  = 0;
};

}  // namespace nano
