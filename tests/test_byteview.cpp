#include <cstdint>

#include "byteview.h"
#include "harness.h"

using nano::ByteView;

int main() {
    const uint8_t raw[8] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04};
    const ByteView v(raw, sizeof raw);

    // --- shape ---------------------------------------------------------------
    CHECK_EQ(v.size(), size_t{8});
    CHECK(!v.empty());
    CHECK(ByteView().empty());
    CHECK_EQ(ByteView().size(), size_t{0});

    // --- big-endian reads ----------------------------------------------------
    CHECK_EQ(v.u8(0), uint8_t{0xDE});
    CHECK_EQ(v.u8(7), uint8_t{0x04});
    CHECK_EQ(v.u16(0), uint16_t{0xDEAD});
    CHECK_EQ(v.u16(6), uint16_t{0x0304});
    CHECK_EQ(v.u32(0), uint32_t{0xDEADBEEF});
    CHECK_EQ(v.u32(4), uint32_t{0x01020304});

    // --- bounds --------------------------------------------------------------
    CHECK(v.has(0, 8));
    CHECK(v.has(8, 0));   // zero bytes at the very end is a legal request
    CHECK(v.has(7, 1));
    CHECK(!v.has(8, 1));
    CHECK(!v.has(0, 9));
    CHECK(!v.has(9, 0));

    // The reason has() is written as two subtractions. Both of these overflow
    // under a naive `off + n <= len` check and would wrongly report success.
    constexpr size_t kHuge = SIZE_MAX;
    CHECK(!v.has(4, kHuge));
    CHECK(!v.has(kHuge, 4));
    CHECK(!v.has(kHuge, kHuge));
    CHECK(!v.has(kHuge - 2, 4));

    // --- slicing -------------------------------------------------------------
    const ByteView tail = v.slice(4, 4);
    CHECK_EQ(tail.size(), size_t{4});
    CHECK_EQ(tail.u32(0), uint32_t{0x01020304});

    // Out-of-range slices fail closed: an empty view, not a view into somebody
    // else's memory.
    CHECK(v.slice(4, 8).empty());
    CHECK(v.slice(kHuge, 1).empty());
    CHECK(v.slice(0, kHuge).empty());

    // A slice of a slice stays inside the original buffer.
    CHECK_EQ(tail.slice(1, 2).size(), size_t{2});
    CHECK_EQ(tail.slice(1, 2).u16(0), uint16_t{0x0203});
    CHECK(tail.slice(1, 4).empty());

    // --- from() --------------------------------------------------------------
    CHECK_EQ(v.from(6).size(), size_t{2});
    CHECK_EQ(v.from(6).u16(0), uint16_t{0x0304});
    CHECK(v.from(8).empty());
    CHECK(v.from(9).empty());
    CHECK(v.from(kHuge).empty());

    return nano::test::summary("byteview");
}
