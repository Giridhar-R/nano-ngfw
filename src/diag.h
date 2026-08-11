#pragma once

#include <cstdio>
#include <cstdlib>

// Debug-only contract check.
//
// The parser accessors in byteview.h are deliberately unchecked: each one
// documents a precondition that the caller establishes with ByteView::has().
// That keeps the hot path free of redundant branches, but it means a forgotten
// bounds check reads out of bounds instead of failing loudly.
//
// NANO_ASSERT closes that gap where it matters. Debug builds abort on a
// violated precondition, and debug is the configuration the test suite and the
// fuzzer both run against -- so a missing has() becomes a reproducible crash
// with a file and line, rather than a silent out-of-bounds read that only shows
// up as a wrong answer three layers later.
//
// Release builds compile it away entirely.

#if defined(NDEBUG)

#define NANO_ASSERT(cond) ((void)0)

#else

namespace nano::detail {

[[noreturn]] inline void assert_failed(const char* expr, const char* file, int line) {
    std::fprintf(stderr, "nano: assertion failed: %s\n  at %s:%d\n", expr, file, line);
    std::abort();
}

}  // namespace nano::detail

#define NANO_ASSERT(cond) \
    ((cond) ? (void)0 : ::nano::detail::assert_failed(#cond, __FILE__, __LINE__))

#endif
