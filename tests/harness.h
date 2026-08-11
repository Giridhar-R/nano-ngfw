#pragma once

#include <cstdio>

// A test harness in forty lines, because the project has no third-party
// dependencies and a packet decoder does not need a framework to check that a
// field came out equal to a number.
//
// Each test file is its own executable with its own main(), registered with
// CTest by tests/CMakeLists.txt. A crash therefore fails exactly one test rather
// than taking the suite down -- which matters once the fuzzer starts finding
// aborts in debug builds.

namespace nano::test {

inline int g_checks   = 0;
inline int g_failures = 0;

inline void report(bool ok, const char* expr, const char* file, int line) {
    ++g_checks;
    if (!ok) {
        ++g_failures;
        std::fprintf(stderr, "FAIL  %s:%d\n      %s\n", file, line, expr);
    }
}

inline int summary(const char* suite) {
    std::printf("%-16s %3d checks, %d failures\n", suite, g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}

}  // namespace nano::test

#define CHECK(expr) ::nano::test::report((expr), #expr, __FILE__, __LINE__)

#define CHECK_EQ(a, b) \
    ::nano::test::report((a) == (b), #a " == " #b, __FILE__, __LINE__)
