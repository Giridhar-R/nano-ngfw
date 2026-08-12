cmake_minimum_required(VERSION 3.20)

project(nano_ngfw
        VERSION 0.1.0
        DESCRIPTION "Stateful packet filter with L7 application identification"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Default to Debug for single-config generators. Debug is where NANO_ASSERT and
# the sanitizers are live, and it is the configuration the fuzzer runs against.
if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

option(NANO_WERROR   "Treat warnings as errors"        ON)
option(NANO_SANITIZE "Enable ASan + UBSan (non-MSVC)"  OFF)
option(NANO_FUZZ     "Build libFuzzer targets (clang)" OFF)

# ---------------------------------------------------------------------------
# Shared compile settings, carried by an INTERFACE target so every real target
# picks them up by linking one thing.
# ---------------------------------------------------------------------------
add_library(nano_flags INTERFACE)

if(MSVC)
    target_compile_options(nano_flags INTERFACE /W4 /permissive- /utf-8)
    if(NANO_WERROR)
        target_compile_options(nano_flags INTERFACE /WX)
    endif()
else()
    # -Wconversion and -Wsign-conversion are on deliberately. This codebase does
    # nothing but move values between differently sized integer types pulled off
    # the wire, which is exactly where silent truncation bugs live.
    target_compile_options(nano_flags INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    if(NANO_WERROR)
        target_compile_options(nano_flags INTERFACE -Werror)
    endif()
    if(NANO_SANITIZE)
        target_compile_options(nano_flags INTERFACE
            -fsanitize=address,undefined -fno-omit-frame-pointer -g)
        target_link_options(nano_flags INTERFACE -fsanitize=address,undefined)
    endif()
endif()

# ---------------------------------------------------------------------------
# Core library. Everything except main() lives here so the tests and the fuzz
# targets can link the same code the binary runs.
# ---------------------------------------------------------------------------
add_library(nano_core STATIC
    src/appid.cpp
    src/cli.cpp
    src/decode.cpp
    src/engine.cpp
    src/flow.cpp
    src/nat.cpp
    src/pcap.cpp
    src/policy.cpp
    src/tcp_state.cpp
    src/version.cpp)

target_include_directories(nano_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_definitions(nano_core PRIVATE NANO_VERSION="${PROJECT_VERSION}")
target_link_libraries(nano_core PUBLIC nano_flags)

# ---------------------------------------------------------------------------
add_executable(nano-ngfw src/main.cpp)
target_link_libraries(nano-ngfw PRIVATE nano_core)

# ---------------------------------------------------------------------------
# Test fixtures.
#
# The pcaps are generated rather than committed: tests/make_fixtures.py is the
# source of truth, so a fixture can be read and reviewed as code instead of
# inspected as an opaque blob. Generating at configure time keeps a fresh clone
# one `cmake` away from a runnable test suite.
# ---------------------------------------------------------------------------
set(NANO_CAPTURES_DIR "${CMAKE_CURRENT_SOURCE_DIR}/captures")

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/make_fixtures.py"
                "${NANO_CAPTURES_DIR}"
        RESULT_VARIABLE nano_fixture_result
        OUTPUT_VARIABLE nano_fixture_output)
    if(NOT nano_fixture_result EQUAL 0)
        message(FATAL_ERROR "fixture generation failed: ${nano_fixture_output}")
    endif()
    message(STATUS "nano-ngfw: ${nano_fixture_output}")

    # Also expose it as a target, for regenerating after editing the generator.
    add_custom_target(fixtures
        COMMAND "${Python3_EXECUTABLE}"
                "${CMAKE_CURRENT_SOURCE_DIR}/tests/make_fixtures.py"
                "${NANO_CAPTURES_DIR}"
        COMMENT "Regenerating pcap fixtures")
else()
    message(WARNING "Python3 not found -- pcap fixtures cannot be generated and "
                    "the capture-driven tests will fail.")
endif()

# ---------------------------------------------------------------------------
enable_testing()
add_subdirectory(tests)

if(NANO_FUZZ)
    add_subdirectory(fuzz)
endif()
