# Fuzz targets. Off by default and clang-only: libFuzzer ships with clang, and
# MSVC's /fsanitize=fuzzer is a different enough animal that supporting both would
# cost more than it returns here. CI runs these on ubuntu-latest with clang.
#
#   cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ -DNANO_FUZZ=ON
#   cmake --build build-fuzz
#   ./build-fuzz/fuzz/fuzz_decode -max_total_time=60 corpus/

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "NANO_FUZZ=ON requires clang (libFuzzer). "
                        "Configure with -DCMAKE_CXX_COMPILER=clang++")
endif()

function(nano_add_fuzzer name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE nano_core)

    # -fsanitize=fuzzer brings its own main(). Address and undefined are what turn
    # an out-of-bounds read from a wrong answer into a crash with a stack trace.
    target_compile_options(${name} PRIVATE
        -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer -g)
    target_link_options(${name} PRIVATE
        -fsanitize=fuzzer,address,undefined)
endfunction()

nano_add_fuzzer(fuzz_decode)
