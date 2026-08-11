# One executable per test file. Registering them individually with CTest means a
# crash or an assertion abort fails that test alone instead of the whole suite.

function(nano_add_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE nano_core)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_compile_definitions(${name} PRIVATE
        NANO_CAPTURES_DIR="${NANO_CAPTURES_DIR}")
    add_test(NAME ${name} COMMAND ${name})
endfunction()

nano_add_test(test_byteview)
nano_add_test(test_pcap)
nano_add_test(test_decode)
nano_add_test(test_flow)
nano_add_test(test_tcp_state)

# Golden-output test. Runs the real binary over every fixture and diffs against
# committed expected output -- which pins the whole pipeline at once, including
# the things unit tests miss: table ordering, stats formatting, session counting.
if(Python3_FOUND)
    add_test(NAME golden
             COMMAND "${Python3_EXECUTABLE}"
                     "${CMAKE_CURRENT_SOURCE_DIR}/run_golden.py"
                     "$<TARGET_FILE:nano-ngfw>"
                     "${NANO_CAPTURES_DIR}")
endif()
