# One executable per test file. Registering them individually with CTest means a
# crash or an assertion abort fails that test alone instead of the whole suite.

function(nano_add_test name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries(${name} PRIVATE nano_core)
    target_include_directories(${name} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    add_test(NAME ${name} COMMAND ${name})
endfunction()

nano_add_test(test_byteview)
