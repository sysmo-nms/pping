cmake_minimum_required (VERSION 2.6)
project (PPING)

include_directories (
    .
    deps/cargo/
)

add_executable(pping pping.c)
add_executable(ping ping.c)

#tests
enable_testing()
add_test (NAME locahost COMMAND pping --host=127.0.0.1)
