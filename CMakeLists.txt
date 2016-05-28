cmake_minimum_required (VERSION 2.6)
project (PPING)

include_directories (
    deps/cargo/
)

add_executable(pping pping.c)
