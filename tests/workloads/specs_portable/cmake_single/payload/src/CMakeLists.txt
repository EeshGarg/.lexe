# The cmake recipe. Two things here are not decoration:
#
#   * CMAKE_RUNTIME_OUTPUT_DIRECTORY, because the manifest declares the
#     entrypoint as payload/bin/portable-cmake and cmake would otherwise leave
#     the binary wherever its build tree happens to be;
#   * PORTABLE_VIA_CMAKE, a define the program prints, so "cmake really compiled
#     this" is an observable fact rather than an assumption about which driver
#     ran.
cmake_minimum_required(VERSION 3.13)
project(portable_cmake C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(portable-cmake main.c)
target_compile_definitions(portable-cmake PRIVATE PORTABLE_VIA_CMAKE=1)
target_compile_options(portable-cmake PRIVATE -Wall -Wextra)

# Relative to this list file's directory: payload/src/../bin == payload/bin.
set_target_properties(portable-cmake PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../bin")
