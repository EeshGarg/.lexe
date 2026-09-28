# cmake with the C++ compiler. project(... CXX) is what makes cmake probe for a
# C++ compiler at configure time rather than a C one, and getting that wrong is a
# configure-time failure with a message about a missing compiler on a host that
# has one.
cmake_minimum_required(VERSION 3.13)
project(portable_cmake_cxx CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(portable-cmake-cxx main.cpp)
target_compile_options(portable-cmake-cxx PRIVATE -Wall -Wextra)

set_target_properties(portable-cmake-cxx PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../bin")
