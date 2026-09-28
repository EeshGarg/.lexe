# A shared library and its consumer, built by cmake, relocatable.
#
# The three lines that matter are the RPATH ones. By default cmake links the
# build tree with an ABSOLUTE rpath pointing at its own build directory and
# rewrites it at install time -- which is exactly the shape the rpath family next
# door records as non-relocatable, and the rewrite never happens for a product
# that is copied rather than installed. Setting BUILD_WITH_INSTALL_RPATH puts the
# final value in at link time, and the final value is $ORIGIN-relative.
cmake_minimum_required(VERSION 3.13)
project(portable_cmake_shared C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_library(shared SHARED libshared.c)
set_target_properties(shared PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../lib")

add_executable(portable-cmake-shared app.c)
target_link_libraries(portable-cmake-shared PRIVATE shared)
target_compile_options(portable-cmake-shared PRIVATE -Wall -Wextra)
set_target_properties(portable-cmake-shared PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../bin"
    BUILD_WITH_INSTALL_RPATH TRUE
    INSTALL_RPATH "$ORIGIN/../lib")
