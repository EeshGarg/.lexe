# A cache variable that changes the product.
#
# Two specimens share this list file: one configured with nothing extra, one with
# -DPORTABLE_FEATURE=ON on the cmake command line. The difference is a compile
# definition and therefore a different binary, which is the cmake equivalent of
# the env_flags pair -- and it is the reason a cmake build directory cannot be
# reused across configurations without being told.
cmake_minimum_required(VERSION 3.13)
project(portable_cmake_option C)

set(CMAKE_C_STANDARD 11)
option(PORTABLE_FEATURE "Compile the optional branch into the product" OFF)

add_executable(portable-cmake-option main.c)
target_compile_definitions(portable-cmake-option PRIVATE CMAKE_SHAPE="option")
target_compile_options(portable-cmake-option PRIVATE -Wall -Wextra)
if(PORTABLE_FEATURE)
    target_compile_definitions(portable-cmake-option PRIVATE PORTABLE_FEATURE_ENABLED=1)
endif()

set_target_properties(portable-cmake-option PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../bin")
