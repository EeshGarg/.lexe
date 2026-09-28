# Two things this recipe covers that the flat cmake recipe does not:
#
#   * add_subdirectory, so the build has more than one list file and a target
#     that depends on a target rather than on a file;
#   * install(TARGETS), so the product reaches payload/bin through `cmake
#     --install --prefix <payload>` rather than through an output-directory
#     property. The two idioms put the file in the same place and fail
#     differently: an output-directory property puts it there as a side effect of
#     linking, while install() puts it there only if the install step runs at all.
cmake_minimum_required(VERSION 3.13)
project(portable_cmake_subdir C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_subdirectory(lib)

add_executable(portable-cmake-subdir main.c)
target_link_libraries(portable-cmake-subdir PRIVATE portable_subdir_util)
target_compile_definitions(portable-cmake-subdir PRIVATE CMAKE_SHAPE="subdir-install")
target_compile_options(portable-cmake-subdir PRIVATE -Wall -Wextra)

install(TARGETS portable-cmake-subdir RUNTIME DESTINATION bin)
