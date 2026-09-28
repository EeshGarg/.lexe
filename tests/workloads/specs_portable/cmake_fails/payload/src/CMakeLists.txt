# A build that fails at CONFIGURE, which is a stage the make recipes do not have.
#
# Nothing is compiled, no object exists, and the diagnostic comes from cmake
# rather than from a compiler -- but a partial build tree DOES exist, because
# cmake writes its cache before it gets as far as this line. A consumer that
# treats "the build directory has contents" as evidence of progress is wrong
# here.
#
# find_package(... REQUIRED) for a package that cannot be installed is the
# ordinary way this happens to people: a missing dependency, discovered at
# configure time, on a host that has a perfectly good compiler.
cmake_minimum_required(VERSION 3.13)
project(portable_cmake_fails C)

find_package(LexeNonexistentPackage REQUIRED)

add_executable(portable-cmake-fails main.c)
