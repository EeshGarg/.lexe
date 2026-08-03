# Tux32 Core 1 CMake toolchain (portability milestone).
#
# This is a MINIMAL, documented toolchain file — NOT a packaged SDK. It makes
# the Core 1 target explicit and pins the CPU baseline; it deliberately does not
# download, assemble, or manage a sysroot.
#
# The glibc symbol ceiling (2.31) is enforced by the SYSROOT you build against,
# not by a compiler flag: a compiler cannot invent symbols its glibc headers and
# libraries do not define. So the reliable way to produce a Core 1 binary is to
# build inside a sysroot whose glibc is <= 2.31 (see build-in-sysroot.sh), and
# ALWAYS confirm the result with `lexe sdk verify`.

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# x86-64-v1 baseline, so the binary runs across the full Core 1 CPU range.
set(_TUX32_CORE1_ARCH "-march=x86-64")
set(CMAKE_C_FLAGS_INIT   "${_TUX32_CORE1_ARCH}")
set(CMAKE_CXX_FLAGS_INIT "${_TUX32_CORE1_ARCH}")

# Core 1 is DYNAMICALLY linked. Fully static images are out of scope — they do
# not exercise the dynamic ABI contract — so never add -static in a Core 1 build.

# When a Core 1 sysroot is provided, target it and resolve libraries/headers
# only from within it. Otherwise warn loudly: the host glibc becomes the floor.
if(DEFINED TUX32_CORE1_SYSROOT)
  set(CMAKE_SYSROOT "${TUX32_CORE1_SYSROOT}")
  set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
  set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
  set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
else()
  message(WARNING
    "Tux32 Core 1: TUX32_CORE1_SYSROOT is not set — building against the host "
    "glibc. If the host glibc is newer than 2.31, the binary will import "
    "symbols above the Core 1 ceiling. Build inside a Core 1 sysroot "
    "(build-in-sysroot.sh) and run `lexe sdk verify` on the result.")
endif()
