# Lexe 0.1 reference runtime — single top-level CMake (docs/ARCHITECTURE.md #Build).
cmake_minimum_required(VERSION 3.22)
project(lexe VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(LEXE_BUILD_GUI "Build the GTK 3 installer GUI (auto-enabled when gtk+-3.0 is found)" OFF)

# ---------------------------------------------------------------------------
# Third-party (vendored, pinned, never modified — third_party/README.md).
# Compiled with warnings silenced so vendored code never breaks the build;
# headers are exposed as SYSTEM includes so first-party /W4 stays clean.
# ---------------------------------------------------------------------------
add_library(lexe_third_party STATIC
  third_party/miniz/miniz.c
  third_party/ed25519/add_scalar.c
  third_party/ed25519/fe.c
  third_party/ed25519/ge.c
  third_party/ed25519/key_exchange.c
  third_party/ed25519/keypair.c
  third_party/ed25519/sc.c
  third_party/ed25519/seed.c
  third_party/ed25519/sha512.c
  third_party/ed25519/sign.c
  third_party/ed25519/verify.c
)
target_include_directories(lexe_third_party SYSTEM PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
# MINIZ_NO_TIME: deterministic archives (FORMAT-0.1 §1). PUBLIC because it
# affects the layout of miniz structs seen by consumers.
target_compile_definitions(lexe_third_party PUBLIC MINIZ_NO_TIME)
if(MSVC)
  target_compile_options(lexe_third_party PRIVATE /w /utf-8)
else()
  target_compile_options(lexe_third_party PRIVATE -w)
endif()
if(WIN32)
  # ed25519/seed.c uses CryptAcquireContext/CryptGenRandom.
  target_link_libraries(lexe_third_party PUBLIC advapi32)
endif()

# ---------------------------------------------------------------------------
# First-party warning/compile settings (ARCHITECTURE.md #Conventions).
# ---------------------------------------------------------------------------
add_library(lexe_settings INTERFACE)
if(MSVC)
  target_compile_options(lexe_settings INTERFACE /W4 /utf-8 /EHsc)
  target_compile_definitions(lexe_settings INTERFACE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
  )
else()
  target_compile_options(lexe_settings INTERFACE -Wall -Wextra)
endif()

# ---------------------------------------------------------------------------
# lexe_core — static library, all portable runtime logic.
# ---------------------------------------------------------------------------
file(GLOB LEXE_CORE_SOURCES CONFIGURE_DEPENDS src/core/*.cpp)
add_library(lexe_core STATIC ${LEXE_CORE_SOURCES})
target_include_directories(lexe_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(lexe_core PUBLIC lexe_third_party lexe_settings)

# ---------------------------------------------------------------------------
# lexe — command-line interface.
# ---------------------------------------------------------------------------
file(GLOB LEXE_CLI_SOURCES CONFIGURE_DEPENDS src/cli/*.cpp)
add_executable(lexe ${LEXE_CLI_SOURCES})
target_link_libraries(lexe PRIVATE lexe_core)

# ---------------------------------------------------------------------------
# lexe_tests — doctest binary, registered with CTest as one test running all
# suites (filter locally with: lexe_tests -ts=<suite>).
# ---------------------------------------------------------------------------
enable_testing()
file(GLOB LEXE_TEST_SOURCES CONFIGURE_DEPENDS tests/*.cpp)
add_executable(lexe_tests ${LEXE_TEST_SOURCES})
target_include_directories(lexe_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(lexe_tests PRIVATE lexe_core)
add_dependencies(lexe_tests lexe) # e2e suite drives the built CLI binary
add_test(NAME lexe_tests COMMAND lexe_tests)
# e2e tests locate the CLI via LEXE_TEST_BINARY / LEXE_CLI (fallbacks: a
# compile definition baked in below, then the test binary's own directory).
set_tests_properties(lexe_tests PROPERTIES ENVIRONMENT
  "LEXE_CLI=$<TARGET_FILE:lexe>;LEXE_TEST_BINARY=$<TARGET_FILE:lexe>")
target_compile_definitions(lexe_tests PRIVATE
  LEXE_TEST_BINARY_PATH="$<TARGET_FILE:lexe>")

# ---------------------------------------------------------------------------
# lexe-installer — GTK 3 GUI, Linux only (ARCHITECTURE.md #GUI). Built when
# pkg-config finds gtk+-3.0, or forced with -DLEXE_BUILD_GUI=ON.
# ---------------------------------------------------------------------------
set(LEXE_GUI_ENABLED OFF)
if(NOT WIN32)
  find_package(PkgConfig QUIET)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(GTK3 QUIET IMPORTED_TARGET gtk+-3.0)
    if(GTK3_FOUND)
      set(LEXE_GUI_ENABLED ON)
    endif()
  endif()
endif()
if(LEXE_BUILD_GUI AND NOT GTK3_FOUND)
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(GTK3 REQUIRED IMPORTED_TARGET gtk+-3.0)
  set(LEXE_GUI_ENABLED ON)
endif()
if(LEXE_GUI_ENABLED)
  add_executable(lexe-installer src/gui/main.cpp)
  target_link_libraries(lexe-installer PRIVATE lexe_core PkgConfig::GTK3)
endif()
