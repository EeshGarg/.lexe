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
# Crypto provider: prefer a maintained libsodium (canonical S, canonical point
# and small-order-point rejection per its documented API); fall back to the
# vendored orlp/ed25519 with our own strict checks where libsodium is not
# available (currently the MSVC dev host). Selected behind crypto.cpp's seam.
# ---------------------------------------------------------------------------
set(LEXE_HAVE_SODIUM OFF)
find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(SODIUM QUIET IMPORTED_TARGET libsodium)
  if(SODIUM_FOUND)
    set(LEXE_HAVE_SODIUM ON)
  endif()
endif()

# ---------------------------------------------------------------------------
# lexe_engine — THE .LEXE implementation. One engine, one static library.
#
# There is no "core" library and no separate "cli" component: the command layer
# under src/lexe/commands/ is part of this library, and `lexe` below is just its
# entry point. Every frontend — the CLI, lexe-ui, lexe-builder — links this and
# reimplements none of it (docs/ARCHITECTURE.md #Dependency-direction).
#
# Subsystems (src/lexe/<subsystem>/): base analysis package verify install
# runtime sandbox integration diagnostics commands.
# ---------------------------------------------------------------------------
file(GLOB LEXE_ENGINE_SOURCES CONFIGURE_DEPENDS src/lexe/*/*.cpp)
# main.cpp is the CLI process entry point, not library code.
list(REMOVE_ITEM LEXE_ENGINE_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/src/lexe/commands/main.cpp)
add_library(lexe_engine STATIC ${LEXE_ENGINE_SOURCES})
target_include_directories(lexe_engine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src)
# Single source of truth for the runtime version (src/lexe/base/version.hpp).
target_compile_definitions(lexe_engine PUBLIC LEXE_VERSION="${PROJECT_VERSION}")
if(LEXE_HAVE_SODIUM)
  target_link_libraries(lexe_engine PUBLIC PkgConfig::SODIUM)
  target_compile_definitions(lexe_engine PUBLIC LEXE_HAVE_SODIUM=1)
endif()
target_link_libraries(lexe_engine PUBLIC lexe_third_party lexe_settings)

# ---------------------------------------------------------------------------
# lexe — the command-line interface: the engine's own entry point.
# ---------------------------------------------------------------------------
add_executable(lexe src/lexe/commands/main.cpp)
target_link_libraries(lexe PRIVATE lexe_engine)

# ---------------------------------------------------------------------------
# lexe_tests — doctest binary, registered with CTest as one test running all
# suites (filter locally with: lexe_tests -ts=<suite>).
# ---------------------------------------------------------------------------
enable_testing()
file(GLOB LEXE_TEST_SOURCES CONFIGURE_DEPENDS tests/*.cpp)
add_executable(lexe_tests ${LEXE_TEST_SOURCES})
target_include_directories(lexe_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(lexe_tests PRIVATE lexe_engine)
add_dependencies(lexe_tests lexe) # e2e suite drives the built CLI binary
add_test(NAME lexe_tests COMMAND lexe_tests)
# e2e tests locate the CLI via LEXE_TEST_BINARY / LEXE_CLI (fallbacks: a
# compile definition baked in below, then the test binary's own directory).
set_tests_properties(lexe_tests PROPERTIES ENVIRONMENT
  "LEXE_CLI=$<TARGET_FILE:lexe>;LEXE_TEST_BINARY=$<TARGET_FILE:lexe>")
target_compile_definitions(lexe_tests PRIVATE
  LEXE_TEST_BINARY_PATH="$<TARGET_FILE:lexe>"
  LEXE_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

# ---------------------------------------------------------------------------
# The two graphical frontends, Linux only (ARCHITECTURE.md #GUI). Built when
# pkg-config finds gtk+-3.0, or forced with -DLEXE_BUILD_GUI=ON. Both link
# lexe_engine and reimplement none of it; the alpha's third frontend,
# `lexe-installer`, is gone — lexe-ui is the `.lexe` handler, and the install
# view model they shared now lives in src/gui/package_view.hpp.
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
  # lexe-builder — GTK 3 developer app: point it at a project folder, fill in
  # the manifest, generate/choose a signing key, and build a signed .lexe.
  add_executable(lexe-builder src/gui/lexe-builder/builder.cpp)
  target_link_libraries(lexe-builder PRIVATE lexe_engine PkgConfig::GTK3)

  # lexe-ui — GTK 3 consumer/power-user frontend: Home, Install, Apps (Launch /
  # Compatibility / Runtime / Permissions / Diagnostics / Error History /
  # Uninstall) and Settings. Single-instance (GtkApplication), and the `.lexe`
  # handler entry point: `lexe-ui --open <file>` dispatches on the SIGNED
  # manifest role. ".LEXE Menu" is `--app <id>`; ".LEXE Error" is
  # `--errors <id>`; both navigate this one window.
  add_executable(lexe-ui src/gui/lexe-ui/ui.cpp)
  target_link_libraries(lexe-ui PRIVATE lexe_engine PkgConfig::GTK3)
endif()
