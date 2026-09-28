# A library target in its own list file, pulled in by add_subdirectory. The
# include directory is attached to the TARGET rather than set globally, which is
# the modern idiom and the one that survives being consumed from elsewhere.
add_library(portable_subdir_util STATIC util.c)
target_include_directories(portable_subdir_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
