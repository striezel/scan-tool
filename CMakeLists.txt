# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

# Recurse into subdirectory for the main executable.
add_subdirectory (source)

## Recurse into subdirectory for the executable for experimentation.
# add_subdirectory (playground)

# enable tests
enable_testing()

# Recurse into subdirectory for tests.
add_subdirectory (test)

# Recurse into subdirectory for SHA-256 tests.
add_subdirectory (libstriezel/tests/hash/sha256)
