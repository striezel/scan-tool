# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

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
