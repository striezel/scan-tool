# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# Recurse into subdirectory for Curly tests.
add_subdirectory (curly)

# Recurse into subdirectory for the main executable tests.
add_subdirectory (scan-tool)
