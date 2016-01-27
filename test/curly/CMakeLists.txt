# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# Recurse into subdirectory for Curly header tests.
add_subdirectory (headers)

# Recurse into subdirectory for Curly POST request tests.
add_subdirectory (post)

# Recurse into subdirectory for Curly version information test.
add_subdirectory (version)
