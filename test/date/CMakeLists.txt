# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

# Recurse into subdirectory for the date conversion tests.
add_subdirectory (string-to-time-t)
