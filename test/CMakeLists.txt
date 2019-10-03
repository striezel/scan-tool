# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# Recurse into subdirectory for Curly tests.
add_subdirectory (curly)

# Recurse into subdirectory for the executable tests.
add_subdirectory (executables)

# Recurse into subdirectory for the date conversion tests.
add_subdirectory (date)

# Recurse into subdirectory for configuration test.
add_subdirectory (configuration)
