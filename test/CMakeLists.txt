# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

# Recurse into subdirectory for Curly tests.
add_subdirectory (curly)

# Recurse into subdirectory for the executable tests.
add_subdirectory (executables)

# Recurse into subdirectory for the date conversion tests.
add_subdirectory (date)

# Recurse into subdirectory for configuration test.
add_subdirectory (configuration)

# Recurse into subdirectory for the parser tests.
add_subdirectory (parser)
