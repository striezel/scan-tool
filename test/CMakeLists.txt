# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# Recurse into subdirectory for Curly tests.
add_subdirectory (curly)

# Recurse into subdirectory for the main executable tests.
add_subdirectory (scan-tool)

# Recurse into subdirectory for the vt-api-request executable tests.
add_subdirectory (vt-api-request)

# Recurse into subdirectory for the honeypottery executable tests.
add_subdirectory (honeypottery)

# Recurse into subdirectory for the date conversion tests.
add_subdirectory (date)
