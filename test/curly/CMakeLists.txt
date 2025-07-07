cmake_minimum_required (VERSION 3.8...3.31)

# Recurse into subdirectory for Curly header tests.
add_subdirectory (headers)

# Recurse into subdirectory for Curly POST request tests.
add_subdirectory (post)

# Recurse into subdirectory for test of Curly POST request with predefined data
# for request body.
add_subdirectory (post-body)

# Recurse into subdirectory for test of Curly POST request with file.
add_subdirectory (post-file)

# Recurse into subdirectory for test of Curly's supported protocols.
add_subdirectory (protocol-support)

# Recurse into subdirectory for test of Curly's response headers.
add_subdirectory (response-headers)

# Recurse into subdirectory for test of HTTP status code retrieval in Curly.
add_subdirectory (status-code)

# Recurse into subdirectory for Curly version information test.
add_subdirectory (version)
