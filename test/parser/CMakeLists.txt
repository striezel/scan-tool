# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# Recurse into subdirectory for the Metascan Online parser.
add_subdirectory (mso)

# Recurse into subdirectory for the VirusTotal v2 parser.
add_subdirectory (vt-v2)
