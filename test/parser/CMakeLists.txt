# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

# Recurse into subdirectory for the Metascan Online parser.
add_subdirectory (mso)

# Recurse into subdirectory for the VirusTotal v2 parser.
add_subdirectory (vt-v2)

# Recurse into subdirectory for the VirusTotal Honeypot API parser.
add_subdirectory (honeypot)
