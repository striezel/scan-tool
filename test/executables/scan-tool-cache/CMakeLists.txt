# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

# ######################### #
# tests for scan-tool-cache #
# ######################### #

# add tests for --version and --help parameters
# default help parameter "--help"
add_test(NAME scan-tool-cache_help
         COMMAND $<TARGET_FILE:scan-tool-cache> --help)

# short help parameter with question mark "-?"
add_test(NAME scan-tool-cache_help_question_mark
         COMMAND $<TARGET_FILE:scan-tool-cache> -?)

# Windows-style help parameter "/?"
add_test(NAME scan-tool-cache_help_question_mark_win
         COMMAND $<TARGET_FILE:scan-tool-cache> /?)

# cache directory
add_test(NAME scan-tool-cache_directory
         COMMAND $<TARGET_FILE:scan-tool-cache> --directory)

# cache integrity check
add_test(NAME scan-tool-cache_integrity_check
         COMMAND $<TARGET_FILE:scan-tool-cache> --integrity)

# cache statistics
add_test(NAME scan-tool-cache_statistics
         COMMAND $<TARGET_FILE:scan-tool-cache> --statistics)

# cache transition
add_test(NAME scan-tool-cache_transition
         COMMAND $<TARGET_FILE:scan-tool-cache> --transition)

# parameter to show version number
add_test(NAME scan-tool-cache_version
         COMMAND $<TARGET_FILE:scan-tool-cache> --version)
