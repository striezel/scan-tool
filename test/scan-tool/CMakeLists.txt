# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# ###################################### #
# tests for default version of scan-tool #
# ###################################### #

# add tests for --version and --help parameters
# default help parameter "--help"
add_test(NAME scan-tool_help
         COMMAND $<TARGET_FILE:scan-tool> --help)

# short help parameter with question mark "-?"
add_test(NAME scan-tool_help_question_mark
         COMMAND $<TARGET_FILE:scan-tool> -?)

# Windows-style help parameter "/?"
add_test(NAME scan-tool_help_question_mark_win
         COMMAND $<TARGET_FILE:scan-tool> /?)

# cache integrity check
add_test(NAME scan-tool_integrity_check
         COMMAND $<TARGET_FILE:scan-tool> --integrity)

# cache transition
add_test(NAME scan-tool_cache_transition
         COMMAND $<TARGET_FILE:scan-tool> --transition)

# parameter to show version number
add_test(NAME scan-tool_version
         COMMAND $<TARGET_FILE:scan-tool> --version)
