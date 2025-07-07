# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

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

# parameter to show version number
add_test(NAME scan-tool_version
         COMMAND $<TARGET_FILE:scan-tool> --version)
