# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

# ######################## #
# tests for vt-api-request #
# ######################## #

# add tests for --version and --help parameters
# default help parameter "--help"
add_test(NAME vt-api-request_help
         COMMAND $<TARGET_FILE:vt-api-request> --help)

# short help parameter with question mark "-?"
add_test(NAME vt-api-request_help_question_mark
         COMMAND $<TARGET_FILE:vt-api-request> -?)

# Windows-style help parameter "/?"
add_test(NAME vt-api-request_help_question_mark_win
         COMMAND $<TARGET_FILE:vt-api-request> /?)

# parameter to show version number
add_test(NAME vt-api-request_version
         COMMAND $<TARGET_FILE:vt-api-request> --version)
