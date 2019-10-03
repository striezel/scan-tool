# We might support earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

# ######################### #
# tests for mso-api-request #
# ######################### #

# add tests for --version and --help parameters
# default help parameter "--help"
add_test(NAME mso-api-request_help
         COMMAND $<TARGET_FILE:mso-api-request> --help)

# short help parameter with question mark "-?"
add_test(NAME mso-api-request_help_question_mark
         COMMAND $<TARGET_FILE:mso-api-request> -?)

# Windows-style help parameter "/?"
add_test(NAME mso-api-request_help_question_mark_win
         COMMAND $<TARGET_FILE:mso-api-request> /?)

# parameter to show version number
add_test(NAME mso-api-request_version
         COMMAND $<TARGET_FILE:mso-api-request> --version)
