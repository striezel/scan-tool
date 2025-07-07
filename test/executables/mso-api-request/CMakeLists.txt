cmake_minimum_required (VERSION 3.8...3.31)

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
