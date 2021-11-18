# We might support earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

# ###################### #
# tests for honeypottery #
# ###################### #

# add tests for --version and --help parameters
# default help parameter "--help"
add_test(NAME honeypottery_help
         COMMAND $<TARGET_FILE:honeypottery> --help)

# short help parameter with question mark "-?"
add_test(NAME honeypottery_help_question_mark
         COMMAND $<TARGET_FILE:honeypottery> -?)

# Windows-style help parameter "/?"
add_test(NAME honeypottery_help_question_mark_win
         COMMAND $<TARGET_FILE:honeypottery> /?)

# parameter to show version number
add_test(NAME honeypottery_version
         COMMAND $<TARGET_FILE:honeypottery> --version)
