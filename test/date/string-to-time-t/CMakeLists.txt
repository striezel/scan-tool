cmake_minimum_required (VERSION 3.8...3.31)

project(string-to-time-t-test)

set(string-to-time-t-test_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../source/StringToTimeT.cpp
    main.cpp)

if (MAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -Wextra -Wpedantic -pedantic-errors -Wshadow -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(string-to-time-t-test ${string-to-time-t-test_sources})

# add it as test case
add_test(NAME stringToTimeT
         COMMAND $<TARGET_FILE:string-to-time-t-test>)
