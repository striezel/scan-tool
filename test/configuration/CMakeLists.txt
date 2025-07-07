cmake_minimum_required (VERSION 3.8...3.31)

project(load-configuration-test)

set(load-configuration-test_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../source/Configuration.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -Wextra -Wpedantic -pedantic-errors -Wshadow -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(load-configuration-test ${load-configuration-test_sources})

# add it as test case
add_test(NAME load-configuration-with-apikey
         COMMAND $<TARGET_FILE:load-configuration-test> "${CMAKE_CURRENT_SOURCE_DIR}/../../script/vt-apikey.example.conf")
