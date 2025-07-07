cmake_minimum_required (VERSION 3.8...3.31)

project(parser-mso)

set(parser-mso_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../source/Engine.cpp
    ../../../source/metascan/Engine.cpp
    ../../../source/metascan/Report.cpp
    ../../../third-party/simdjson/simdjson.cpp
    main.cpp)

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_definitions (-Wall -Wextra -Wpedantic -pedantic-errors -Wshadow -O2 -fexceptions)

    set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )
endif ()
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(parser-mso ${parser-mso_sources})

# add it as test case
add_test(NAME Test_Parser_MetascanOnline
         COMMAND $<TARGET_FILE:parser-mso> "${CMAKE_CURRENT_SOURCE_DIR}/Metascan.json")
