# Might work with earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

project(parser-virustotal-v2)

set(parser-virustotal-v2_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../source/Engine.cpp
    ../../../source/Report.cpp
    ../../../source/StringToTimeT.cpp
    ../../../source/virustotal/EngineV2.cpp
    ../../../source/virustotal/ReportBase.cpp
    ../../../source/virustotal/ReportV2.cpp
    ../../../third-party/simdjson/simdjson.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(parser-virustotal-v2 ${parser-virustotal-v2_sources})

# add it as test case
add_test(NAME Test_Parser_VirusTotal_v2
         COMMAND $<TARGET_FILE:parser-virustotal-v2> "${CMAKE_CURRENT_SOURCE_DIR}/ScanResponse.json")
