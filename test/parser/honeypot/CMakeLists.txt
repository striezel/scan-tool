# Might work with earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8)

project(parser-virustotal-honeypot)

set(parser-virustotal-honeypot_sources
    ../../../libstriezel/common/StringUtils.cpp
    ../../../libstriezel/filesystem/file.cpp
    ../../../source/Engine.cpp
    ../../../source/Report.cpp
    ../../../source/StringToTimeT.cpp
    ../../../source/virustotal/ReportBase.cpp
    ../../../source/virustotal/ReportHoneypot.cpp
    ../../../third-party/simdjson/simdjson.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(parser-virustotal-honeypot ${parser-virustotal-honeypot_sources})

# add it as test case
add_test(NAME Test_Parser_VirusTotal_Honeypot
         COMMAND $<TARGET_FILE:parser-virustotal-honeypot> "${CMAKE_CURRENT_SOURCE_DIR}/HoneypotAPI.json")
