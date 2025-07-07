# Might work with earlier versions, too, but try to use a more recent one.
cmake_minimum_required (VERSION 3.8...3.31)

project(scan-tool-mso)

set(scan-tool-mso_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/directory.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../libstriezel/hash/sha256/FileSource.cpp
    ../../libstriezel/hash/sha256/FileSourceUtility.cpp
    ../../libstriezel/hash/sha256/MessageSource.cpp
    ../../libstriezel/hash/sha256/sha256.cpp
    ../../third-party/simdjson/simdjson.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../metascan/Definitions.cpp
    ../metascan/Engine.cpp
    ../metascan/Report.cpp
    ../metascan/Scanner.cpp
    ../Report.cpp
    ../Scanner.cpp
    summary.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(scan-tool-mso ${scan-tool-mso_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (scan-tool-mso ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)
