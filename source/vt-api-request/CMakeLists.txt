# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(vt-api-request)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(vt-api-request_sources
    ../../libthoro/common/StringUtils.cpp
    ../../libthoro/filesystem/DirectoryFunctions.cpp
    ../../libthoro/filesystem/FileFunctions.cpp
    ../../libthoro/hash/sha256/sha256.cpp
    ../CacheManagerVirusTotalV2.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../EngineV2.cpp
    ../Report.cpp
    ../ReportV2.cpp
    ../ReportVirusTotalBase.cpp
    ../Scanner.cpp
    ../ScannerVirusTotalV2.cpp
    ../StringToTimeT.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(vt-api-request ${vt-api-request_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (vt-api-request ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# find jsoncpp library
set(LibJsonCpp_DIR "../../cmake/" )
find_package (LibJsonCpp)
if (LIBJSONCPP_FOUND)
  include_directories(${LIBJSONCPP_INCLUDE_DIRS})
  target_link_libraries (vt-api-request ${LIBJSONCPP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libjsoncpp was not found!" )
endif (LIBJSONCPP_FOUND)
