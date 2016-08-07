# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(mso-api-request)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(mso-api-request_sources
    ../../libstriezel/common/StringUtils.cpp
    ../../libstriezel/filesystem/directory.cpp
    ../../libstriezel/filesystem/file.cpp
    ../../libstriezel/hash/sha256/sha256.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../metascan/Engine.cpp
    ../metascan/Report.cpp
    ../metascan/Scanner.cpp
    ../Scanner.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(mso-api-request ${mso-api-request_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (mso-api-request ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# find jsoncpp library
set(LibJsonCpp_DIR "../../cmake/" )
find_package (LibJsonCpp)
if (LIBJSONCPP_FOUND)
  include_directories(${LIBJSONCPP_INCLUDE_DIRS})
  target_link_libraries (mso-api-request ${LIBJSONCPP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libjsoncpp was not found!" )
endif (LIBJSONCPP_FOUND)
