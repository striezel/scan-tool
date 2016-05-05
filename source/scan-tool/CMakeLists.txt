# Might work with earlier versions, too, but it's only tested with 2.8.9.
cmake_minimum_required (VERSION 2.8)

project(scan-tool)

#add_definitions(-DDEFINE_CONSTANT_HERE -DANOTHER_ONE_THERE -DTHIS_IS_THE_THIRD)

set(scan-tool_sources
    ../../libthoro/archive/ar/archive.cpp
    ../../libthoro/archive/archiveLibarchive.cpp
    ../../libthoro/archive/entry.cpp
    ../../libthoro/archive/entryLibarchive.cpp
    ../../libthoro/archive/gzip/archive.cpp
    ../../libthoro/archive/iso9660/archive.cpp
    ../../libthoro/archive/tar/archive.cpp
    ../../libthoro/archive/xz/archive.cpp
    ../../libthoro/archive/zip/archive.cpp
    ../../libthoro/archive/zip/entry.cpp
    ../../libthoro/common/StringUtils.cpp
    ../../libthoro/filesystem/directory.cpp
    ../../libthoro/filesystem/file.cpp
    ../../libthoro/hash/sha256/FileSource.cpp
    ../../libthoro/hash/sha256/FileSourceUtility.cpp
    ../../libthoro/hash/sha256/MessageSource.cpp
    ../../libthoro/hash/sha256/sha256.cpp
    ../virustotal/CacheManagerV2.cpp
    ../virustotal/EngineV2.cpp
    ../virustotal/ReportV2.cpp
    ../virustotal/ReportBase.cpp
    ../virustotal/ScannerV2.cpp
    ../Configuration.cpp
    ../Curly.cpp
    ../Engine.cpp
    ../Report.cpp
    ../Scanner.cpp
    ../StringToTimeT.cpp
    HandlerGeneric.hpp
    HandlerGzip.cpp
    HandlerTar.cpp
    ScanStrategy.cpp
    ScanStrategyDefault.cpp
    ScanStrategyDirectScan.cpp
    ScanStrategyNoRescan.cpp
    Strategies.cpp
    summary.cpp
    ZipHandler.cpp
    main.cpp)

if (CMAKE_COMPILER_IS_GNUCC)
    add_definitions (-Wall -O2 -fexceptions)
endif (CMAKE_COMPILER_IS_GNUCC)
add_definitions(-std=c++0x)

set( CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} -s" )

add_executable(scan-tool ${scan-tool_sources})

# find cURL library
find_package (CURL)
if (CURL_FOUND)
  include_directories(${CURL_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${CURL_LIBRARIES})
else ()
  message ( FATAL_ERROR "cURL was not found!" )
endif (CURL_FOUND)

# find jsoncpp library
set(LibJsonCpp_DIR "../../cmake/" )
find_package (LibJsonCpp)
if (LIBJSONCPP_FOUND)
  include_directories(${LIBJSONCPP_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBJSONCPP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libjsoncpp was not found!" )
endif (LIBJSONCPP_FOUND)

# find libzip
set(libzip_DIR "../../cmake/" )
find_package (libzip)
if (LIBZIP_FOUND)
  include_directories(${LIBZIP_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBZIP_LIBRARIES})
else ()
  message ( FATAL_ERROR "libzip was not found!" )
endif (LIBZIP_FOUND)

# find libarchive
set(libarchive_DIR "../../libthoro/cmake/" )
find_package (libarchive)
if (LIBARCHIVE_FOUND)
  include_directories(${LIBARCHIVE_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${LIBARCHIVE_LIBRARIES})
else ()
  message ( FATAL_ERROR "libarchive was not found!" )
endif (LIBARCHIVE_FOUND)

# find libz
find_package (ZLIB)
if (ZLIB_FOUND)
  include_directories(${ZLIB_INCLUDE_DIRS})
  target_link_libraries (scan-tool ${ZLIB_LIBRARIES})
else ()
  message ( FATAL_ERROR "zlib was not found!" )
endif (ZLIB_FOUND)
