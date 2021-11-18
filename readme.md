# scan-tool

scan-tool is a command line tool that scans selected files for malicious
content. It uses the public ReST API provided by
[VirusTotal](https://www.virustotal.com/) to scan files.

## Build status

* GitHub Actions:
[![GitHub CI status](https://github.com/striezel/scan-tool/workflows/GitHub%20CI%20with%20Clang/badge.svg)](https://github.com/striezel/scan-tool/actions)
* GitLab CI:
[![GitLab pipeline status](https://gitlab.com/striezel/scan-tool/badges/master/pipeline.svg)](https://gitlab.com/striezel/scan-tool/-/pipelines)

## Building from source

### Prerequisites

To build the scan-tool from source you need a C++ compiler, CMake 3.8 or later,
the cURL library (>=7.17), as well as the libarchive, libzip and zlib libraries.
pkg-config is required to make it easier to find compiler options for the
installed libraries.
It also helps to have Git, a distributed version control system, on your build
system to get the latest source code directly from the Git repository.

All of that can usually be installed be typing

    apt-get install cmake g++ git libarchive-dev libcurl4-gnutls-dev \
    libzip-dev zlib1g-dev pkg-config

or

    yum install cmake gcc-c++ git libarchive-devel libcurl-devel libzip-devel \
    zlib-devel pkgconfig

into a root terminal.

### Getting the source code

Get the source directly from Git by cloning the Git repository and change to
the directory after the repository is completely cloned:

    git clone https://gitlab.com/striezel/scan-tool.git ./scan-tool
    cd scan-tool
    git submodule update --init

That's it, you should now have the current source code of scan-tool on your
machine.

### Build process

The build process is relatively easy, because CMake does all the preparations.
Starting in the root directory of the source, you can do the following steps:

    mkdir build
    cd build
    cmake ../
    make -j4

### Test suite

The build commands as described above also create files for a small test suite
for scan-tool. The test suite uses CTest, which usually comes with CMake.
To run the test suite, make sure you are still in the build directory that was
created during the build process and then type:

    ctest -V

If all tests succeeded, the output of the above command should end with
something like:

    100% tests passed, 0 tests failed out of 39

    Total Test time (real) =  85.99 sec

That's an indication that the basic functionality of scan-tool still works as
it was intended by the developer.

## Copyright and Licensing

Copyright 2015, 2016, 2017, 2019, 2021  Dirk Stolle

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
