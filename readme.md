# scan-tool

scan-tool is (or better: will be) a tool that scans selected files for
malicious content.

TODO

# Building from source

## Prerequisites

To build the scan-tool from source you need a C++ compiler and CMake 2.8 or
later.
It also helps to have Git, a distributed version control system, on your build
system to get the latest source code directly from the Git repository.

All three can usually be installed be typing

    apt-get install cmake g++ git

or

    yum install cmake gcc-c++ git

into a root terminal.

## Getting the source code

Get the source directly from Git by cloning the Git repository and change to
the directory after the repository is completely cloned:

    git clone https://github.com/Thoronador/scan-tool.git ./scan-tool
    cd scan-tool

That's it, you should now have the current source code of scan-tool on your
machine.

## Build process

The build process is relatively easy, because CMake does all the preparations.
Starting in the root directory of the source, you can do the following steps:

    mkdir build
    cd build
    cmake ../
    make -j2

In the repository's current state, CMake will not find anythin to build.
This will change in the future.

# Copyright and Licensing

Copyright 2015 Thoronador

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
