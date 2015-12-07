#!/bin/bash

# This file is part of scan-tool's CI scripts.
# Copyright (C) 2015, 2016  Dirk Stolle
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# variable for CI base directory - you might need to adjust that
ci_base="/c/projects/scan-tool/ci/windows"
# relative paths of zlib and OpenSSL source
relative_zlib_path="../zlib-1.2.8"
relative_openssl_path="../openssl-1.0.2e"

# list path-related environment variables (to ease debugging)
echo "Info: Path-related environment variables are:"
env | grep -i PATH
echo
echo "Total: $(env | grep -i PATH | wc -l)"
echo

# directory has to exist, of course
if [[ ! -d "$ci_base" ]]
then
  echo "Error: The directory $ci_base does not exist!"
  exit 1
fi

# change to cURL directory
cd "$ci_base"/curl-7.46.0
if [[ $? -ne 0 ]]
then
  echo "Error: Could not change to directory $ci_base/curl-7.46.0!"
  exit 2
fi

# check zlib directory
if [[ ! -d "$relative_zlib_path" ]]
then
  echo "Error: zlib directory $(pwd)/$relative_zlib_path does not exist!"
  exit 1
fi

# check OpenSSL directory
if [[ ! -d "$relative_openssl_path" ]]
then
  echo "Error: OpenSSL directory $(pwd)/$relative_openssl_path does not exist!"
  exit 1
fi

# build cURL with zlib and OpenSSL support
env ZLIB_PATH="$relative_zlib_path" OPENSSL_PATH="$relative_openssl_path" \
mingw32-make mingw32-ssl-zlib
# mingw32-make mingw32-ssh2-ssl-zlib
if [[ $? -ne 0 ]]
then
  echo "ERROR: Build process for cURL failed!"
  exit 3
else
  echo "Hint: Build process for cURL finished successfully!"
fi

# change back to parent directory for the fun that will follow
cd ..
# reminder
echo "Finished build script, but there is more to do!"
