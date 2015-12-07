@echo off
REM bogus build script

REM   This file is part of scan-tool's CI scripts.
REM   Copyright (C) 2015  Dirk Stolle
REM
REM   This program is free software: you can redistribute it and/or modify
REM   it under the terms of the GNU General Public License as published by
REM   the Free Software Foundation, either version 3 of the License, or
REM   (at your option) any later version.
REM
REM   This program is distributed in the hope that it will be useful,
REM   but WITHOUT ANY WARRANTY; without even the implied warranty of
REM   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
REM   GNU General Public License for more details.
REM
REM   You should have received a copy of the GNU General Public License
REM   along with this program.  If not, see <http://www.gnu.org/licenses/>.

echo:"This is the build script. It does nothing yet."

REM add MinGW's binary directory to path
set PATH=%PATH%;C:\MinGW\bin\

set

echo.
echo "Current directory:"
cd

echo.
echo "C:"
dir C:\
echo "**** Program Files ****"
dir "C:\Program Files"

echo "**** Program Files 32 bit ****"
dir "C:\Program Files (x86)"

echo "**** MinGW ****"
dir "C:\MinGW"
dir "C:\MinGW\bin"
dir "C:\MinGW\msys"

dir "C:\projects\scan-tool"
echo "**** cURL source directory ****"
dir "C:\projects\scan-tool\curl-7.46.0"

echo "**** zlib source directory ****"
dir "C:\projects\scan-tool\zlib-1.2.8"

echo "**** OpenSSL source directory ****"
dir "C:\projects\scan-tool\openssl-1.0.2e"

SET ZLIB_PATH=C:\projects\scan-tool\zlib-1.2.8

REM try to build zlib
cd zlib-1.2.8
mingw32-make -fwin32\Makefile.gcc
cd ..

REM TODO: build OpenSSL


REM set OpenSSL directory
SET OPENSSL_PATH=C:\projects\scan-tool\openssl-1.0.2e

REM change to directory
cd "C:\projects\scan-tool"

REM try to build cURL
"C:\Program Files\Git\bin\sh.exe" --login -i ci/windows/build_curl.sh

exit 0

REM REM try to configure
REM .\configure --without-ssl --disable-shared --build=x86_64-w64-mingw32
REM make install strip
