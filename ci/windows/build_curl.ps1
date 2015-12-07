# PowerShell script to compile cURL (still experimental)

#   This file is part of scan-tool's CI scripts.
#   Copyright (C) 2016  Dirk Stolle
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.


# get directory of this script as reference point for other paths
$ci_win_dir = Split-Path $script:MyInvocation.MyCommand.Path
Write-Output "Info: ci_win_dir is $ci_win_dir"

# variables that contain some custom paths
# NOTE: You might need to adjust them for other systems to work properly.

# path to MinGW's binary directory
$mingw_bin = "C:\Progam Files\CodeBlocks\MinGW\bin"
# path of Git Bash's sh.exe
$git_bash = "C:\Program Files\Git\bin\sh.exe"

# test, if MinGW\bin directory exists
If (Test-Path $mingw_bin){
	Write-Output "Info: MinGW binary directory exists."
}
else
{
	Write-Output "ERROR: MinGW binary directory is missing, it's not located at $mingw_bin!"
    Write-Output "HINT: You probably need to adjust the mingw_bin variable in this script!"
    Exit 1
}

# test, if Git Bash exists
If (Test-Path $git_bash){
	Write-Output "Info: Git Bash's sh.exe exists."
}
else
{
	Write-Output "ERROR: Git Bash's sh.exe is missing, it's not located at $git_bash!"
    Write-Output "HINT: You probably need to adjust the git_bash variable in this script!"
    Exit 1
}

# Add MinGW's binary directory to PATH environment variable,
# but only if it's not already right there where we will add it.
If (-not ($env:PATH).EndsWith(";$mingw_bin"))
{
  $env:PATH = $env:PATH + ";$mingw_bin"
}
Write-Output "Info: PATH is currently $env:PATH"

# set environment variables for zlib and OpenSSL locations
# Examples in cmd would be:
#     set ZLIB_PATH=c:\zlib-1.2.8
#     set OPENSSL_PATH=c:\openssl-1.0.2e

# zlib path
$env:ZLIB_PATH = "$ci_win_dir\zlib-1.2.8"
Write-Output "Info: ZLIB_PATH is $env:ZLIB_PATH"
# test, if zlib path exists
If (Test-Path $env:ZLIB_PATH){
	Write-Output "Info: The zlib directory exists."
}
else
{
	Write-Output "ERROR: The zlib directory does not exist at $env:ZLIB_PATH!"
    Write-Output "HINT: You probably need to adjust the version number of zlib in this script!"
    Exit 1
}


# OpenSSL path
$env:OPENSSL_PATH = "$ci_win_dir\openssl-1.0.2e"
Write-Output "Info: OPENSSL_PATH is $env:OPENSSL_PATH"
# test, if OpenSSL path exists
If (Test-Path $env:OPENSSL_PATH){
	Write-Output "Info: The OpenSSL directory exists."
}
else
{
	Write-Output "ERROR: The OpenSSL directory does not exist at $env:OPENSSL_PATH!"
    Write-Output "HINT: You probably need to adjust the version number of OpenSSL in this script!"
    Exit 1
}

# call Git Bash
& "$git_bash" --login "$ci_win_dir\build_curl.sh"
