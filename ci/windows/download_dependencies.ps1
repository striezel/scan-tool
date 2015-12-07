# PowerShell script to download and extract depencencies (still experimental)

#   This file is part of scan-tool's CI scripts.
#   Copyright (C) 2015  Dirk Stolle
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
$location_extract_openssl = $ci_win_dir + '\extract_openssl.sh'

# variables that contain some custom paths
# NOTE: You might need to adjust them for other systems to work properly.

# path to 7-Zip's command line executable
$sevenzip = "C:\Program Files\7-Zip\7z.exe"

# test, if files exist
If (Test-Path $sevenzip){
	Write-Output "Info: 7-Zip executable exists."
}
else
{
	Write-Output "ERROR: 7-Zip is missing, it's not located at $sevenzip!"
    Exit 1
}


########
# zlib #
########

# Download URL for zlib 1.2.8 is http://zlib.net/zlib128.zip
$zlib_url = "http://zlib.net/zlib128.zip"
$zlib_output = $ci_win_dir + "\zlib128.zip"
$start = Get-Date

# download zlib
$webclient = New-Object System.Net.WebClient
$webclient.DownloadFile($zlib_url, $zlib_output)
$dl_success = $?
if ($dl_success)
{
  Write-Output "zlib was downloaded successfully."
  Write-Output "Time required for zlib download: $((Get-Date).Subtract($start).Seconds) second(s)"
}
else
{
  Write-Output "ERROR: zlib could not be downloaded!"
  Exit 1
}
# extract zlib archive
$o_parameter = "-o" + $ci_win_dir
& "$sevenzip" x -y $o_parameter "$zlib_output"
$zlib_extract_success = $?
if ($zlib_extract_success)
{
  Write-Output "zlib was extracted successfully."
}
else
{
  # extraction failed
  Write-Output "zlib extraction FAILED!"
  Write-Output $error
  Exit 1
}

# Delete the downloaded ZIP file, because we do not want to clutter the file
# system.
If (Test-Path $zlib_output){
	Remove-Item $zlib_output
}

###########
# OpenSSL #
###########

# Download URL for OpenSSL 1.0.2e is ftp://ftp.openssl.org/source/openssl-1.0.2e.tar.gz
$openssl_url = "ftp://ftp.openssl.org/source/openssl-1.0.2e.tar.gz"
$openssl_output = $ci_win_dir + "\openssl-1.0.2e.tar.gz"
$start = Get-Date

# download OpenSSL
$webclient.DownloadFile($openssl_url, $openssl_output)
$dl_success = $?
if ($dl_success)
{
  Write-Output "OpenSSL was downloaded successfully."
  Write-Output "Time required for OpenSSL download: $((Get-Date).Subtract($start).Seconds) second(s)"
}
else
{
  Write-Output "ERROR: OpenSSL could not be downloaded!"
  Exit 1
}
# extract OpenSSL - first step: get .tar file
$o_parameter = "-o" + $ci_win_dir
& "$sevenzip" x -y $o_parameter "$openssl_output"
$openssl_extract_success = $?
if ($openssl_extract_success)
{
  Write-Output "OpenSSL's tar.gz file (first step) was extracted successfully."
}
else
{
  # extraction failed
  Write-Output "OpenSSL's tar.gz file extraction (first step) FAILED!"
  Write-Output $error
  Exit 1
}
# extract OpenSSL - second step: extract .tar file
$o_parameter = "-o" + $ci_win_dir
$tar_file = $ci_win_dir + "\openssl-1.0.2e.tar"
& "$sevenzip" x -y $o_parameter "$tar_file"
$openssl_extract_success = $?
if ($openssl_extract_success)
{
  Write-Output "OpenSSL's tar.gz file (second step) was extracted successfully."
}
else
{
  # extraction failed
  Write-Output "OpenSSL's tar.gz file extraction (second step) FAILED!"
  Write-Output $error
  Exit 1
}

########
# cURL #
########

# Download URL for cURL 7.46 is http://curl.haxx.se/download/curl-7.46.0.zip
$curl_url = "http://curl.haxx.se/download/curl-7.46.0.zip"
$curl_output = $ci_win_dir +"\curl.zip"
$start = Get-Date

# download
$webclient.DownloadFile($curl_url, $curl_output)
$dl_success = $?
if ($dl_success)
{
  Write-Output "cURL was downloaded successfully."
  Write-Output "Time required for cURL download: $((Get-Date).Subtract($start).Seconds) second(s)"
}
else
{
  Write-Output "ERROR: cURL could not be downloaded!"
  Exit 1
}
# extract cURL archive
$o_parameter = "-o" + $ci_win_dir
& "$sevenzip" x -y $o_parameter "$curl_output"
$curl_extract_success = $?
if ($curl_extract_success)
{
  Write-Output "cURL was extracted successfully."
}
else
{
  # extraction failed
  Write-Output "cURL extraction FAILED!"
  Write-Output $error
  Exit 1
}

# Delete the downloaded ZIP file, because we do not want to clutter the file
# system.
If (Test-Path $curl_output){
	Remove-Item $curl_output
}

# alright so far
Exit 0
