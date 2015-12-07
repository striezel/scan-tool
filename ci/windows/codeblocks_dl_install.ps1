# PowerShell script to download (and install) Code::Blocks 13.12.

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



# Download URL for Code::Blocks 13.12 with MinGW is
# http://sourceforge.net/projects/codeblocks/files/Binaries/13.12/Windows/codeblocks-13.12mingw-setup.exe
# Direct link on mirror is
# http://heanet.dl.sourceforge.net/project/codeblocks/Binaries/13.12/Windows/codeblocks-13.12mingw-setup.exe

$url = "http://heanet.dl.sourceforge.net/project/codeblocks/Binaries/13.12/Windows/codeblocks-13.12mingw-setup.exe"
$output = "codeblocks-mingw-setup.exe"
$start = Get-Date

# $webcli = New-Object System.Net.WebClient
# $webcli.DownloadFile($url, $output)
(New-Object System.Net.WebClient).DownloadFile($url, $output)

Write-Output "Time required for download: $((Get-Date).Subtract($start).Seconds) second(s)"

# Call executable to install Code::Blocks 13.12, silent/unattended installation.
& codeblocks-mingw-setup.exe /S
$install_success = $?
if ($install_success)
{
  Write-Output "Installation of Code::Blocks 13.12 succeeded."
}
else
{
  Write-Output "Installation of Code::Blocks 13.12 FAILED!"
  Write-Output $error
}

# Delete the downloaded installer, because we do not want to clutter the file
# system.
If (Test-Path $output){
	Remove-Item $output
}

if ($install_success)
{
  # alright
  Exit 0
}
else
{
  # installation failed
  Exit 1
}
