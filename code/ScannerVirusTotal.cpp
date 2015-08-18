/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Thoronador

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
 -------------------------------------------------------------------------------
*/

#include "ScannerVirusTotal.hpp"

ScannerVirusTotal::ScannerVirusTotal(const std::string& apikey, const bool honourTimeLimits)
: Scanner(honourTimeLimits),
  m_apikey(apikey)
{
}

void ScannerVirusTotal::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::seconds ScannerVirusTotal::timeBetweenConsecutiveRequests() const
{
  /* The public API allows four requests per minute, so we can perform one
     request every 15 seconds.
  */
  return std::chrono::seconds(15);
}
