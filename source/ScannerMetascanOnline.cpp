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

#include "ScannerMetascanOnline.hpp"
#include <iostream>
#include "Curly.hpp"
#include "../libthoro/hash/sha256/sha256.hpp"

ScannerMetascanOnline::ScannerMetascanOnline(const std::string& apikey, const bool honourTimeLimits, const bool silent)
: Scanner(honourTimeLimits, silent),
  m_apikey(apikey)
{
}

void ScannerMetascanOnline::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::seconds ScannerMetascanOnline::timeBetweenConsecutiveRequests() const
{
  /* Metascan Online allows 1500 hash lookups per hour,
     i.e. one request every 2.4 seconds.
     However, we round that up to three seconds as long as this function in
     the base class Scanner can only handle seconds and not milliseconds.
  */
  #warning TODO: change prototype in Scanner to return milliseconds instead of seconds.
  //return std::chrono::milliseconds(2400);
  return std::chrono::seconds(3);
}

bool ScannerMetascanOnline::getReport(const std::string& resource, ReportMetascanOnline& report)
{
  //We only want SHA 256 hashes here, no MD5 or SHA 1.
  if (!SHA256::isValidHash(resource))
    return false;

  std::string response = "";
  waitForLimitExpiration();
  //send request via cURL
  Curly cURL;
  cURL.setURL("https://hashlookup.metascan-online.com/v2/hash/"+resource);
  //add API key
  cURL.addHeader("apikey: "+m_apikey);
  //indicate that we want more meta data for the file
  cURL.addHeader("file_metadata: 1");

  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): Request could not be performed." << std::endl;
    return false;
  }
  requestWasNow();

  //400: Bad request
  if (cURL.getResponseCode() == 400)
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): Bad request!" << std::endl;
    return false;
  }
  //401: wrong or missing API key
  if (cURL.getResponseCode() == 401)
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): API key is wrong or missing!" << std::endl;
    return false;
  }
  //403: greetings from your hourly rate limit
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): Hourly rate limit reached!" << std::endl;
    return false;
  }
  //response code should be 200
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): Unexpected HTTP status code "
              << cURL.getResponseCode() << "!" << std::endl;
    return false;
  }
  #ifdef SCAN_TOOL_DEBUG
  std::cout << "Request was successful!" << std::endl
            << "Code: " << cURL.getResponseCode() << std::endl
            << "Content-Type: " << cURL.getContentType() << std::endl
            << "Response text: " << response << std::endl;
  #endif
  // parse JSON response
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): Unable to "
              << "parse JSON data!" << std::endl;
    return false;
  }
  // fill report with JSON data
  if (!report.fromJSONRoot(root))
  {
    std::cerr << "Error in ScannerMetascanOnline::getReport(): The parsed "
              << "JSON does not contain data to fill a report!" << std::endl;
    return false;
  }
  //all done here
  return true;
}

int64_t ScannerMetascanOnline::maxScanSize() const
{
  //unknown? Assume 50 MB for starters.
  #warning TODO: Find out where the real limit is.
  return 50*1024*1024;
}
