/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

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
#include "../libthoro/filesystem/DirectoryFunctions.hpp"
#include "../libthoro/filesystem/FileFunctions.hpp"

ScannerMetascanOnline::ScannerMetascanOnline(const std::string& apikey, const bool honourTimeLimits, const bool silent)
: Scanner(honourTimeLimits, silent),
  m_apikey(apikey)
{
}

ScannerMetascanOnline::RescanData::RescanData()
: data_id(""),
  rest_ip("")
{
}

void ScannerMetascanOnline::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::milliseconds ScannerMetascanOnline::timeBetweenConsecutiveScanRequests() const
{
  /* Metascan Online allows 25 file scans per hour,
     i.e. one scan every 144 seconds. */
  return std::chrono::milliseconds(144000);
}

std::chrono::milliseconds ScannerMetascanOnline::timeBetweenConsecutiveHashLookups() const
{
  /* Metascan Online allows 1500 hash lookups per hour,
     i.e. one request every 2.4 seconds. */
  return std::chrono::milliseconds(2400);
}

bool ScannerMetascanOnline::getReport(const std::string& resource, ReportMetascanOnline& report)
{
  //We only want SHA 256 hashes here, no MD5 or SHA 1.
  if (!SHA256::isValidHash(resource))
    return false;

  std::string response = "";
  waitForHashLookupLimitExpiration();
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
  hashLookupWasNow();

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

bool ScannerMetascanOnline::rescan(const std::string& file_id, RescanData& scan_data)
{
  if (file_id.empty())
    return false;

  std::string response = "";
  waitForScanLimitExpiration();
  //send request via cURL
  Curly cURL;
  cURL.setURL("https://scan.metascan-online.com/v2/rescan/" + file_id);
  //add API key
  cURL.addHeader("apikey: "+m_apikey);

  //perform request
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerMetascanOnline::rescan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  //400: Bad request
  if (cURL.getResponseCode() == 400)
  {
    std::cerr << "Error in ScannerMetascanOnline::rescan(): Bad request!" << std::endl;
    return false;
  }
  //401: wrong or missing API key
  if (cURL.getResponseCode() == 401)
  {
    std::cerr << "Error in ScannerMetascanOnline::rescan(): API key is wrong or missing!" << std::endl;
    return false;
  }
  //500: internal server error / server temporary unavailable
  if (cURL.getResponseCode() == 500)
  {
    std::cerr << "Error in ScannerMetascanOnline::rescan(): Internal server error / server temporarily unavailable!" << std::endl;
    return false;
  }
  //503: Server temporary unavailable. There're too many unfinished file in pending queue.
  if (cURL.getResponseCode() == 503)
  {
    std::cerr << "Error in ScannerMetascanOnline::rescan(): Service temporarily unavailable!"
              << " There are too many unfinished file in pending queue."
              << " Try again later." << std::endl;
    return false;
  }
  //response code should be 200
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerMetascanOnline::rescan(): Unexpected HTTP status code "
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
    std::cerr << "Error in ScannerMetascanOnline::rescan(): Unable to parse "
              << "JSON data!" << std::endl;
    return false;
  }
  //data_id
  Json::Value js_value = root["data_id"];
  if (!js_value.empty() && js_value.isString())
    scan_data.data_id = js_value.asString();
  else
  {
    scan_data.data_id.clear();
  } //else
  //rest_ip
  js_value = root["rest_ip"];
  if (!js_value.empty() && js_value.isString())
    scan_data.rest_ip = js_value.asString();
  else
  {
    scan_data.rest_ip.clear();
  } //else

  //Found?
  return (!scan_data.data_id.empty() && !scan_data.rest_ip.empty());
}

bool ScannerMetascanOnline::scan(const std::string& filename, RescanData& scan_data)
{
  if (filename.empty())
    return false;

  waitForScanLimitExpiration();
  //send request
  Curly cURL;
  cURL.setURL("https://scan.metascan-online.com/v2/file");
  cURL.addHeader("apikey: " + m_apikey);
  //scope for "basename" stuff
  {
    //add "basename" of file for better file info after scan
    std::string dummy, fName, ext;
    libthoro::filesystem::splitPathFileExtension(filename, libthoro::filesystem::pathDelimiter, dummy, fName, ext);
    if (!fName.empty())
    {
      if (!ext.empty())
        cURL.addHeader("filename: " + fName + '.' + ext);
      else
        cURL.addHeader("filename: " + fName);
    } //if
  } //scope
  if (!cURL.addFile(filename, "file"))
    return false;

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  //400: Bad request
  if (cURL.getResponseCode() == 400)
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): Bad request!" << std::endl;
    return false;
  }
  //401: wrong or missing API key
  if (cURL.getResponseCode() == 401)
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): API key is wrong or missing!" << std::endl;
    return false;
  }
  //403: scan limit reached
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): The hourly scan limit has been reached!" << std::endl;
    return false;
  }
  //500: internal server error / server temporary unavailable
  if (cURL.getResponseCode() == 500)
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): Internal server error / server temporarily unavailable!" << std::endl;
    return false;
  }
  //503: Server temporary unavailable due to maintenance or overloading.
  if (cURL.getResponseCode() == 503)
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): Service temporarily"
              << " unavailable due to maintenance or overloading."
              << " Try again later." << std::endl;
    return false;
  }
  //response code should be 200
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerMetascanOnline::scan(): Unexpected HTTP status code "
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
    std::cerr << "Error in ScannerMetascanOnline::scan(): Unable to parse "
              << "JSON data!" << std::endl;
    return false;
  }
  //data_id
  Json::Value js_value = root["data_id"];
  if (!js_value.empty() && js_value.isString())
    scan_data.data_id = js_value.asString();
  else
  {
    scan_data.data_id.clear();
  } //else
  //rest_ip
  js_value = root["rest_ip"];
  if (!js_value.empty() && js_value.isString())
    scan_data.rest_ip = js_value.asString();
  else
  {
    scan_data.rest_ip.clear();
  } //else

  //Did we get the data and initialize a scan?
  return (!scan_data.data_id.empty() && !scan_data.rest_ip.empty());
}

int64_t ScannerMetascanOnline::maxScanSize() const
{
  //unknown? Assume 50 MB for starters.
  #warning TODO: Find out where the real limit is.
  return 50*1024*1024;
}
