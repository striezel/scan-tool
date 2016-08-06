/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Dirk Stolle

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

#include "ScannerV2.hpp"
#include <fstream>
#include <iostream>
#include <jsoncpp/json/reader.h>
#include "CacheManagerV2.hpp"
#include "../Curly.hpp"
#include "../../libthoro/filesystem/directory.hpp"
#include "../../libthoro/filesystem/file.hpp"

namespace scantool
{

namespace virustotal
{

ScannerV2::ScannerV2(const std::string& apikey, const bool honourTimeLimits, const bool silent)
: Scanner(honourTimeLimits, silent),
  m_apikey(apikey)
{
}

void ScannerV2::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::milliseconds ScannerV2::timeBetweenConsecutiveScanRequests() const
{
  /* The public API allows four requests per minute, so we can perform one
     request every 15 seconds without hitting the rate limit.
  */
  return std::chrono::milliseconds(15000);
}

std::chrono::milliseconds ScannerV2::timeBetweenConsecutiveHashLookups() const
{
  /* The public API allows four requests per minute, so we can perform one
     request every 15 seconds without hitting the rate limit.
  */
  return std::chrono::milliseconds(15000);
}

void ScannerV2::scanRequestWasNow()
{
  /* VirusTotal API does not distinguish between the different kinds of
     requests and all requests have the same time limit. That is why we have
     to set both limits here. */
  m_LastScanRequest = std::chrono::steady_clock::now();
  m_LastHashLookup = m_LastScanRequest;
}

void ScannerV2::hashLookupWasNow()
{
  /* VirusTotal API does not distinguish between the different kinds of
     requests and all requests have the same time limit. That is why we have
     to set both limits here. */
  m_LastHashLookup = std::chrono::steady_clock::now();
  m_LastScanRequest = m_LastHashLookup;
}

bool ScannerV2::getReport(const std::string& resource, Report& report, const bool useCache,
                   const std::string& cacheDir)
{
  std::string response = "";
  const std::string cachedFilePath = CacheManagerV2::getPathForCachedElement(resource, cacheDir);
  if (useCache && !cacheDir.empty() && !cachedFilePath.empty()
      && libthoro::filesystem::file::exists(cachedFilePath))
  {
    //try to read JSON data from cached file
    std::ifstream cachedJSON(cachedFilePath, std::ios_base::in | std::ios_base::binary);
    if (!cachedJSON.good())
    {
      std::cerr << "Error in ScannerV2::getReport(): Cached JSON could not be opened." << std::endl;
      return false;
    }
    std::string temp = "";
    while (!cachedJSON.eof() && std::getline(cachedJSON, temp, '\0'))
    {
      response.append(temp);
    }
    //File should be read until EOF, but failbit and badbit should not be set.
    if (!cachedJSON.eof() || cachedJSON.bad() || cachedJSON.fail())
    {
      cachedJSON.close();
      std::cerr << "Error in ScannerV2::getReport(): "
                << "Cached JSON could not be read." << std::endl;
      return false;
    }
    cachedJSON.close();
  } //if cached JSON file shall be used
  else
  {
    waitForHashLookupLimitExpiration();
    //send request via cURL
    Curly cURL;
    cURL.setURL("https://www.virustotal.com/vtapi/v2/file/report");
    cURL.addPostField("resource", resource);
    cURL.addPostField("apikey", m_apikey);

    if (!cURL.perform(response))
    {
      std::cerr << "Error in ScannerV2::getReport(): Request could not be performed." << std::endl;
      return false;
    }
    hashLookupWasNow();

    if (cURL.getResponseCode() == 204)
    {
      std::cerr << "Error in ScannerV2::getReport(): Rate limit exceeded!" << std::endl;
      return false;
    }
    if (cURL.getResponseCode() == 403)
    {
      std::cerr << "Error in ScannerV2::getReport(): Access denied!" << std::endl;
      return false;
    }
    if (cURL.getResponseCode() != 200)
    {
      std::cerr << "Error in ScannerV2::getReport(): Unexpected HTTP status code "
                << cURL.getResponseCode() << "!" << std::endl;
      const auto & rh = cURL.responseHeaders();
      std::cerr << "HTTP response headers (" << rh.size() << "):" << std::endl;
      for (const auto & s : rh)
      {
        std::cerr << "    " << s << std::endl;
      }
      return false;
    }
    #ifdef SCAN_TOOL_DEBUG
    std::cout << "Request was successful!" << std::endl
              << "Code: " << cURL.getResponseCode() << std::endl
              << "Content-Type: " << cURL.getContentType() << std::endl
              << "Response text: " << response << std::endl;
    #endif
    /* write JSON data to request cache, if request cache directory is given,
       independent of cache use during previous request
    */
    if (!cacheDir.empty() && libthoro::filesystem::directory::exists(cacheDir)
        && !cachedFilePath.empty())
    {
      std::ofstream cachedJSON(cachedFilePath, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
      if (!cachedJSON.good())
      {
        std::cerr << "Error in ScannerV2::getReport(): JSON data file could not be opened for update!" << std::endl;
        return false;
      }
      cachedJSON.write(response.c_str(), response.size());
      if (!cachedJSON.good())
      {
        cachedJSON.close();
        std::cerr << "Error in ScannerV2::getReport(): JSON data could not be written to cache!" << std::endl;
        return false;
      }
      cachedJSON.close();
    } //if request cache is enabled
  } //else (normal, uncached request)
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in ScannerV2::getReport(): Unable to parse JSON data!" << std::endl;
    /* If JSON data came from a cached file, then delete the file, because it
       is most likely corrupted, e.g. disk corruption or content manipulation.
    */
    if (useCache && !cacheDir.empty() && !cachedFilePath.empty()
      && libthoro::filesystem::file::exists(cachedFilePath))
    {
      CacheManagerV2::deleteCachedElement(resource, cacheDir);
    } //if
    return false;
  }

  #ifdef SCAN_TOOL_DEBUG
  const Json::Value response_code = root["response_code"];
  const Json::Value verbose_msg = root["verbose_msg"];
  if (!response_code.empty() && response_code.isInt())
  {
    std::cout << "response_code: " << response_code.asInt() << std::endl;
  }
  if (!verbose_msg.empty() && verbose_msg.isString())
  {
    std::cout << "verbose_msg: " << verbose_msg.asString() << std::endl;
  }
  #endif
  return report.fromJSONRoot(root);
}

bool ScannerV2::rescan(const std::string& resource, std::string& scan_id)
{
  waitForScanLimitExpiration();
  //send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/vtapi/v2/file/rescan");
  cURL.addPostField("resource", resource);
  cURL.addPostField("apikey", m_apikey);

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in Scanner::rescan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerV2::rescan(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerV2::rescan(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerV2::rescan(): Unexpected HTTP status code "
              << cURL.getResponseCode() << "!" << std::endl;
    const auto & rh = cURL.responseHeaders();
    std::cerr << "HTTP response headers (" << rh.size() << "):" << std::endl;
    for (const auto & s : rh)
    {
      std::cerr << "    " << s << std::endl;
    }
    return false;
  }

  #ifdef SCAN_TOOL_DEBUG
  std::cout << "Request was successful!" << std::endl
            << "Code: " << cURL.getResponseCode() << std::endl
            << "Content-Type: " << cURL.getContentType() << std::endl
            << "Response text: " << response << std::endl;
  #endif
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in ScannerV2::rescan(): Unable to parse JSON data!" << std::endl;
    return false;
  }

  const Json::Value response_code = root["response_code"];
  const Json::Value retrieved_scan_id = root["scan_id"];
  #ifdef SCAN_TOOL_DEBUG
  const Json::Value verbose_msg = root["verbose_msg"];
  if (!response_code.empty() && response_code.isInt())
  {
    std::cout << "response_code: " << response_code.asInt() << std::endl;
  }
  if (!verbose_msg.empty() && verbose_msg.isString())
  {
    std::cout << "verbose_msg: " << verbose_msg.asString() << std::endl;
  }
  if (!retrieved_scan_id.empty() && retrieved_scan_id.isString())
  {
    std::cout << "scan_id: " << retrieved_scan_id.asString() << std::endl;
  }
  #endif
  if (!retrieved_scan_id.empty() && retrieved_scan_id.isString())
  {
    scan_id = retrieved_scan_id.asString();
  }
  else
    scan_id = "";
  if (!response_code.empty() && response_code.isInt())
  {
    //Response code 1 means resource is queued for rescan.
    //Response code 0 means resource is not present in file store.
    //Response code -1 means that some kind of error occurred.
    return ((response_code.asInt() == 1) && !scan_id.empty());
  }
  //No response_code element: something is wrong with the API.
  return false;
}

bool ScannerV2::scan(const std::string& filename, std::string& scan_id)
{
  if (filename.empty())
    return false;

  waitForScanLimitExpiration();
  //send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/vtapi/v2/file/scan");
  cURL.addPostField("apikey", m_apikey);
  if (!cURL.addFile(filename, "file"))
    return false;

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerV2::scan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerV2::scan(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerV2::scan(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 413)
  {
    std::cerr << "Error in ScannerV2::scan(): Code 413, Request entity is too large!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerV2::scan(): Unexpected HTTP status code "
              << cURL.getResponseCode() << "!" << std::endl;
    const auto & rh = cURL.responseHeaders();
    std::cerr << "HTTP response headers (" << rh.size() << "):" << std::endl;
    for (const auto & s : rh)
    {
      std::cerr << "    " << s << std::endl;
    }
    return false;
  }

  #ifdef SCAN_TOOL_DEBUG
  std::cout << "Request was successful!" << std::endl
            << "Code: " << cURL.getResponseCode() << std::endl
            << "Content-Type: " << cURL.getContentType() << std::endl
            << "Response text: " << response << std::endl;
  #endif
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in ScannerV2::scan(): Unable to parse JSON data!" << std::endl;
    return false;
  }

  const Json::Value response_code = root["response_code"];
  const Json::Value retrieved_scan_id = root["scan_id"];
  #ifdef SCAN_TOOL_DEBUG
  if (!response_code.empty() && response_code.isInt())
  {
    std::cout << "response_code: " << response_code.asInt() << std::endl;
  }
  const Json::Value verbose_msg = root["verbose_msg"];
  if (!verbose_msg.empty() && verbose_msg.isString())
  {
    std::cout << "verbose_msg: " << verbose_msg.asString() << std::endl;
  }
  if (!retrieved_scan_id.empty() && retrieved_scan_id.isString())
  {
    std::cout << "scan_id: " << retrieved_scan_id.asString() << std::endl;
  }
  #endif
  if (!retrieved_scan_id.empty() && retrieved_scan_id.isString())
  {
    scan_id = retrieved_scan_id.asString();
  }
  else
    scan_id = "";
  if (!response_code.empty() && response_code.isInt())
  {
    //Response code 1 means resource is queued for scan.
    return ((response_code.asInt() == 1) && !scan_id.empty());
  }
  //No response_code element: something is wrong with the API.
  return false;
}

int64_t ScannerV2::maxScanSize() const
{
  //Maximum allowed scan size is 32 MB.
  return 32 * 1024 * 1024;
}

} //namespace

} //namespace
