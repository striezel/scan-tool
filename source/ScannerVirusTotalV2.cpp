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

#include "ScannerVirusTotalV2.hpp"
#include <fstream>
#include <iostream>
#include <jsoncpp/json/reader.h>
#include "CacheManagerVirusTotalV2.hpp"
#include "Curly.hpp"
#include "StringToTimeT.hpp"
#include "../libthoro/filesystem/DirectoryFunctions.hpp"
#include "../libthoro/filesystem/FileFunctions.hpp"

ScannerVirusTotalV2::Report reportFromJSONRoot(const Json::Value& root)
{
  ScannerVirusTotalV2::Report report;
  const Json::Value response_code = root["response_code"];
  const Json::Value verbose_msg = root["verbose_msg"];
  if (!response_code.empty() && response_code.isInt())
    report.response_code = response_code.asInt();
  else
    report.response_code = 0;
  if (!verbose_msg.empty() && verbose_msg.isString())
    report.verbose_msg = verbose_msg.asString();
  Json::Value val = root["resource"];
  if (!val.empty() && val.isString())
    report.resource = val.asString();
  else
    report.resource = "";
  val = root["scan_id"];
  if (!val.empty() && val.isString())
    report.scan_id = val.asString();
  else
    report.scan_id = "";
  val = root["scan_date"];
  if (!val.empty() && val.isString())
  {
    report.scan_date = val.asString();
    if (!stringToTimeT(report.scan_date, report.scan_date_t))
      report.scan_date_t = static_cast<std::time_t>(-1);
  }
  else
  {
    report.scan_date = "";
    report.scan_date_t = static_cast<std::time_t>(-1);
  }
  val = root["total"];
  if (!val.empty() && val.isInt())
    report.total = val.asInt();
  else
    report.total = -1;
  val = root["positives"];
  if (!val.empty() && val.isInt())
    report.positives = val.asInt();
  else
    report.positives = -1;
  val = root["permalink"];
  if (!val.empty() && val.isString())
    report.permalink = val.asString();
  else
    report.permalink = "";
  val = root["md5"];
  if (!val.empty() && val.isString())
    report.md5 = val.asString();
  else
    report.md5 = "";
  val = root["sha1"];
  if (!val.empty() && val.isString())
    report.sha1 = val.asString();
  else
    report.sha1 = "";
  val = root["sha256"];
  if (!val.empty() && val.isString())
    report.sha256 = val.asString();
  else
    report.sha256 = "";
  const Json::Value scans = root["scans"];
  if (!scans.empty() && scans.isObject())
  {
    report.scans.clear();
    const auto members = scans.getMemberNames();
    auto iter = members.cbegin();
    const auto itEnd = members.cend();
    while (iter != itEnd)
    {
      std::shared_ptr<ScannerVirusTotalV2::Report::Engine> data(new ScannerVirusTotalV2::Report::Engine());
      data->engine = *iter;

      const Json::Value engVal = scans.get(*iter, Json::Value());
      //detected
      Json::Value val = engVal["detected"];
      if (!val.empty() && val.isBool())
        data->detected = val.asBool();
      else
        data->detected = false;
      //version
      val = engVal["version"];
      if (!val.empty() && val.isString())
        data->version = val.asString();
      else
        data->version = "";
      //result
      val = engVal["result"];
      if (!val.empty() && val.isString())
        data->result = val.asString();
      else
        data->result = "";
      //update
      val = engVal["update"];
      if (!val.empty() && val.isString())
        data->update = val.asString();
      else
        data->update = "";
      report.scans.push_back(std::move(data));
      ++iter;
    } //while
  } //if "scans" is present
  else
    report.scans.clear();

  return std::move(report);
}

ScannerVirusTotalV2::ScannerVirusTotalV2(const std::string& apikey, const bool honourTimeLimits, const bool silent)
: Scanner(honourTimeLimits, silent),
  m_apikey(apikey)
{
}

void ScannerVirusTotalV2::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::milliseconds ScannerVirusTotalV2::timeBetweenConsecutiveScanRequests() const
{
  /* The public API allows four requests per minute, so we can perform one
     request every 15 seconds without hitting the rate limit.
  */
  return std::chrono::milliseconds(15000);
}

std::chrono::milliseconds ScannerVirusTotalV2::timeBetweenConsecutiveHashLookups() const
{
  /* The public API allows four requests per minute, so we can perform one
     request every 15 seconds without hitting the rate limit.
  */
  return std::chrono::milliseconds(15000);
}

void ScannerVirusTotalV2::scanRequestWasNow()
{
  /* VirusTotal API does not distinguish between the different kinds of
     requests and all requests have the same time limit. That is why we have
     to set both limits here. */
  m_LastScanRequest = std::chrono::steady_clock::now();
  m_LastHashLookup = m_LastScanRequest;
}

void ScannerVirusTotalV2::hashLookupWasNow()
{
  /* VirusTotal API does not distinguish between the different kinds of
     requests and all requests have the same time limit. That is why we have
     to set both limits here. */
  m_LastHashLookup = std::chrono::steady_clock::now();
  m_LastScanRequest = m_LastHashLookup;
}

bool ScannerVirusTotalV2::getReport(const std::string& resource, Report& report, const bool useCache,
                   const std::string& cacheDir)
{
  std::string response = "";
  const std::string cachedFilePath = CacheManagerVirusTotalV2::getPathForCachedElement(resource, cacheDir);
  if (useCache && !cacheDir.empty() && !cachedFilePath.empty()
      && libthoro::filesystem::File::exists(cachedFilePath))
  {
    //try to read JSON data from cached file
    std::ifstream cachedJSON(cachedFilePath, std::ios_base::in | std::ios_base::binary);
    if (!cachedJSON.good())
    {
      std::cerr << "Error in ScannerVirusTotalV2::getReport(): Cached JSON could not be opened." << std::endl;
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
      std::cerr << "Error in ScannerVirusTotalV2::getReport(): "
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
      std::cerr << "Error in ScannerVirusTotalV2::getReport(): Request could not be performed." << std::endl;
      return false;
    }
    hashLookupWasNow();

    if (cURL.getResponseCode() == 204)
    {
      std::cerr << "Error in ScannerVirusTotalV2::getReport(): Rate limit exceeded!" << std::endl;
      return false;
    }
    if (cURL.getResponseCode() == 403)
    {
      std::cerr << "Error in ScannerVirusTotalV2::getReport(): Access denied!" << std::endl;
      return false;
    }
    if (cURL.getResponseCode() != 200)
    {
      std::cerr << "Error in ScannerVirusTotalV2::getReport(): Unexpected HTTP status code "
                << cURL.getResponseCode() << "!" << std::endl;
      return false;
    }
    #ifdef SCAN_TOOL_DEBUG
    std::cout << "Request was successful!" << std::endl
              << "Code: " << cURL.getResponseCode() << std::endl
              << "Content-Type: " << cURL.getContentType() << std::endl
              << "Response text: " << response << std::endl;
    #endif
    //write JSON data to request cache, if request cache is enabled
    if (useCache && !cacheDir.empty() && libthoro::filesystem::Directory::exists(cacheDir))
    {
      std::ofstream cachedJSON(cachedFilePath, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
      if (!cachedJSON.good())
      {
        std::cerr << "Error in ScannerVirusTotalV2::getReport(): JSON data could not be opened for update!" << std::endl;
        return false;
      }
      cachedJSON.write(response.c_str(), response.size());
      if (!cachedJSON.good())
      {
        cachedJSON.close();
        std::cerr << "Error in ScannerVirusTotalV2::getReport(): JSON data could not be written to cache!" << std::endl;
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
    std::cerr << "Error in ScannerVirusTotalV2::getReport(): Unable to parse JSON data!" << std::endl;
    /* If JSON data came from a cached file, then delete the file, because it
       is most likely corrupted, e.g. disk corruption or content manipulation.
    */
    if (useCache && !cacheDir.empty() && !cachedFilePath.empty()
      && libthoro::filesystem::File::exists(cachedFilePath))
    {
      CacheManagerVirusTotalV2::deleteCachedElement(resource, cacheDir);
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
  report = reportFromJSONRoot(root);
  return true;
}

bool ScannerVirusTotalV2::rescan(const std::string& resource, std::string& scan_id)
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
    std::cerr << "Error in ScannerVirusTotalV2::rescan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerVirusTotalV2::rescan(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerVirusTotalV2::rescan(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerVirusTotalV2::rescan(): Unexpected HTTP status code "
              << cURL.getResponseCode() << "!" << std::endl;
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
    std::cerr << "Error in ScannerVirusTotalV2::rescan(): Unable to parse JSON data!" << std::endl;
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

bool ScannerVirusTotalV2::scan(const std::string& filename, std::string& scan_id)
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
    std::cerr << "Error in ScannerVirusTotalV2::scan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerVirusTotalV2::scan(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerVirusTotalV2::scan(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 413)
  {
    std::cerr << "Error in ScannerVirusTotalV2::scan(): Code 413, Request entity is too large!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerVirusTotalV2::scan(): Unexpected HTTP status code "
              << cURL.getResponseCode() << "!" << std::endl;
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
    std::cerr << "Error in ScannerVirusTotalV2::scan(): Unable to parse JSON data!" << std::endl;
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

int64_t ScannerVirusTotalV2::maxScanSize() const
{
  //Maximum allowed scan size is 32 MB.
  return 32 * 1024 * 1024;
}
