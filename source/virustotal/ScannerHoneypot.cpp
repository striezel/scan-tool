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

#include "ScannerHoneypot.hpp"
#include <iostream>
#include <jsoncpp/json/reader.h>
#include "../Curly.hpp"
#include "../StringToTimeT.hpp"

namespace scantool
{

namespace virustotal
{

ScannerHoneypot::Report honeypotReportFromJSONRoot(const Json::Value& root)
{
  ScannerHoneypot::Report report;
  const Json::Value result = root["result"];
  if (!result.empty() && result.isInt())
    report.response_code = result.asInt();
  else
    report.response_code = 0;

  Json::Value val = root["permalink"];
  if (!val.empty() && val.isString())
    report.permalink = val.asString();
  else
    report.permalink = "";

  const Json::Value reportElem = root["report"];
  // first array element is scan date
  if (reportElem.isValidIndex(0))
  {
    val = reportElem.get(0u, Json::Value(Json::nullValue));
    if (!val.empty() && val.isString())
      report.scan_date = val.asString();
    else
      report.scan_date = "";
    if (!stringToTimeT(report.scan_date, report.scan_date_t))
      report.scan_date_t = static_cast<std::time_t>(-1);
  }
  else
  {
    report.scan_date = "";
    report.scan_date_t = static_cast<std::time_t>(-1);
    report.scans.clear();
  }

  report.positives = 0;

  // second array element is list of engines
  if (reportElem.isValidIndex(1))
  {
    const Json::Value engines = reportElem.get(1u, Json::Value(Json::nullValue));
    if (!engines.empty() && engines.isObject())
    {
      const auto members = engines.getMemberNames();
      auto iter = members.cbegin();
      const auto itEnd = members.cend();
      while (iter != itEnd)
      {
        scantool::Report::EnginePtr data = std::make_shared<scantool::Engine>();
        data->engine = *iter;
        const Json::Value virusVal = engines.get(*iter, Json::Value());
        if (!virusVal.empty() && virusVal.isString())
        {
          data->result = virusVal.asString();
        }
        else
          data->result = "";
        data->detected = (!data->result.empty());
        if (data->detected)
          ++report.positives;
        report.scans.push_back(std::move(data));
        ++iter;
      } // while
    } // if
    else
      report.scans.clear();
  } // if valid index
  else
  {
    report.scans.clear();
  }

  return std::move(report);
}

ScannerHoneypot::ScannerHoneypot(const std::string& apikey, const bool honourTimeLimits, const bool silent)
: Scanner(honourTimeLimits, silent),
  m_apikey(apikey)
{
}

void ScannerHoneypot::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::milliseconds ScannerHoneypot::timeBetweenConsecutiveScanRequests() const
{
  /* The public honeypot API allows 300 requests per five minutes, so we can
     perform one request every single second without hitting the rate limit.
  */
  return std::chrono::milliseconds(1000);
}

std::chrono::milliseconds ScannerHoneypot::timeBetweenConsecutiveHashLookups() const
{
  /* The public honeypot API allows 300 requests per five minutes, so we can
     perform one request every single second without hitting the rate limit.
  */
  return std::chrono::milliseconds(1000);
}

void ScannerHoneypot::scanRequestWasNow()
{
  /* VirusTotal API does not distinguish between the different kinds of
     requests and all requests have the same time limit. That is why we have
     to set both limits here. */
  m_LastScanRequest = std::chrono::steady_clock::now();
  m_LastHashLookup = m_LastScanRequest;
}

void ScannerHoneypot::hashLookupWasNow()
{
  /* VirusTotal API does not distinguish between the different kinds of
     requests and all requests have the same time limit. That is why we have
     to set both limits here. */
  m_LastHashLookup = std::chrono::steady_clock::now();
  m_LastScanRequest = m_LastHashLookup;
}

bool ScannerHoneypot::getReport(const std::string& scan_id, Report& report)
{
  waitForHashLookupLimitExpiration();
  // send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/api/get_submitted_file_report.json");
  cURL.addPostField("resource", scan_id);
  cURL.addPostField("key", m_apikey);

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerHoneypot::getReport(): Request could not be performed." << std::endl;
    return false;
  }
  hashLookupWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerHoneypot::getReport(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerHoneypot::getReport(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerHoneypot::getReport(): Unexpected HTTP status code "
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
    std::cerr << "Error in ScannerHoneypot::getReport(): Unable to parse JSON data!" << std::endl;
    return false;
  }
  #ifdef SCAN_TOOL_DEBUG
  const Json::Value result = root["result"];
  if (!result.empty() && result.isInt())
  {
    std::cout << "result: " << result.asInt() << std::endl;
  }
  #endif
  report = honeypotReportFromJSONRoot(root);
  return false;
}

bool ScannerHoneypot::scan(const std::string& filename, std::string& scan_id)
{
  if (filename.empty())
    return false;

  waitForScanLimitExpiration();
  // send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/api/bulk_scan_file.json");
  cURL.addPostField("key", m_apikey);
  if (!cURL.addFile(filename, "file"))
    return false;

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerHoneypot::scan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerHoneypot::scan(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerHoneypot::scan(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 413)
  {
    std::cerr << "Error in ScannerHoneypot::scan(): Code 413, Request entity is too large!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerHoneypot::scan(): Unexpected HTTP status code "
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
    std::cerr << "Error in ScannerHoneypot::scan(): Unable to parse JSON data!" << std::endl;
    return false;
  }

  const Json::Value result = root["result"];
  const Json::Value retrieved_scan_id = root["scan_id"];
  #ifdef SCAN_TOOL_DEBUG
  if (!result.empty() && result.isInt())
  {
    std::cout << "result: " << result.asInt() << std::endl;
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
  if (!result.empty() && result.isInt())
  {
    // Result code 1 means resource is queued for scan.
    return ((result.asInt() == 1) && !scan_id.empty());
  }
  // No result element: something is wrong with the API.
  return false;
}

int64_t ScannerHoneypot::maxScanSize() const noexcept
{
  // Maximum allowed scan size should be 32 MB.
  return 32 * 1024 * 1024;
}

} // namespace

} // namespace
