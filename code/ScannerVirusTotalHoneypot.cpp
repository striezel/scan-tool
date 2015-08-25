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

#include "ScannerVirusTotalHoneypot.hpp"
#include <iostream>
#include <jsoncpp/json/reader.h>
#include "Curly.hpp"

ScannerVirusTotalHoneypot::Report::Engine::Engine()
: engine(""),
  detected(false),
  result("")
{
}

ScannerVirusTotalHoneypot::Report::Report()
: response_code(-1),
  scan_date(""),
  total(-1),
  positives(-1),
  scans(std::vector<Engine>()),
  permalink("")
{
}

ScannerVirusTotalHoneypot::Report honeypotReportFromJSONRoot(const Json::Value& root)
{
  ScannerVirusTotalHoneypot::Report report;
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
  //first array element is scan date
  if (reportElem.isValidIndex(0))
  {
    val = reportElem.get(0u, Json::Value(Json::nullValue));
    if (!val.empty() && val.isString())
      report.scan_date = val.asString();
    else
      report.scan_date = "";
  }
  else
  {
    report.scan_date = "";
    report.scans.clear();
  }

  report.positives = 0;

  //second array element is list of engines
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
        ScannerVirusTotalHoneypot::Report::Engine data;
        data.engine = *iter;
        const Json::Value virusVal = engines.get(*iter, Json::Value());
        if (!virusVal.empty() && virusVal.isString())
        {
          data.result = virusVal.asString();
        }
        else
          data.result = "";
        data.detected = (!data.result.empty());
        if (data.detected)
          ++report.positives;
        report.scans.push_back(std::move(data));
        ++iter;
      } //while
    } //if
    else
      report.scans.clear();
  } //if valid index
  else
  {
    report.scans.clear();
  }
  report.total = report.scans.size();

  return std::move(report);
}

ScannerVirusTotalHoneypot::ScannerVirusTotalHoneypot(const std::string& apikey, const bool honourTimeLimits, const bool silent)
: Scanner(honourTimeLimits, silent),
  m_apikey(apikey)
{
}

void ScannerVirusTotalHoneypot::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::seconds ScannerVirusTotalHoneypot::timeBetweenConsecutiveRequests() const
{
  /* The public honeypot API allows 3000 requests per five minutes, so we can
     perform one request every single second without hitting the rate limit.
  */
  return std::chrono::seconds(1);
}

bool ScannerVirusTotalHoneypot::getReport(const std::string& scan_id, Report& report)
{
  waitForLimitExpiration();
  //send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/api/get_submitted_file_report.json");
  cURL.addPostField("resource", scan_id);
  cURL.addPostField("key", m_apikey);

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::getReport(): Request could not be performed." << std::endl;
    return false;
  }
  requestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::getReport(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::getReport(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::getReport(): Unexpected HTTP status code "
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
    std::cerr << "Error in ScannerVirusTotalHoneypot::getReport(): Unable to parse JSON data!" << std::endl;
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

bool ScannerVirusTotalHoneypot::scan(const std::string& filename, std::string& scan_id)
{
  if (filename.empty())
    return false;

  waitForLimitExpiration();
  //send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/api/bulk_scan_file.json");
  cURL.addPostField("key", m_apikey);
  if (!cURL.addFile(filename, "file"))
    return false;

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::scan(): Request could not be performed." << std::endl;
    return false;
  }
  requestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::scan(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::scan(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 413)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::scan(): Code 413, Request entity is too large!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerVirusTotalHoneypot::scan(): Unexpected HTTP status code "
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
    std::cerr << "Error in ScannerVirusTotalHoneypot::scan(): Unable to parse JSON data!" << std::endl;
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
    //Result code 1 means resource is queued for scan.
    return ((result.asInt() == 1) && !scan_id.empty());
  }
  //No result element: something is wrong with the API.
  return false;
}

int64_t ScannerVirusTotalHoneypot::maxScanSize() const
{
  //Maximum allowed scan size should be 32 MB.
  return 32 * 1024 * 1024;
}
