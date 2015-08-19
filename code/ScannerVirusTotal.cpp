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
#include <iostream>
#include <jsoncpp/json/reader.h>
#include "Curly.hpp"

ScannerVirusTotal::Report::Report()
: response_code(-1),
  verbose_msg(""),
  resource(""),
  scan_id(""),
  scan_date(""),
  total(-1),
  positives(-1),
  permalink(""),
  md5(""), sha1(""), sha256("")
{
}

ScannerVirusTotal::Report reportFromJSONRoot(const Json::Value& root)
{
  ScannerVirusTotal::Report report;
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
    report.scan_date = val.asString();
  else
    report.scan_date = "";
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
  return std::move(report);
}

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

bool ScannerVirusTotal::getReport(const std::string& resource, Report& report)
{
  waitForLimitExpiration();
  //send request
  Curly cURL;
  cURL.setURL("https://www.virustotal.com/vtapi/v2/file/report");
  cURL.addPostField("resource", resource);
  cURL.addPostField("apikey", m_apikey);

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in ScannerVirusTotal::getReport(): Request could not be performed." << std::endl;
    return false;
  }
  requestWasNow();

  if (cURL.getResponseCode() == 204)
  {
    std::cerr << "Error in ScannerVirusTotal::getReport(): Rate limit exceeded!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in ScannerVirusTotal::getReport(): Access denied!" << std::endl;
    return false;
  }
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in ScannerVirusTotal::getReport(): Unexpected HTTP status code "
              << cURL.getResponseCode() << "!" << std::endl;
    return false;
  }

  std::cout << "Request was successful!" << std::endl
            << "Code: " << cURL.getResponseCode() << std::endl
            << "Content-Type: " << cURL.getContentType() << std::endl
            << "Response text: " << response << std::endl;

  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in ScannerVirusTotal::getReport(): Unable to parse JSON data!" << std::endl;
    return false;
  }

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
  report = reportFromJSONRoot(root);
  return true;
}
