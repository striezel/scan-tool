/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2021  Dirk Stolle

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
#include "../../third-party/simdjson/simdjson.h"
#include "../Curly.hpp"
#include "../StringToTimeT.hpp"

namespace scantool
{

namespace virustotal
{

ScannerHoneypot::Report honeypotReportFromJSONRoot(const simdjson::dom::element& doc)
{
  ScannerHoneypot::Report report;
  simdjson::dom::element elem;
  simdjson::error_code error;
  doc["result"].tie(elem, error);
  if (!error && elem.is_int64())
    report.response_code = elem.get<int64_t>().value();
  else
    report.response_code = 0;

  doc["permalink"].tie(elem, error);
  if (!error && elem.is_string())
    report.permalink = elem.get<std::string_view>().value();
  else
    report.permalink = "";

  simdjson::dom::element reportElem;
  doc["report"].tie(reportElem, error);
  // first array element is scan date
  if (!error && reportElem.is_array() && !reportElem.at(0))
  {
    error = reportElem.at(0).get(elem);
    if (!error && elem.is_string())
      report.scan_date = elem.get<std::string_view>().value();
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
  simdjson::dom::element engines;
  error = reportElem.at(1).get(engines);
  if (!error && engines.is_object())
  {
    const simdjson::dom::object enginesObject(engines);
    for (const auto [key, value] : enginesObject)
    {
      scantool::Report::EnginePtr data = std::make_shared<scantool::Engine>();
      data->engine = key;
      if (value.is_string())
      {
        data->result = value.get<std::string_view>().value();
      }
      else
        data->result = "";
      data->detected = !data->result.empty();
      if (data->detected)
        ++report.positives;
      report.scans.push_back(std::move(data));
    } // for
  } // if
  else
    report.scans.clear();

  return report;
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
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(response).get(doc);
  if (error)
  {
    std::cerr << "Error in ScannerHoneypot::getReport(): Unable to parse JSON data!" << std::endl;
    return false;
  }
  #ifdef SCAN_TOOL_DEBUG
  simdjson::dom::element result;
  doc["result"].tie(result, error);
  if (!error && result.is_int64())
  {
    std::cout << "result: " << result.get<int64_t>().value() << std::endl;
  }
  #endif
  report = honeypotReportFromJSONRoot(doc);
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
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(response).get(doc);
  if (error)
  {
    std::cerr << "Error in ScannerHoneypot::scan(): Unable to parse JSON data!" << std::endl;
    return false;
  }

  simdjson::dom::element result;
  simdjson::error_code result_error;
  doc["result"].tie(result, result_error);
  simdjson::dom::element retrieved_scan_id;
  simdjson::error_code retrieved_scan_id_error;
  doc["scan_id"].tie(retrieved_scan_id, retrieved_scan_id_error);
  #ifdef SCAN_TOOL_DEBUG
  if (!result_error && result.is_int64())
  {
    std::cout << "result: " << result.get<int64_t>().value() << std::endl;
  }
  if (!retrieved_scan_id_error && retrieved_scan_id.is_string())
  {
    std::cout << "scan_id: " << retrieved_scan_id.get<std::string_view>().value() << std::endl;
  }
  #endif
  if (!retrieved_scan_id_error && retrieved_scan_id.is_string())
  {
    scan_id = retrieved_scan_id.get<std::string_view>().value();
  }
  else
    scan_id = "";
  if (!result_error && result.is_int64())
  {
    // Result code 1 means resource is queued for scan.
    return ((result.get<int64_t>().value() == 1) && !scan_id.empty());
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
