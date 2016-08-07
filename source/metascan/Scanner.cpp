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

#include "Scanner.hpp"
#include <iostream>
#include "../Curly.hpp"
#include "../../libstriezel/hash/sha256/sha256.hpp"
#include "../../libstriezel/filesystem/directory.hpp"
#include "../../libstriezel/filesystem/file.hpp"

namespace scantool
{

namespace metascan
{

Scanner::Scanner(const std::string& apikey, const bool honourTimeLimits, const bool silent, const std::string& certFile)
: scantool::Scanner(honourTimeLimits, silent),
  m_apikey(apikey),
  m_certFile(certFile)
{
}

Scanner::ScanData::ScanData()
: data_id(""),
  rest_ip("")
{
}

bool Scanner::ScanData::operator< (const ScanData& other) const
{
  if (data_id < other.data_id)
    return true;
  if (data_id == other.data_id)
    return (rest_ip < other.rest_ip);
  return false;
}

void Scanner::setApiKey(const std::string& apikey)
{
  if (!apikey.empty())
    m_apikey = apikey;
}

std::chrono::milliseconds Scanner::timeBetweenConsecutiveScanRequests() const
{
  /* Metadefender Cloud allows only five file scans per hour,
     i.e. one scan every 12 minutes or 720 seconds. */
  return std::chrono::milliseconds(720000);
}

std::chrono::milliseconds Scanner::timeBetweenConsecutiveHashLookups() const
{
  /* Metadefender Cloud allows 100 hash lookups per hour,
     i.e. one request every 36 seconds. */
  return std::chrono::milliseconds(36000);
}

bool Scanner::getReport(const std::string& resource, Report& report)
{
  //We only want SHA 256 hashes here, no MD5 or SHA 1.
  if (!SHA256::isValidHash(resource))
    return false;

  std::string response = "";
  waitForHashLookupLimitExpiration();
  //send request via cURL
  Curly cURL;
  cURL.setURL("https://hashlookup.metadefender.com/v2/hash/"+resource);
  //add API key
  cURL.addHeader("apikey: "+m_apikey);
  //indicate that we want more meta data for the file
  cURL.addHeader("file_metadata: 1");

  if (!m_certFile.empty())
  {
    if (!cURL.setCertificateFile(m_certFile))
    {
      std::cerr << "Error in Scanner::getReport(): Certificate file could not be set." << std::endl;
      return false;
    }
  } //if certificate file

  if (!cURL.perform(response))
  {
    std::cerr << "Error in Scanner::getReport(): Request could not be performed." << std::endl;
    return false;
  }
  hashLookupWasNow();

  //400: Bad request
  if (cURL.getResponseCode() == 400)
  {
    std::cerr << "Error in Scanner::getReport(): Bad request!" << std::endl;
    return false;
  }
  //401: wrong or missing API key
  if (cURL.getResponseCode() == 401)
  {
    std::cerr << "Error in Scanner::getReport(): API key is wrong or missing!" << std::endl;
    return false;
  }
  //403: greetings from your hourly rate limit
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in Scanner::getReport(): Hourly rate limit reached!" << std::endl;
    return false;
  }
  //response code should be 200
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in Scanner::getReport(): Unexpected HTTP status code "
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
  // parse JSON response
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in Scanner::getReport(): Unable to "
              << "parse JSON data!" << std::endl;
    return false;
  }
  // fill report with JSON data
  if (!report.fromJSONRoot(root))
  {
    std::cerr << "Error in Scanner::getReport(): The parsed "
              << "JSON does not contain data to fill a report!" << std::endl;
    return false;
  }
  //all done here
  return true;
}

bool Scanner::rescan(const std::string& file_id, ScanData& scan_data)
{
  if (file_id.empty())
    return false;

  std::string response = "";
  waitForScanLimitExpiration();
  //send request via cURL
  Curly cURL;
  cURL.setURL("https://scan.metadefender.com/v2/rescan/" + file_id);
  //add API key
  cURL.addHeader("apikey: "+m_apikey);

  if (!m_certFile.empty())
  {
    if (!cURL.setCertificateFile(m_certFile))
    {
      std::cerr << "Error in Scanner::rescan(): Certificate file could not be set." << std::endl;
      return false;
    }
  } //if certificate file

  //perform request
  if (!cURL.perform(response))
  {
    std::cerr << "Error in Scanner::rescan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  //400: Bad request
  if (cURL.getResponseCode() == 400)
  {
    std::cerr << "Error in Scanner::rescan(): Bad request!" << std::endl;
    return false;
  }
  //401: wrong or missing API key
  if (cURL.getResponseCode() == 401)
  {
    std::cerr << "Error in Scanner::rescan(): API key is wrong or missing!" << std::endl;
    return false;
  }
  //500: internal server error / server temporary unavailable
  if (cURL.getResponseCode() == 500)
  {
    std::cerr << "Error in Scanner::rescan(): Internal server error / server temporarily unavailable!" << std::endl;
    return false;
  }
  //503: Server temporary unavailable. There're too many unfinished file in pending queue.
  if (cURL.getResponseCode() == 503)
  {
    std::cerr << "Error in Scanner::rescan(): Service temporarily unavailable!"
              << " There are too many unfinished file in pending queue."
              << " Try again later." << std::endl;
    return false;
  }
  //response code should be 200
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in Scanner::rescan(): Unexpected HTTP status code "
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
  // parse JSON response
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in Scanner::rescan(): Unable to parse "
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

bool Scanner::scan(const std::string& filename, ScanData& scan_data)
{
  if (filename.empty())
    return false;

  //get file content, so we can put it into HTTP POST body later
  /* This might cause huge memory consumption for large files, so we should be
     careful which files we use here.
  */
  std::string content = "";
  if (!libstriezel::filesystem::file::readIntoString(filename, content))
    return false;

  //wait
  waitForScanLimitExpiration();

  //send request
  Curly cURL;
  cURL.setURL("https://scan.metadefender.com/v2/file");
  cURL.addHeader("apikey: " + m_apikey);
  //scope for "basename" stuff
  {
    //add "basename" of file for better file info after scan
    std::string dummy, fName, ext;
    libstriezel::filesystem::splitPathFileExtension(filename, libstriezel::filesystem::pathDelimiter, dummy, fName, ext);
    if (!fName.empty())
    {
      if (!ext.empty())
        cURL.addHeader("filename: " + fName + '.' + ext);
      else
        cURL.addHeader("filename: " + fName);
    } //if
  } //scope

  //set file content as HTTP POST body
  cURL.setPostBody(content);

  //set certificate file, if one was specified
  if (!m_certFile.empty())
  {
    if (!cURL.setCertificateFile(m_certFile))
    {
      std::cerr << "Error in Scanner::scan(): Certificate file could not be set." << std::endl;
      return false;
    }
  } //if certificate file

  std::string response = "";
  if (!cURL.perform(response))
  {
    std::cerr << "Error in Scanner::scan(): Request could not be performed." << std::endl;
    return false;
  }
  scanRequestWasNow();

  //400: Bad request
  if (cURL.getResponseCode() == 400)
  {
    std::cerr << "Error in Scanner::scan(): Bad request!" << std::endl;
    return false;
  }
  //401: wrong or missing API key
  if (cURL.getResponseCode() == 401)
  {
    std::cerr << "Error in Scanner::scan(): API key is wrong or missing!" << std::endl;
    return false;
  }
  //403: scan limit reached
  if (cURL.getResponseCode() == 403)
  {
    std::cerr << "Error in Scanner::scan(): The hourly scan limit has been reached!" << std::endl;
    return false;
  }
  //500: internal server error / server temporary unavailable
  if (cURL.getResponseCode() == 500)
  {
    std::cerr << "Error in Scanner::scan(): Internal server error / server temporarily unavailable!" << std::endl;
    return false;
  }
  //503: Server temporary unavailable due to maintenance or overloading.
  if (cURL.getResponseCode() == 503)
  {
    std::cerr << "Error in Scanner::scan(): Service temporarily"
              << " unavailable due to maintenance or overloading."
              << " Try again later." << std::endl;
    return false;
  }
  //response code should be 200
  if (cURL.getResponseCode() != 200)
  {
    std::cerr << "Error in Scanner::scan(): Unexpected HTTP status code "
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
  // parse JSON response
  Json::Value root; // will contain the root value after parsing.
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error in Scanner::scan(): Unable to parse "
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

int64_t Scanner::maxScanSize() const
{
  //Assume 140 MB like on the web interface.
  return 140*1024*1024;
}

} //namespace

} //namespace
