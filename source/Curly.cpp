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

#include "Curly.hpp"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <memory>
#include <curl/curl.h>

size_t writeCallbackString(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  const size_t actualSize = size * nmemb;
  if (userdata == nullptr)
  {
    std::cerr << "Error: write callback received NULL pointer!" << std::endl;
    return 0;
  }

  const auto cBufferSize = actualSize+1;
  std::unique_ptr<char[]> tmpBuffer(new char[cBufferSize]);
  std::memcpy(tmpBuffer.get(), ptr, actualSize);
  tmpBuffer.get()[actualSize] = '\0';

  std::string data = std::string(tmpBuffer.get());
  while (data.size() < actualSize)
  {
    data.append(1, '\0');
    data += tmpBuffer.get()[data.size()];
  } //while

  std::string * theString = reinterpret_cast<std::string*>(userdata);
  theString->append(data);
  return actualSize;
}

Curly::Curly()
: m_URL(""),
  m_PostFields(std::unordered_map<std::string, std::string>()),
  m_Files(std::unordered_map<std::string, std::string>()),
  m_headers(std::vector<std::string>()),
  m_LastResponseCode(0),
  m_LastContentType("")
{
}

void Curly::setURL(const std::string& newURL)
{
  if (!newURL.empty())
    m_URL = newURL;
}

const std::string& Curly::getURL() const
{
  return m_URL;
}

bool Curly::addPostField(const std::string& name, const std::string& value)
{
  //No empty names, and avoid conflict with file field names.
  if (!name.empty() && (m_Files.find(name) == m_Files.end()))
  {
    m_PostFields[name] = value;
    return true;
  }
  else
    return false;
}

bool Curly::hasPostField(const std::string& name) const
{
  return (m_PostFields.find(name) != m_PostFields.end());
}

std::string Curly::getPostField(const std::string& name) const
{
  const auto iter = m_PostFields.find(name);
  if (iter != m_PostFields.end())
    return iter->second;
  return std::move(std::string(""));
}

bool Curly::removePostField(const std::string& name)
{
  return (m_PostFields.erase(name) > 0);
}

bool Curly::addFile(const std::string& filename, const std::string& field)
{
  //No empty field or file names!
  if (field.empty() || filename.empty())
    return false;
  //Avoid name conflict with post fields.
  if (m_PostFields.find(field) != m_PostFields.end())
    return false;
  //Add file.
  m_Files[field] = filename;
  return true;
}

const std::vector<std::string>& Curly::getHeaders() const
{
  return m_headers;
}

bool Curly::addHeader(const std::string& header)
{
  /* There are some rules for reasonable headers:
     - No empty headers.
     - Header must not be present yet.
     - Header has to contain a colon (":"), but not as first character.
     - Header must not contain CRLF.
  */
  const auto colonPos = header.find(':');
  if (!header.empty()
      && (std::find(m_headers.cbegin(), m_headers.cend(), header) == m_headers.cend())
      && (colonPos != std::string::npos) && (colonPos > 0)
      && (header.find('\n') == std::string::npos)
      && (header.find('\r') == std::string::npos))
  {
    m_headers.push_back(header);
    return true;
  } //if conditions for header are met
  //Not a valid header!
  return false;
}

bool Curly::perform(std::string& response)
{
  //"minimum" URL should be something like "http://a.bc"
  if (m_URL.size() < 11)
    return false;

  //initialize cURL
  #ifdef DEBUG_MODE
  std::clog << "curl_easy_init()..." << std::endl;
  #endif
  CURL * handle = curl_easy_init();
  if (NULL==handle)
  {
    //cURL error
    std::cerr << "cURL easy init failed!" << std::endl;;
    return false;
  }

  //set URL
  #ifdef DEBUG_MODE
  std::clog << "curl_easy_setopt(..., URL, ...)..." << std::endl;
  #endif
  CURLcode retCode = curl_easy_setopt(handle, CURLOPT_URL, m_URL.c_str());
  if (retCode != CURLE_OK)
  {
    std::cerr << "cURL error: setting URL failed!" << std::endl;
    std::cerr << curl_easy_strerror(retCode) << std::endl;
    curl_easy_cleanup(handle);
    return false;
  }

  //add custom headers
  struct curl_slist * header_list = nullptr;
  if (!m_headers.empty())
  {
    #ifdef DEBUG_MODE
    std::clog << "adding headers with curl_slist_append() ..." << std::endl;
    #endif // DEBUG_MODE
    for(auto const & h: m_headers)
    {
      header_list = curl_slist_append(header_list, h.c_str());
      if (nullptr == header_list)
      {
        std::cerr << "cURL error: creation of header list failed!" << std::endl;
        std::cerr << curl_easy_strerror(retCode) << std::endl;
        curl_easy_cleanup(handle);
        return false;
      }
    } //for
    //add headers to the handle
    #ifdef DEBUG_MODE
    std::clog << "curl_easy_setopt(handle, CURLOPT_HTTPHEADER, ...)" << std::endl;
    #endif // DEBUG_MODE
    retCode = curl_easy_setopt(handle, CURLOPT_HTTPHEADER, header_list);
    if (retCode != CURLE_OK)
    {
      std::cerr << "cURL error: setting custom headers failed!" << std::endl;
      std::cerr << curl_easy_strerror(retCode) << std::endl;
      curl_slist_free_all(header_list);
      header_list = nullptr;
      curl_easy_cleanup(handle);
      return false;
    }
  } //if custom headers are given

  //construct fields for post request
  #ifdef DEBUG_MODE
  std::clog << "curl_easy_escape(...)..." << std::endl;
  #endif
  std::string postfields("");
  if (m_Files.empty())
  {
    auto iter = m_PostFields.begin();
    while (iter != m_PostFields.end())
    {
      //escape key
      char * c_str = curl_easy_escape(handle, iter->first.c_str(), iter->first.length());
      if (c_str == nullptr)
      {
        //escaping failed!
        std::cerr << "cURL error: escaping of post values failed!" << std::endl;
        curl_easy_cleanup(handle);
        curl_slist_free_all(header_list);
        header_list = nullptr;
        return false;
      }
      if (!postfields.empty())
        postfields += "&"+std::string(c_str);
      else
        postfields += std::string(c_str);
      curl_free(c_str);
      //escape value
      c_str = curl_easy_escape(handle, iter->second.c_str(), iter->second.length());
      if (c_str == nullptr)
      {
        //escaping failed!
        std::cerr << "cURL error: escaping of post values failed!" << std::endl;
        curl_easy_cleanup(handle);
        curl_slist_free_all(header_list);
        header_list = nullptr;
        return false;
      }
      postfields += "=" + std::string(c_str);
      curl_free(c_str);
      //... and go on with next field
      ++iter;
    } //while
  } //no files

  // --set post fields
  if (!postfields.empty())
  {
    retCode = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, postfields.c_str());
    if (retCode != CURLE_OK)
    {
      std::cerr << "cURL error: setting POST fields for Curly::perform failed! Error: "
                << curl_easy_strerror(retCode) << std::endl;
      curl_easy_cleanup(handle);
      curl_slist_free_all(header_list);
      header_list = nullptr;
      return false;
    }
  } //if post fields exist

  //multipart/formdata
  struct curl_httppost* formFirst = nullptr;
  struct curl_httppost* formLast = nullptr;
  if (!m_Files.empty())
  {
    auto fileIter = m_Files.begin();
    while (fileIter != m_Files.end())
    {
      CURLFORMcode errCode = curl_formadd(&formFirst, &formLast,
                             CURLFORM_COPYNAME, fileIter->first.c_str(),
                             CURLFORM_FILE, fileIter->second.c_str(),
                             CURLFORM_END);
      if (errCode != CURL_FORMADD_OK)
      {
        std::cerr << "cURL error: could not add file to multipart/formdata!"
                  << std::endl;
        curl_formfree(formFirst);
        curl_slist_free_all(header_list);
        header_list = nullptr;
        curl_easy_cleanup(handle);
        return false;
      }
      ++fileIter;
    } //while

    //add normal post fields
    auto pfIter = m_PostFields.begin();
    while (pfIter != m_PostFields.end())
    {
      CURLFORMcode errCode = curl_formadd(&formFirst, &formLast,
                             CURLFORM_COPYNAME, pfIter->first.c_str(),
                             CURLFORM_COPYCONTENTS, pfIter->second.c_str(),
                             CURLFORM_END);
      if (errCode != CURL_FORMADD_OK)
      {
        std::cerr << "cURL error: could not add file to multipart/formdata!"
                  << std::endl;
        curl_formfree(formFirst);
        curl_slist_free_all(header_list);
        header_list = nullptr;
        curl_easy_cleanup(handle);
        return false;
      }
      ++pfIter;
    } //while post fields
    retCode = curl_easy_setopt(handle, CURLOPT_HTTPPOST, formFirst);
    if (retCode != CURLE_OK)
    {
      std::cerr << "cURL error: setting multipart form data failed! Error: "
                << curl_easy_strerror(retCode) << std::endl;
      curl_formfree(formFirst);
      curl_slist_free_all(header_list);
      header_list = nullptr;
      curl_easy_cleanup(handle);
      return false;
    }
  } //if files are there

  //set write callback
  retCode = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeCallbackString);
  if (retCode != CURLE_OK)
  {
    std::cerr << "curl_easy_setopt() of Curly::perform could not set write function! Error: "
              << curl_easy_strerror(retCode) << std::endl;
    curl_formfree(formFirst);
    curl_slist_free_all(header_list);
    header_list = nullptr;
    curl_easy_cleanup(handle);
    return false;
  }
  //provide string stream for the data
  std::string string_data("");
  retCode = curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&string_data);
  if (retCode != CURLE_OK)
  {
    std::cerr << "curl_easy_setopt() of Curly::perform could not set write data! Error: "
              << curl_easy_strerror(retCode) << std::endl;
    curl_formfree(formFirst);
    curl_slist_free_all(header_list);
    header_list = nullptr;
    curl_easy_cleanup(handle);
    return false;
  }

  //send
  #ifdef DEBUG_MODE
  std::clog << "calling cURL easy perform..." << std::endl;
  #endif
  retCode = curl_easy_perform(handle);
  if (retCode != CURLE_OK)
  {
    std::cerr << "curl_easy_perform() of Curly::perform failed! Error: "
              << curl_easy_strerror(retCode) << std::endl;
    curl_formfree(formFirst);
    curl_slist_free_all(header_list);
    header_list = nullptr;
    curl_easy_cleanup(handle);
    return false;
  }
  #ifdef DEBUG_MODE
  else
  {
    std::clog << "POST request data was sent to server." << std::endl;
  }
  #endif
  //free multipart/formdata, if any data was given
  curl_formfree(formFirst);
  formFirst = nullptr;

  //free header data, if any data was given
  curl_slist_free_all(header_list);
  header_list = nullptr;

  //get response code
  retCode = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &m_LastResponseCode);
  if (retCode != CURLE_OK)
  {
    std::cerr << "curl_easy_getinfo() of Curly::perform failed! Error: "
              << curl_easy_strerror(retCode) << std::endl;
    curl_easy_cleanup(handle);
    m_LastResponseCode = 0;
    return false;
  }
  //get content type
  char * contType = nullptr;
  retCode = curl_easy_getinfo(handle, CURLINFO_CONTENT_TYPE, &contType);
  if (retCode != CURLE_OK)
  {
    std::cerr << "curl_easy_getinfo() of Curly::perform failed! Error: "
              << curl_easy_strerror(retCode) << std::endl;
    curl_easy_cleanup(handle);
    m_LastContentType.erase();
    return false;
  }
  if (contType == NULL)
    m_LastContentType.erase();
  else
    m_LastContentType = std::string(m_LastContentType);

  curl_easy_cleanup(handle);
  response = std::move(string_data);
  return true;
}

long Curly::getResponseCode() const
{
  return m_LastResponseCode;
}

const std::string& Curly::getContentType() const
{
  return m_LastContentType;
}

Curly::VersionData::VersionData()
: cURL(""),
  ssl(""),
  libz(""),
  protocols(std::vector<std::string>()),
  ares(""),
  idn(""),
  ssh("")
{
}

Curly::VersionData Curly::curlVersion()
{
  auto data = curl_version_info(CURLVERSION_NOW);
  VersionData vd;
  if (data->age < 0)
    return vd;
  //cURL version
  vd.cURL = std::string(data->version);
  //OpenSSL version
  if (data->ssl_version != nullptr)
    vd.ssl = std::string(data->ssl_version);
  //zlib version
  if (data->libz_version != nullptr)
    vd.libz = std::string(data->libz_version);
  //supported protocols
  if (data->protocols != nullptr)
  {
    unsigned int i;
    for (i = 0; data->protocols[i] != nullptr; ++i)
    {
      vd.protocols.push_back(std::string(data->protocols[i]));
    } //for
  } //if

  if (data->age < 1)
    return vd;
  //ares version
  if (data->ares != nullptr)
    vd.ares = std::string(data->ares);

  if (data->age < 2)
    return vd;
  //idn version
  if (data->libidn != nullptr)
    vd.idn = std::string(data->libidn);

  if (data->age < 3)
    return vd;
  //libssh version
  if (data->libssh_version != nullptr)
    vd.ssh = std::string(data->libssh_version);
  return vd;
}
