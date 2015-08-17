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

#include "Curly.hpp"
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

void Curly::addPostField(const std::string& name, const std::string& value)
{
  m_PostFields[name] = value;
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

  //construct fields for post request
  #ifdef DEBUG_MODE
  std::clog << "curl_easy_escape(...)..." << std::endl;
  #endif
  std::string postfields("");
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
      return false;
    }
    postfields += "=" + std::string(c_str);
    curl_free(c_str);
    //... and go on with next field
    ++iter;
  } //while

  // --set post fields
  if (!postfields.empty())
  {
    retCode = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, postfields.c_str());
    if (retCode != CURLE_OK)
    {
      std::cerr << "cURL error: setting POST fields for Curly::perform failed! Error: "
                << curl_easy_strerror(retCode) << std::endl;
      curl_easy_cleanup(handle);
      return false;
    }
  } //if post fields exist

  //set write callback
  retCode = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, writeCallbackString);
  if (retCode != CURLE_OK)
  {
    std::cerr << "curl_easy_setopt() of Curly::perform could not set write function! Error: "
              << curl_easy_strerror(retCode) << std::endl;
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
    curl_easy_cleanup(handle);
    return false;
  }
  #ifdef DEBUG_MODE
  else
  {
    std::clog << "POST request data was sent to server." << std::endl;
  }
  #endif

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
  retCode = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &contType);
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
  #warning TODO!
  response = string_data;
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
