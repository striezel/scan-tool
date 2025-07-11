/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
    Copyright (C) 2016, 2021, 2025  Dirk Stolle

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

#include <chrono>
#include <fstream>
#include <iostream>
#include <thread>
#include <vector>
#include "../../../third-party/simdjson/simdjson.h"
#include "../../../source/Curly.hpp"

int main()
{
  // This is a test for setting POST body directly,

  // basic URL
  const std::string HeadToThisPlaceSecurely = "https://httpbin.org/post";

  // test data
  /* Note: The version of libjsoncpp that is used with Debian 7 ("wheezy") and
     Ubuntu 12.04 ("precise") is 0.6.0, and that version has a problem with
     embedded NUL characters in strings. In fact, strings returned by
     Json::Value::asString() are cut after the first NUL byte, because NUL
     bytes signal the end of C-style strings (basically char * / char[]) and
     therefore the first NUL character is interpreted as end of string.

     That is why the following test does not use strings with embedded NUL
     bytes, although that would be an interesting test case.
  */
  const std::vector<std::string> testData = {
    "", // empty string
    "This is a test.", // string without any "special" characters
    std::string("Line one\nLine two\r\nLine three\t\vTest"), // line feeds etc.
    std::string(200, '\x05'), // 200 bytes with value 5
    // test the first 128 possible characters / bytes, except the NUL byte
    // (See reason for exclusion of NUL byte above.)
    "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f",
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f",
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f",
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f",
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f",
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f",
    /*
    // Bytes from 0x80 turn the data element in httpbin.org's response into an
    // octet stream, which is base64-encoded. However, I do not want to write a
    // base64 decoder for that test, so I'll leave the rest out of the test.
    "\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f",
    "\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f",
    "\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf",
    "\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf",
    "\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf",
    "\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf",
    "\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef",
    "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
    */
  };

  // iterate over test data
  for (const auto & elem : testData)
  {
    Curly postBody;
    // set URL
    postBody.setURL(HeadToThisPlaceSecurely);
    // add the post body
    if (!postBody.setPostBody(elem))
    {
      std::cout << "Error: Could not set POST body!" << std::endl;
      return 1;
    }
    // set content type to text/plain to avoid interpretation as URL encoded form
    if (!postBody.addHeader("Content-Type: text/plain"))
    {
      std::cout << "Error: Could not add Content-Type header!" << std::endl;
      return 1;
    }

    // perform request
    std::string response = "";
    unsigned int attempts = 0;
    constexpr unsigned int max_attempts = 3;
    for ( ; ; )
    {
      if (!postBody.perform(response))
      {
        std::cout << "Error: Could not perform post request!" << std::endl;
        return 1;
      }
      ++attempts;
      if ((attempts >= max_attempts) || (postBody.getResponseCode() == 200))
      {
        break;
      }
      if ((postBody.getResponseCode() == 502) && (attempts < max_attempts))
      {
        std::cout << "Info: Server seems to have a problem. "
                  << "I'll wait a few seconds and try again.\n";
        std::this_thread::sleep_for(std::chrono::seconds(2));
      }
    }

    // check HTTP status code
    if (postBody.getResponseCode() != 200)
    {
      std::cout << "Error: HTTP status code is not 200, it is "
                << postBody.getResponseCode() << " instead!" << std::endl;
      return 1;
    }
    // check content type
    if (postBody.getContentType() != "application/json" && !postBody.getContentType().empty())
    {
      std::cout << "Error: Content type is not application/json, it is "
                << postBody.getContentType() << " instead!" << std::endl;
      return 1;
    }

    // check response
    simdjson::dom::parser parser;
    simdjson::dom::element doc;
    auto error = parser.parse(response).get(doc);
    if (error)
    {
      std::cerr << "Error: Unable to parse JSON data from response!" << std::endl;
      std::cerr << "Response:" << std::endl << response << std::endl << std::endl;
      return 1;
    }

    simdjson::dom::element data;
    doc["data"].tie(data, error);
    if (error || !data.is_string())
    {
      std::cerr << "Error: data element in response is empty or no string!" << std::endl;
      std::cerr << "Response:" << std::endl << response << std::endl << std::endl;
      return 1;
    }
    // check against original value
    if (data.get<std::string_view>().value() != elem)
    {
      std::cerr << "Error: Value of data is not \"" << elem << "\", but \""
                << data.get<std::string_view>().value() << "\" instead!\n";
      std::cerr << "Response:" << std::endl << response << std::endl << std::endl;
      return 1;
    }
  }

  std::cout << "Curly's POST body seems to be OK." << std::endl;
  return 0;
}
