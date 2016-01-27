/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
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

#include <iostream>
#include <utility>
#include <vector>
#include <jsoncpp/json/reader.h>
#include "../../../source/Curly.hpp"

int main()
{
  Curly get;
  //set URL
  get.setURL("https://httpbin.org/headers");
  // test headers
  const std::vector<std::pair<std::string, bool> > testHeaders = {
      { "Foo: bar", true},
      { "X-Custom-Header-Test: scan-tool test suite", true},
      // empty header, should fail
      { "", false},
      // missing colon (":"), should fail
      { "ThisHeaderDoesNotContainAColon or does it?", false},
      //has colon, but as first character, should fail
      { ": DotDot", false},
      // CRLF not allowed, should fail
      { "X-Custom-Header-ABC: Hey \r\n", false},
      { "X-Custom-Header-DEF: Hey \r", false},
      { "X-Custom-Header-GHI: Hey \n", false}
  };

  //try to add headers
  for (const auto & elem : testHeaders)
  {
    if (get.addHeader(elem.first) != elem.second)
    {
      std::cout << "Error: Header \"" << elem.first << "\" could ";
      if (elem.second)
        std::cout << "NOT be added!" << std::endl;
      else
        std::cout << " be added, although that should NOT be possible!" << std::endl;
      return 1;
    }
  } //for

  //perform request
  std::string response = "";
  if (!get.perform(response))
  {
    std::cout << "Error: Could not perform GET request!" << std::endl;
    return 1;
  }
  //check HTTP status code
  if (get.getResponseCode() != 200)
  {
    std::cout << "Error: HTTP status code is not 200, it is "
              << get.getResponseCode() << " instead!" << std::endl;
    return 1;
  }
  //check content type
  if (get.getContentType() != "application/json" && !get.getContentType().empty())
  {
    std::cout << "Error: Content type is not application/json, it is "
              << get.getContentType() << " instead!" << std::endl;
    return 1;
  }
  //check response
  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  Json::Value root; // will contain the root value after parsing
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error: Unable to parse JSON data from response!" << std::endl;
    return 1;
  }

  Json::Value headers = root["headers"];
  if (headers.empty() || !headers.isObject())
  {
    std::cout << "Error: headers element in response is empty or no object!" << std::endl;
    return 1;
  }
  //check for "Foo: bar"
  Json::Value val = headers["Foo"];
  if (val.empty() || !val.isString())
  {
    std::cout << "Error: element Foo in response is empty or no string!" << std::endl;
    return 1;
  }
  if (val.asString() != "bar")
  {
    std::cout << "Error: Value of Foo is not \"bar\", but \"" << val.asString()
              << "\" instead!" << std::endl;
    return 1;
  }

  //check for "X-Custom-Header-Test: scan-tool test suite"
  val = headers["X-Custom-Header-Test"];
  if (val.empty() || !val.isString())
  {
    std::cout << "Error: element X-Custom-Header-Test in response is empty or no string!" << std::endl;
    return 1;
  }
  if (val.asString() != "scan-tool test suite")
  {
    std::cout << "Error: Value of X-Custom-Header-Test is not \"scan-tool test suite\", but \""
              << val.asString() << "\" instead!" << std::endl;
    return 1;
  }
  std::cout << "Curly's headers are just fine." << std::endl;
  return 0;
}
