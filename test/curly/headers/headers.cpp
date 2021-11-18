/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
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

#include <iostream>
#include <utility>
#include <vector>
#include "../../../third-party/simdjson/simdjson.h"
#include "../../../source/Curly.hpp"

int main()
{
  Curly get;
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
  }

  // perform request
  std::string response = "";
  if (!get.perform(response))
  {
    std::cout << "Error: Could not perform GET request!" << std::endl;
    return 1;
  }
  // check HTTP status code
  if (get.getResponseCode() != 200)
  {
    std::cout << "Error: HTTP status code is not 200, it is "
              << get.getResponseCode() << " instead!" << std::endl;
    return 1;
  }
  // check content type
  if (get.getContentType() != "application/json" && !get.getContentType().empty())
  {
    std::cout << "Error: Content type is not application/json, it is "
              << get.getContentType() << " instead!" << std::endl;
    return 1;
  }
  // check response
  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(response).get(doc);
  if (error)
  {
    std::cerr << "Error: Unable to parse JSON data from response!" << std::endl;
    return 1;
  }

  simdjson::dom::element headers;
  doc["headers"].tie(headers, error);
  if (error || !headers.is_object())
  {
    std::cout << "Error: headers element in response is empty or no object!" << std::endl;
    return 1;
  }
  simdjson::dom::element elem;
  // check for "Foo: bar"
  headers["Foo"].tie(elem, error);
  if (error || !elem.is_string())
  {
    std::cout << "Error: element Foo in response is empty or no string!" << std::endl;
    return 1;
  }
  if (elem.get<std::string_view>().value() != "bar")
  {
    std::cout << "Error: Value of Foo is not \"bar\", but \""
              << elem.get<std::string_view>().value()
              << "\" instead!" << std::endl;
    return 1;
  }

  // check for "X-Custom-Header-Test: scan-tool test suite"
  headers["X-Custom-Header-Test"].tie(elem, error);
  if (error || !elem.is_string())
  {
    std::cout << "Error: element X-Custom-Header-Test in response is empty or no string!" << std::endl;
    return 1;
  }
  if (elem.get<std::string_view>().value() != "scan-tool test suite")
  {
    std::cout << "Error: Value of X-Custom-Header-Test is not \"scan-tool test suite\", but \""
              << elem.get<std::string_view>().value() << "\" instead!" << std::endl;
    return 1;
  }
  std::cout << "Curly's headers are just fine." << std::endl;
  return 0;
}
