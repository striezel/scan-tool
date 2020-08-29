/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
    Copyright (C) 2015, 2016, 2020  Dirk Stolle

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

#include <algorithm>
#include <iostream>
#include <vector>
#include "../../../source/Curly.hpp"
#include "../../../libstriezel/common/StringUtils.hpp"

int main()
{
  Curly get;
  get.setURL(std::string("https://httpbin.org/response-headers?")
            + "Key=value"
            + "&X-Response-Header=foo+bar"
            + "&Xyz=Abc+def+ghi");
  std::string response;
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
  // print response
  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  const std::vector<std::string>& headers = get.responseHeaders();
  std::cout << "Curly's response headers (" << headers.size() << "):" << std::endl;
  for(const auto & s : headers)
  {
    std::cout << "    \"" << s << "\"" << std::endl;
  }
  std::cout << std::endl;

  // check for "Key: value"
  std::vector<std::string>::const_iterator iter = std::find_if(headers.begin(), headers.end(), [](const std::string &x) { return toLowerString(x) == "key: value"; });
  if (iter == headers.end())
  {
    std::cout << "Error: element \"Key: value\" is not among the response headers!" << std::endl;
    return 1;
  }
  // check for "X-Response-Header: foo bar"
  iter = std::find_if(headers.begin(), headers.end(), [](const std::string &x) { return toLowerString(x) == "x-response-header: foo bar"; });
  if (iter == headers.end())
  {
    std::cout << "Error: element \"X-Response-Header: foo bar\" is not among the response headers!" << std::endl;
    return 1;
  }
  // check for "Xyz: Abc def ghi"
  iter = std::find_if(headers.begin(), headers.end(), [](const std::string &x) { return toLowerString(x) == "xyz: abc def ghi"; });
  if (iter == headers.end())
  {
    std::cout << "Error: element \"Xyz: Abc def ghi\" is not among the response headers!" << std::endl;
    return 1;
  }
  // Response headers are OK.
  std::cout << "Curly's response headers are just fine." << std::endl;
  return 0;
}
