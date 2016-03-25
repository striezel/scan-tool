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

#include <algorithm>
#include <iostream>
#include <vector>
#include "../../../source/Curly.hpp"

int main()
{
  Curly get;
  //set URL
  get.setURL(std::string("https://httpbin.org/response-headers?")
            + "Key=value"
            + "&X-Response-Header=foo+bar"
            + "&Xyz=Abc+def+ghi");
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
  //print response
  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  const std::vector<std::string>& headers = get.responseHeaders();
  std::cout << "Curly's response headers (" << headers.size() << "):" << std::endl;
  for(const auto & s : headers)
  {
    std::cout << "    \"" << s << "\"" << std::endl;
  }
  std::cout << std::endl;

  if (headers.size() >= 12)
  {
    std::cout << "headers[11] is ";
    int i;
    for(i = 0; i< headers[11].size(); ++i)
    {
      std::cout << (int) (headers[11].at(i)) << " ";
    }
    std::cout << std::endl;
  }

  //check for "Key: value"
  std::vector<std::string>::const_iterator iter = std::find(headers.begin(), headers.end(), "Key: value");
  if (iter == headers.end())
  {
    std::cout << "Error: element \"Key: value\" is not among the response headers!" << std::endl;
    return 1;
  }
  //check for "X-Response-Header: foo bar"
  iter = std::find(headers.begin(), headers.end(), "X-Response-Header: foo bar");
  if (iter == headers.end())
  {
    std::cout << "Error: element \"X-Response-Header: foo bar\" is not among the response headers!" << std::endl;
    return 1;
  }
  //check for "Xyz: Abc def ghi"
  iter = std::find(headers.begin(), headers.end(), "Xyz: Abc def ghi");
  if (iter == headers.end())
  {
    std::cout << "Error: element \"Xyz: Abc def ghi\" is not among the response headers!" << std::endl;
    return 1;
  }
  //Response headers are OK.
  std::cout << "Curly's response headers are just fine." << std::endl;
  return 0;
}
