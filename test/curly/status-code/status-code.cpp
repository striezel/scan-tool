/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
    Copyright (C) 2016  Dirk Stolle

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
#include <vector>
#include "../../../libthoro/common/StringUtils.hpp"
#include "../../../source/Curly.hpp"

int main()
{
  //basic URL for status code tests
  const std::string baseURL = "https://httpbin.org/status/";

  //vector of status codes that will be used in the test
  const std::vector<int> testCodes = {
     200, //OK
     204, //No content
     300, //Multiple choices
     304, //Not modified
     400, //bad request
     401, //unauthorized
     402, //payment required
     403, //forbidden
     404, //Not found
     405, //method not allowed
     406, //not acceptable
     410, //Gone
     418, //Teapot
     500, //Internal serve error
     501, //Not implemented
     502, //Bad gateway
     503, //Service unavailable
     504, //Gateway timeout
     505  //HTTP version not supported
  };


  for (const auto sc : testCodes)
  {
    Curly statusCode;
    //set URL
    statusCode.setURL(baseURL + intToString(sc));
    //perform post request
    std::string response = "";
    if (!statusCode.perform(response))
    {
      std::cout << "Error: Could not perform HTTP request!" << std::endl;
      return 1;
    }
    //check HTTP status code
    if (statusCode.getResponseCode() != sc)
    {
      std::cout << "Error: HTTP status code is not " << sc << ", it is "
                << statusCode.getResponseCode() << " instead!" << std::endl;
      return 1;
    }
    //check content type
    if (statusCode.getContentType() != "application/json" && !statusCode.getContentType().empty())
    {
      std::cout << "Error: Content type is not application/json, it is "
                << statusCode.getContentType() << " instead!" << std::endl;
      return 1;
    }

    //show teapot (because that's the only one with something nice to show)
    if ((sc == 418) && !response.empty())
      std::cout << "Have some tea." << std::endl << response << std::endl;
  } //for

  std::cout << "Curly's status codes are fine. All of the " << testCodes.size()
            << " test requests returned the proper status code." << std::endl;
  return 0;
}
