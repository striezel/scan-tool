/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
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

#include <iostream>
#include <vector>
#include "../../code/Curly.hpp"

int main()
{
  Curly post;
  //check, if URL is empty
  if (post.getURL() != "")
  {
    std::cout << "Error: URL precondition not met." << std::endl;
    return 1;
  }
  //set URL
  const std::string HeadToThisPlaceSecurely = "https://httpbin.org/post";
  post.setURL(HeadToThisPlaceSecurely);
  //... and check new value
  if (post.getURL() != HeadToThisPlaceSecurely)
  {
    std::cout << "Error: URL postcondition not met." << std::endl;
    return 1;
  }
  //add some fields
  post.addPostField("foo", "bar");
  post.addPostField("ping", "pong");
  //perform post request
  std::string response = "";
  if (!post.perform(response))
  {
    std::cout << "Error: Could not perform post request!" << std::endl;
    return 1;
  }
  //check HTTP status code
  if (post.getResponseCode() != 200)
  {
    std::cout << "Error: HTTP status code is not 200, it is "
              << post.getResponseCode() << " instead!" << std::endl;
    return 1;
  }
  //check content type
  if (post.getContentType() != "application/json" && !post.getContentType().empty())
  {
    std::cout << "Error: Content type is not application/json, it is "
              << post.getContentType() << " instead!" << std::endl;
    return 1;
  }
  //check response
  std::vector<std::string> expectedSubstrings = {
      std::string("\"args\": {}"),
      "\"data\": \"\"",
      "\"files\": {}",
      "\"form\": {",
      "\"foo\": \"bar\",",
      "\"ping\": \"pong\"",
      "\"Host\": \"httpbin.org\"",
      "\"url\": \"https://httpbin.org/post\""
  };

  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  for (const auto & item : expectedSubstrings)
  {
    if (response.find(item) == std::string::npos)
    {
      std::cout << "Error: Expected and actual response do not match!" << std::endl
                << "Expected response to contain \"" << item << "\", but it does not."
                << std::endl;
    return 1;
    }
  } //for

  std::cout << "Curly is fine." << std::endl;
  return 0;
}
