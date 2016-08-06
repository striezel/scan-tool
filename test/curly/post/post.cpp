/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
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

#include <iostream>
#include <vector>
#include <jsoncpp/json/reader.h>
#include "../../../source/Curly.hpp"

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

  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  //check response
  Json::Value root; // will contain the root value after parsing
  Json::Reader jsonReader;
  const bool success = jsonReader.parse(response, root, false);
  if (!success)
  {
    std::cerr << "Error: Unable to parse JSON data from response!" << std::endl;
    return 1;
  }

  const Json::Value form = root["form"];
  if (form.empty() || !form.isObject())
  {
    std::cout << "Error: form element in response is empty or no object!" << std::endl;
    return 1;
  }
  //check for "foo"
  Json::Value val = form["foo"];
  if (val.empty() || !val.isString())
  {
    std::cout << "Error: element foo in response is empty or no string!" << std::endl;
    return 1;
  }
  if (val.asString() != "bar")
  {
    std::cout << "Error: Value of foo is not \"bar\", but \"" << val.asString()
              << "\" instead!" << std::endl;
    return 1;
  }
  //check for "ping"
  val = form["ping"];
  if (val.empty() || !val.isString())
  {
    std::cout << "Error: element ping in response is empty or no string!" << std::endl;
    return 1;
  }
  if (val.asString() != "pong")
  {
    std::cout << "Error: Value of ping is not \"pong\", but \"" << val.asString()
              << "\" instead!" << std::endl;
    return 1;
  }

  std::cout << "Curly's POST fields are fine." << std::endl;
  return 0;
}
