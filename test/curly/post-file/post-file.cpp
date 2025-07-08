/*
 -------------------------------------------------------------------------------
    This file is part of the scan-tool test suite.
    Copyright (C) 2015, 2016, 2021, 2025  Dirk Stolle

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

#include <fstream>
#include <iostream>
#include <vector>
#include "../../../third-party/simdjson/simdjson.h"
#include "../../../libstriezel/filesystem/file.hpp"
#include "../../../source/Curly.hpp"

int main()
{
  // **** test for file submission capability in POST requests ****

  Curly post;
  // check, if URL is empty
  if (post.getURL() != "")
  {
    std::cout << "Error: URL precondition not met." << std::endl;
    return 1;
  }
  // set URL
  const std::string HeadToThisPlaceSecurely = "https://httpbin.org/post";
  post.setURL(HeadToThisPlaceSecurely);
  // ... and check new value
  if (post.getURL() != HeadToThisPlaceSecurely)
  {
    std::cout << "Error: URL postcondition not met." << std::endl;
    return 1;
  }
  // add some fields
  post.addPostField("foo", "bar");
  post.addPostField("ping", "pong");
  // add the file
  #if defined(_WIN32)
  if (!post.addFile("nul", "fieldname"))
  #else
  if (!post.addFile("/dev/null", "fieldname"))
  #endif
  {
    std::cout << "Error: Could not add file to request data!" << std::endl;
    return 1;
  }

  // get temporary file
  std::string tmpFileName = "";
  if (!libstriezel::filesystem::file::createTemp(tmpFileName))
  {
    std::cout << "Error: Could not create temporary file!" << std::endl;
    return 1;
  }
  // fill it with some data
  std::ofstream output(tmpFileName, std::ios_base::out | std::ios_base::binary | std::ios_base::trunc);
  if (!output.good())
  {
    std::cerr << "Error: Temporary file could not be opened." << std::endl;
    libstriezel::filesystem::file::remove(tmpFileName);
    return 1;
  }
  const std::string content = "This is some random data.\nHave fun with that.";
  output.write(&content[0], content.length());
  if (!output.good())
    return 1;
  output.close();

  // add the temporary file
  if (!post.addFile(tmpFileName, "tempfile"))
  {
    std::cout << "Error: Could not add file " << tmpFileName << " to request data!" << std::endl;
    libstriezel::filesystem::file::remove(tmpFileName);
    return 1;
  }

  // perform post request
  std::string response = "";
  if (!post.perform(response))
  {
    std::cout << "Error: Could not perform post request!" << std::endl;
    libstriezel::filesystem::file::remove(tmpFileName);
    return 1;
  }

  // remove temporary file
  libstriezel::filesystem::file::remove(tmpFileName);

  // check HTTP status code
  if (post.getResponseCode() != 200)
  {
    std::cout << "Error: HTTP status code is not 200, it is "
              << post.getResponseCode() << " instead!" << std::endl;
    return 1;
  }
  // check content type
  if (post.getContentType() != "application/json" && !post.getContentType().empty())
  {
    std::cout << "Error: Content type is not application/json, it is "
              << post.getContentType() << " instead!" << std::endl;
    return 1;
  }

  std::cout << "Response:" << std::endl << response << std::endl << std::endl;

  // check response
  simdjson::dom::parser parser;
  simdjson::dom::element doc;
  auto error = parser.parse(response).get(doc);
  if (error)
  {
    std::cerr << "Error: Unable to parse JSON data from response!" << std::endl;
    return 1;
  }

  simdjson::dom::element files;
  doc["files"].tie(files, error);
  if (error || !files.is_object())
  {
    std::cout << "Error: files element in response is empty or no object!" << std::endl;
    return 1;
  }
  // check for "fieldname"
  simdjson::dom::element elem;
  files["fieldname"].tie(elem, error);
  if (error || !elem.is_string())
  {
    std::cout << "Error: Element fieldname in response is empty or no string!" << std::endl;
    return 1;
  }
  if (elem.get<std::string_view>().value() != "")
  {
    std::cout << "Error: Value of fieldname is not \"\", but \""
              << elem.get<std::string_view>().value()
              << "\" instead!" << std::endl;
    return 1;
  }
  // check for "tempfile"
  files["tempfile"].tie(elem, error);
  if (error || !elem.is_string())
  {
    std::cout << "Error: Element tempfile in response is empty or no string!" << std::endl;
    return 1;
  }
  if (elem.get<std::string_view>().value() != content)
  {
    std::cout << "Error: Value of tempfile is not \"" << content << "\", but \""
              << elem.get<std::string_view>().value()
              << "\" instead!" << std::endl;
    return 1;
  }

  std::cout << "Curly can send files via POST." << std::endl;
  return 0;
}
