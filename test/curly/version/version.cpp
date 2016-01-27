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
#include "../../../source/Curly.hpp"

int main()
{
  const auto vInfo = Curly::curlVersion();
  std::cout << "cURL: " << vInfo.cURL << std::endl
            << "SSL: " << (vInfo.ssl.empty() ? "no SSL support" : vInfo.ssl) << std::endl
            << "zlib: " << (vInfo.libz.empty() ? "no zlib support" : vInfo.libz) << std::endl;
  std::cout << "Supported protocols (" << vInfo.protocols.size() << " in total):" << std::endl;
  for (auto proto : vInfo.protocols)
  {
    std::cout << "    " << proto << std::endl;
  }
  std::cout << "Ares: " << (vInfo.ares.empty() ? "(empty)" : vInfo.ares) << std::endl
            << "IDN: " << (vInfo.idn.empty() ? "no IDN support" : vInfo.idn) << std::endl
            << "libssh: " << (vInfo.ssh.empty() ? "no libssh support" : vInfo.ssh) << std::endl;
  //minimal presence check for some info
  if (vInfo.cURL.empty())
  {
    std::cout << "Error: cURL version information string is empty!" << std::endl;
    return 1;
  }
  if (vInfo.protocols.empty())
  {
    std::cout << "Error: Could not get the supported protocols!" << std::endl;
    return 1;
  }
  //All is fine here.
  std::cout << "Curly's version information is fine." << std::endl;
  return 0;
}
