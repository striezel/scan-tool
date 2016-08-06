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

#include <algorithm>
#include <iostream>
#include "../../../source/Curly.hpp"

int main()
{
  const auto vInfo = Curly::curlVersion();
  std::cout << "cURL: " << vInfo.cURL << std::endl
            << "Supported protocols (" << vInfo.protocols.size() << " in total):" << std::endl;
  for (auto proto : vInfo.protocols)
  {
    std::cout << "    " << proto << std::endl;
  }
  //We do not want empty protocol list here.
  if (vInfo.protocols.empty())
  {
    std::cout << "Error: Could not get the supported protocols!" << std::endl;
    return 1;
  }
  //HTTP support would be nice, although we are only using HTTPS.
  if (std::find(vInfo.protocols.begin(), vInfo.protocols.end(), "http") != vInfo.protocols.end())
  {
    std::cout << "HTTP is among the supported protocols." << std::endl
              << "  Currently, HTTP is not needed, but it's nice to have." << std::endl;
  }
  else
  {
    std::cout << "Error: HTTP is NOT among the supported protocols." << std::endl
              << "  Currently, HTTP is not needed, but it would be nice to have." << std::endl;
    return 1;
  }
  //scan-tool needs at least HTTPS support.
  if (std::find(vInfo.protocols.begin(), vInfo.protocols.end(), "https") != vInfo.protocols.end())
  {
    std::cout << "HTTPS is among the supported protocols." << std::endl;
  }
  else
  {
    std::cout << "Error: HTTPS is NOT among the supported protocols." << std::endl;
    return 1;
  }
  //All is fine here.
  std::cout << "=> Curly's supported protocols are sufficient for scan-tool." << std::endl;
  return 0;
}
