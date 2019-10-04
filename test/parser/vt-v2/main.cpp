/*
 -------------------------------------------------------------------------------
    This file is part of the test suite for scan-tool.
    Copyright (C) 2019 Dirk Stolle

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
#include <fstream>
#include <iostream>
#include "../../../libstriezel/filesystem/file.hpp"
#include "../../../source/virustotal/ReportV2.hpp"

int main(int argc, char** argv)
{
  if ((argc < 2) || (argv == nullptr) || (argv[1] == nullptr))
  {
    std::cout << "Error: This program expects a JSON file name as "
              << "its first argument." << std::endl;
    return 1;
  }
  const std::string jsonFile = std::string(argv[1]);
  if (!libstriezel::filesystem::file::exists(jsonFile))
  {
    std::cout << "Error: The specified JSON file " << jsonFile
              << " does not exist!" << std::endl;
    return 1;
  }

  std::string json;
  {
    // try to read JSON data from given file
    std::ifstream jsonStream(jsonFile, std::ios_base::in | std::ios_base::binary);
    if (!jsonStream.good())
    {
      std::cerr << "Error: JSON file could not be opened." << std::endl;
      return 1;
    }
    std::string temp = "";
    while (!jsonStream.eof() && std::getline(jsonStream, temp, '\0'))
    {
      json.append(temp);
    }
    // File should be read until EOF, but failbit and badbit should not be set.
    if (!jsonStream.eof() || jsonStream.bad() || jsonStream.fail())
    {
      jsonStream.close();
      std::cerr << "Error: JSON file could not be read." << std::endl;
      return 1;
    }
    jsonStream.close();
  }

  scantool::virustotal::ReportV2 report;
  if (!report.fromJsonString(json))
  {
    std::cerr << "Error: JSON from file " << jsonFile
              << " could not be parsed." << std::endl;
    return 1;
  }

  // Test parsed data.
  if (report.md5 != "f15f72d615a81141f5fed876e9a11fb0")
  {
    std::cerr << "Error: md5 does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.permalink != "https://www.virustotal.com/file/8d44a0cce1e229179fb1369842750d537606793bcb63686ce25f9e9c13885295/analysis/1439832650/")
  {
    std::cerr << "Error: permalink does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.positives != 33)
  {
    std::cerr << "Error: positives does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.resource != "8d44a0cce1e229179fb1369842750d537606793bcb63686ce25f9e9c13885295")
  {
    std::cerr << "Error: resource does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.response_code != 1)
  {
    std::cerr << "Error: response_code does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.scan_id != "8d44a0cce1e229179fb1369842750d537606793bcb63686ce25f9e9c13885295-1439832650")
  {
    std::cerr << "Error: scan_id does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.sha1 != "3d7c73d9fbe08855f3bab77ecde02d58bcae0a40")
  {
    std::cerr << "Error: sha1 does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.sha256 != "8d44a0cce1e229179fb1369842750d537606793bcb63686ce25f9e9c13885295")
  {
    std::cerr << "Error: sha256 does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.total != 56)
  {
    std::cerr << "Error: total does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.verbose_msg != "Scan finished, information embedded")
  {
    std::cerr << "Error: verbose_msg does not match the expected value!" << std::endl;
    return 1;
  }

  if (report.scans.size() != 56)
  {
    std::cerr << "Error: Expected 56 scans, but there are " << report.scans.size()
              << " scans instead!" << std::endl;
    return 1;
  }

  // Test some engines.
  {
    const auto it = std::find_if(report.scans.begin(), report.scans.end(), [](const auto& e) { return e->engine == "ClamAV";});
    if (it == report.scans.end())
    {
      std::cerr << "Error: Could not find scan entry for ClamAV!" << std::endl;
      return 1;
    }
    const scantool::virustotal::EngineV2* ptr = dynamic_cast<scantool::virustotal::EngineV2*> (it->get());
    if (ptr->detected)
    {
      std::cerr << "Error: ClamAV detected does not match the expected value!" << std::endl;
      return 1;
    }
    if (ptr->result != "")
    {
      std::cerr << "Error: ClamAV result does not match the expected value!" << std::endl;
      return 1;
    }
    if (ptr->update != "20150817")
    {
      std::cerr << "Error: ClamAV update does not match the expected value!" << std::endl;
      return 1;
    }
    if (ptr->version != "0.98.5.0")
    {
      std::cerr << "Error: ClamAV version does not match the expected value!" << std::endl;
      return 1;
    }
  }

  {
    const auto it = std::find_if(report.scans.begin(), report.scans.end(), [](const auto& e) { return e->engine == "F-Secure";});
    if (it == report.scans.end())
    {
      std::cerr << "Error: Could not find scan entry for F-Secure!" << std::endl;
      return 1;
    }
    const scantool::virustotal::EngineV2* ptr = dynamic_cast<scantool::virustotal::EngineV2*> (it->get());
    if (!(ptr->detected))
    {
      std::cerr << "Error: F-Secure detected does not match the expected value!" << std::endl;
      return 1;
    }
    if (ptr->result != "Trojan.Generic.13198670")
    {
      std::cerr << "Error: F-Secure result does not match the expected value!" << std::endl;
      return 1;
    }
    if (ptr->update != "20150817")
    {
      std::cerr << "Error: F-Secure update does not match the expected value!" << std::endl;
      return 1;
    }
    if (ptr->version != "11.0.19100.45")
    {
      std::cerr << "Error: F-Secure version does not match the expected value!" << std::endl;
      return 1;
    }
  }

  // OK
  std::cout << "Test was successful." << std::endl;
  return 0;
}
