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
#include "../../../source/metascan/Report.hpp"

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

  scantool::metascan::Report report;
  if (!report.fromJsonString(json))
  {
    std::cerr << "Error: JSON from file " << jsonFile
              << " could not be parsed." << std::endl;
    return 1;
  }

  // Test parsed data.
  if (report.data_id != "ZTE3MDUyN1NrbHhCdDQ4UFdacjFZa0RxRl9HWg")
  {
    std::cerr << "Error: data_id does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_id != "ZTE3MDUyN1NrbHhCdDQ4UFda")
  {
    std::cerr << "Error: file_id does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.display_name != "ar40eng.exe")
  {
    std::cerr << "Error: file_info.display_name does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.file_size != 5455526)
  {
    std::cerr << "Error: file_info.file_size does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.file_type_category != "E")
  {
    std::cerr << "Error: file_info.file_type_category does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.file_type_description != "Generic Win/DOS Executable")
  {
    std::cerr << "Error: file_info.file_type_description does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.file_type_extension != "EXE/DLL/OCX")
  {
    std::cerr << "Error: file_info.file_type_extension does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.md5 != "F3712493976FE1C0E32625DFAAB51DC8")
  {
    std::cerr << "Error: file_info.md5 does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.sha1 != "D03034BCA1960D7927A3C416DF9E861E4EB12610")
  {
    std::cerr << "Error: file_info.sha1 does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.sha256 != "3C1CBD07F1D78336F07A9DA6388AF1E8D631B06DB9D4C1CCB8129CE2C54728E4")
  {
    std::cerr << "Error: file_info.sha256 does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.file_info.upload_timestamp != "2017-05-27T19:33:05.000Z")
  {
    std::cerr << "Error: file_info.upload_timestamp does not match the expected value!" << std::endl;
    return 1;
  }

  if (report.in_queue != 0)
  {
    std::cerr << "Error: in_queue does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.progress_percentage != 100)
  {
    std::cerr << "Error: progress_percentage does not match the expected value!" << std::endl;
    return 1;
  }
  if (!report.rescan_available)
  {
    std::cerr << "Error: rescan_available does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.scan_all_result_a != "Infected")
  {
    std::cerr << "Error: scan_all_result_a does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.scan_all_result_i != 1)
  {
    std::cerr << "Error: scan_all_result_i does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.start_time != "2017-06-09T20:51:31.369Z")
  {
    std::cerr << "Error: start_time does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.top_threat != -1)
  {
    std::cerr << "Error: top_threat does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.total_avs != 40)
  {
    std::cerr << "Error: total_avs does not match the expected value!" << std::endl;
    return 1;
  }
  if (report.total_time != 18125)
  {
    std::cerr << "Error: total_time does not match the expected value!" << std::endl;
    return 1;
  }

  if (report.scan_details.size() != 40)
  {
    std::cerr << "Error: Expected 40 scans, but there are " << report.scan_details.size()
              << " scans instead!" << std::endl;
    return 1;
  }

  // Test some engines.
  {
    const auto it = std::find_if(report.scan_details.begin(), report.scan_details.end(), [](const auto& e) { return e.engine == "ClamAV";});
    if (it == report.scan_details.end())
    {
      std::cerr << "Error: Could not find scan entry for ClamAV!" << std::endl;
      return 1;
    }
    const scantool::metascan::Engine eng = *it;
    if (eng.def_time != "2017-06-09T00:00:00.000Z")
    {
      std::cerr << "Error: ClamAV def_time does not match the expected value!" << std::endl;
      return 1;
    }
    if (!eng.detected)
    {
      std::cerr << "Error: ClamAV detected does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.engine != "ClamAV")
    {
      std::cerr << "Error: ClamAV engine does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.result != "Win.Trojan.Agent-777267")
    {
      std::cerr << "Error: ClamAV result does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.scan_result_i != 1)
    {
      std::cerr << "Error: ClamAV scan_result_i does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.scan_time.count() != 3484)
    {
      std::cerr << "Error: ClamAV scan_time does not match the expected value!" << std::endl;
      return 1;
    }
  }

  {
    const auto it = std::find_if(report.scan_details.begin(), report.scan_details.end(), [](const auto& e) { return e.engine == "Sophos";});
    if (it == report.scan_details.end())
    {
      std::cerr << "Error: Could not find scan entry for Sophos!" << std::endl;
      return 1;
    }
    const scantool::metascan::Engine eng = *it;
    if (eng.def_time != "2017-06-09T00:00:00.000Z")
    {
      std::cerr << "Error: Sophos def_time does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.detected)
    {
      std::cerr << "Error: Sophos detected does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.engine != "Sophos")
    {
      std::cerr << "Error: Sophos engine does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.result != "")
    {
      std::cerr << "Error: Sophos result does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.scan_result_i != 0)
    {
      std::cerr << "Error: Sophos scan_result_i does not match the expected value!" << std::endl;
      return 1;
    }
    if (eng.scan_time.count() != 2359)
    {
      std::cerr << "Error: Sophos scan_time does not match the expected value!" << std::endl;
      return 1;
    }
  }

  // OK
  std::cout << "Test was successful." << std::endl;
  return 0;
}
