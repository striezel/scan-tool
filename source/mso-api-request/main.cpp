/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
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
#include <string>
#include <unordered_set>
#include "../../libthoro/filesystem/file.hpp"
#include "../metascan/Report.hpp"
#include "../metascan/Scanner.hpp"
#include "../ReturnCodes.hpp"

void showHelp()
{
  std::cout << "\nmso-api-request [options ...]\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version        - displays the version of the program and quits\n"
            << "  -v               - same as --version\n"
            << "  --apikey KEY     - sets the API key for Metascan Online\n"
            << "  --report ID      - request the report with the given ID from Metascan\n"
            << "                     Online. Can occur multiple times, if more than one report\n"
            << "                     shall be requested.\n"
            << "  --rescan FILE_ID - request rescan of a file with the given ID that was\n"
            << "                     uploaded earlier. The file ID usually is a 32 digit hex\n"
            << "                     number. This parameter can occur multiple times.\n"
            << "  --re FILE_ID     - same as --rescan FILE_ID\n"
            << "  -- file FILE     - request to scan the file FILE by Metascan Online.\n"
            << "                     FILE must be a local file that can be read by the user\n"
            << "                     that runs this program. The program will print the scan\n"
            << "                     data of the file to the standard output. Note that it can\n"
            << "                     take some time for Metascan Online to scan this file,\n"
            << "                     depending on the current load and number of queued scans.\n"
            << "                     Can be repeated multiple times, if you want to scan\n"
            << "                     several files.\n"
            << "  --scan FILE      - same as --file FILE\n"
            << "  --certfile FILE  - use the certificates in FILE to verify peers with.\n";
}

void showVersion()
{
  std::cout << "mso-api-request, version 0.0.7, 2016-02-21\n";
}

int main(int argc, char ** argv)
{
  //path for custom certificate file
  std::string certificateFile = "";
  //string that will hold the API key
  std::string key = "";
  //resources that will be queried
  std::unordered_set<std::string> resources_report = std::unordered_set<std::string>();
  //file IDs for which a rescan will be requested
  std::unordered_set<std::string> file_IDs_rescan = std::unordered_set<std::string>();
  //files for which an upload and scan is requested
  std::unordered_set<std::string> files_scan = std::unordered_set<std::string>();

  if ((argc > 1) and (argv != nullptr))
  {
    int i=1;
    while (i<argc)
    {
      if (argv[i] != nullptr)
      {
        const std::string param = std::string(argv[i]);
        //help parameter
        if ((param=="--help") or (param=="-?") or (param=="/?"))
        {
          showHelp();
          return 0;
        }//help
        //version information requested?
        else if ((param=="--version") or (param=="-v"))
        {
          showVersion();
          return 0;
        } //version
        else if ((param=="--key") or (param=="--apikey"))
        {
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            key = std::string(argv[i+1]);
            ++i; //skip next parameter, because it's used as API key already
            std::cout << "API key was set to \"" << key << "\"." << std::endl;
          }
          else
          {
            std::cout << "Error: You have to enter some text after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        }//API key
        else if ((param=="--report") or (param=="--resource"))
        {
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string next_resource = std::string(argv[i+1]);
            ++i; //skip next parameter, because it's used as resource identifier already
            if (resources_report.find(next_resource) == resources_report.end())
            {
              std::cout << "Adding resource " << next_resource
                        << " to list of report requests." << std::endl;
            }
            resources_report.insert(next_resource);
          }
          else
          {
            std::cout << "Error: You have to enter a resource ID after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        }//resource report
        else if ((param=="--re") or (param=="--rescan"))
        {
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string next_file_ID = std::string(argv[i+1]);
            ++i; //Skip next parameter, because it's used as file identifier already
            if (file_IDs_rescan.find(next_file_ID) == file_IDs_rescan.end())
            {
              std::cout << "Adding file ID " << next_file_ID
                        << " to list of rescan requests." << std::endl;
            }
            file_IDs_rescan.insert(next_file_ID);
          }
          else
          {
            std::cout << "Error: You have to enter a file ID after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        }//rescan
        else if ((param=="--file") or (param=="--scan"))
        {
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string next_file = std::string(argv[i+1]);
            ++i; //Skip next parameter, because it's used as filename already.
            if (files_scan.find(next_file) == files_scan.end())
            {
              std::cout << "Adding file " << next_file
                        << " to list of scan files." << std::endl;
            }
            files_scan.insert(next_file);
          }
          else
          {
            std::cout << "Error: You have to enter a file name after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        }//scan file
        else if ((param=="--certfile") or (param=="--certs") or (param=="--cacert"))
        {
          //only one file is permitted
          if (!certificateFile.empty())
          {
            std::cout << "Error: You must not specify " << param
                      << " more than once!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string customCertFile = std::string(argv[i+1]);
            ++i; //Skip next parameter, because it's used as certificate file already.
            if (!libthoro::filesystem::file::exists(customCertFile))
            {
              std::cout << "Error: File " << customCertFile << " does not exist!"
                        << std::endl;
              return scantool::rcFileError;
            }
            //set certificate file name
            certificateFile = customCertFile;
            std::cout << "Using custom certificate file " << customCertFile
                      << " to verify peers." << std::endl;
          } //if
          else
          {
            std::cout << "Error: You have to enter a file name after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          } //else
        } //certificate file
        else
        {
          //unknown or wrong parameter
          std::cout << "Invalid parameter given: \"" << param << "\"." << std::endl
                    << "Use --help to get a list of valid parameters.\n";
          return scantool::rcInvalidParameter;
        }
      }//parameter exists
      else
      {
        std::cout << "Parameter at index " << i << " is null pointer." << std::endl;
        return scantool::rcInvalidParameter;
      }
      ++i;//on to next parameter
    }//while
  }//if arguments present

  if (key.empty())
  {
    std::cout << "Error: This program won't work properly without an API key! "
              << "Use --apikey to specify the Metascan Online API key."
              << std::endl;
    return scantool::rcInvalidParameter;
  }
  if (resources_report.empty() && file_IDs_rescan.empty() && files_scan.empty())
  {
    std::cout << "No resources for report retrieval, file IDs for rescan or "
              << "files to scan were given. Exiting." << std::endl;
    return scantool::rcInvalidParameter;
  } //if no resources

  //initialize scanner instance
  scantool::metascan::Scanner scanMSO(key, true, false, certificateFile);

  //iterate over all resources for rescan requests
  for(const std::string& i : file_IDs_rescan)
  {
    scantool::metascan::Scanner::ScanData scan_data;
    if (!scanMSO.rescan(i, scan_data))
    {
      std::cout << "Error: Could not initiate rescan for file ID \""
                << i << "\"!" << std::endl;
      return scantool::rcScanError;
    }
    std::cout << "Rescan for \"" << i << "\" initiated. "
              << "Data ID for later retrieval is " << scan_data.data_id << "."
              << " Address for progress requests is " << scan_data.rest_ip
              << "."  << std::endl;
  } //for (range-based)

  //iterate over all resources for report requests
  for(const std::string& i : resources_report)
  {
    scantool::metascan::Report report;
    if (!scanMSO.getReport(i, report))
    {
      std::cout << "Error: Could not retrieve report!" << std::endl;
      return scantool::rcScanError;
    }
    std::cout << std::endl;
    std::cout << "Report data for " << i << ":" << std::endl
              << "  file_id: " << report.file_id << std::endl
              << "  data_id: " << report.data_id << std::endl
              << "  start_time: " << report.start_time << std::endl
              << "  scan engines: " << report.total_avs << std::endl
              //<< "  engines that detected a threat: " << report.positives << std::endl
              << "  scan_all_result_a: " << report.scan_all_result_a << std::endl
              << "  SHA256: " << report.file_info.sha256 << std::endl;
    const unsigned int detection_count = std::count_if(
        report.scan_details.cbegin(), report.scan_details.cend(),
        // lambda expression to count all entries where detected == true
        [](const scantool::metascan::Engine& e) { return e.detected;}
                                                );
    if (detection_count > 0)
    {
      std::cout << "  INFECTED: " << detection_count << " engine(s) found a threat!" << std::endl;
      for (const auto & e : report.scan_details)
      {
        if (e.detected)
        {
          std::cout << "    " << e.engine << " found " << e.result << std::endl;
        } //if engine detected threat
      } //for (range-based loop over all engines in report)
    } //if at least one engine found a threat
    else
      std::cout << "  No threat was found for this resource." << std::endl;
  } //for (range-based) over all resources

  //iterate over all files for scan requests
  for(const std::string& i : files_scan)
  {
    scantool::metascan::Scanner::ScanData scan_data;
    if (!scanMSO.scan(i, scan_data))
    {
      std::cout << "Error: Could not initiate scan for \""
                << i << "\"!" << std::endl;
      return scantool::rcScanError;
    }
    std::cout << "Scan for \"" << i << "\" initiated. "
              << "Data ID for later retrieval is " << scan_data.data_id << "."
              << " Address for progress requests is " << scan_data.rest_ip
              << "."  << std::endl;
  } //for (range-based)

  return 0;
}
