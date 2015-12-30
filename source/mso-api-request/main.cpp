/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
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

#include <algorithm>
#include <iostream>
#include <string>
#include <unordered_set>
#include "../ReportMetascanOnline.hpp"
#include "../ScannerMetascanOnline.hpp"

const int rcInvalidParameter = 1;
const int rcScanError = 3; //same as in scan-tool

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
            << "                     shall be requested.\n";
}

void showVersion()
{
  std::cout << "mso-api-request, version 0.0.2, 2015-12-31\n";
}

int main(int argc, char ** argv)
{
  //string that will hold the API key
  std::string key = "";
  //resources that will be queried
  std::unordered_set<std::string> resources_report = std::unordered_set<std::string>();

  if ((argc>1) and (argv!=NULL))
  {
    int i=1;
    while (i<argc)
    {
      if (argv[i]!=NULL)
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
          if ((i+1<argc) and (argv[i+1]!=NULL))
          {
            key = std::string(argv[i+1]);
            ++i; //skip next parameter, because it's used as API key already
            std::cout << "API key was set to \"" << key << "\"." << std::endl;
          }
          else
          {
            std::cout << "Error: You have to enter some text after \""
                      << param <<"\"." << std::endl;
            return rcInvalidParameter;
          }
        }//API key
        else if ((param=="--report") or (param=="--resource"))
        {
          //enough parameters?
          if ((i+1<argc) and (argv[i+1]!=NULL))
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
            return rcInvalidParameter;
          }
        }//resource report
        else
        {
          //unknown or wrong parameter
          std::cout << "Invalid parameter given: \"" << param << "\"." << std::endl
                    << "Use --help to get a list of valid parameters.\n";
          return rcInvalidParameter;
        }
      }//parameter exists
      else
      {
        std::cout << "Parameter at index " << i << " is NULL." << std::endl;
        return rcInvalidParameter;
      }
      ++i;//on to next parameter
    }//while
  }//if arguments present

  if (key.empty())
  {
    std::cout << "Error: This program won't work properly without an API key! "
              << "Use --apikey to specify the Metascan Online API key."
              << std::endl;
    return rcInvalidParameter;
  }
  if (resources_report.empty())
  {
    std::cout << "No resources for report retrieval given. Exiting." << std::endl;
    return rcInvalidParameter;
  } //if no resources


  //initialize scanner instance
  ScannerMetascanOnline scanMSO(key);

  //iterate over all resources for report requests
  for(const std::string& i : resources_report)
  {
    ReportMetascanOnline report;
    if (!scanMSO.getReport(i, report))
    {
      std::cout << "Error: Could not retrieve report!" << std::endl;
      return rcScanError;
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
        [](const EngineMetascanOnline& e) { return e.detected;}
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

  std::cout << std::endl << "Not completely implemented yet!" << std::endl;
  return 0;
}
