/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2019, 2021  Dirk Stolle

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
#include <string>
#include <thread>
#include <unordered_set>
#include "../../libstriezel/filesystem/file.hpp"
#include "../Configuration.hpp"
#include "../Curly.hpp"
#include "../ReturnCodes.hpp"
#include "../virustotal/ScannerV2.hpp"


void showHelp()
{
  std::cout << "\nvt-api-request [options ...]\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version        - displays the version of the program and quits\n"
            << "  -v               - same as --version\n"
            << "  --apikey KEY     - sets the API key for VirusTotal\n"
            << "  --keyfile FILE   - read the API key for VirusTotal from the file FILE.\n"
            << "                     This way the API key will not appear in the process list\n"
            << "                     and/or shell history. However, the file name can still be\n"
            << "                     seen, so proper file permissions should be set.\n"
            << "  --report ID      - request the report with the given ID from VirusTotal.\n"
            << "                     Can occur multiple times, if more than one report shall\n"
            << "                     be requested.\n"
            << "                     The ID is either a SHA256 hash of a file or a scan ID\n"
            << "                     that was returned by an earlier request to the API.\n"
            << "  --resource ID    - same as --report ID\n"
            << "  --rescan ID      - request rescan of a resource with the given ID that was\n"
            << "                     uploaded earlier. The ID is a SHA256 hash of the uploaded\n"
            << "                     file. This parameter can occur multiple times.\n"
            << "  --re ID          - same as --rescan ID\n"
            << "  -- file FILE     - request to scan the file FILE by VirusTotal. FILE must be\n"
            << "                     a local file that can be read by the user that runs this\n"
            << "                     program. The program will print the scan ID of the file\n"
            << "                     to the standard output. Note that it can take several\n"
            << "                     hours for VirusTotal to scan this file, depending on the\n"
            << "                     current load and number of queued scan requests.\n"
            << "                     Can be repeated multiple times, if you want to scan\n"
            << "                     several files.\n"
            << "  --scan FILE      - same as --file FILE\n"
            << "  --initial-wait   - wait a few seconds before the first request, so that the\n"
            << "                     API rate limit will not be exceeded, if this program was\n"
            << "                     invoked more than once in a row.\n"
            << "  --wait           - same as --initial-wait\n" ;
}

void showVersion()
{
  std::cout << "vt-api-request, version 1.0.5, 2021-11-18\n";
}

int main(int argc, char ** argv)
{
  //string that will hold the API key
  std::string key = "";
  //whether to wait a while before the first request
  bool initial_wait = false;
  //resources that will be queried
  std::unordered_set<std::string> resources_report = std::unordered_set<std::string>();
  //resources for which a rescan will be requested
  std::unordered_set<std::string> resources_rescan = std::unordered_set<std::string>();
  //files for which an upload and scan
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
            #ifdef SCAN_TOOL_DEBUG
            std::cout << "API key was set to \"" << key << "\"." << std::endl;
            #endif
          }
          else
          {
            std::cout << "Error: You have to enter some text after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        }//API key
        else if (param=="--keyfile")
        {
          //only one key required
          if (!key.empty())
          {
            std::cout << "Error: API key was already specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string keyfile = std::string(argv[i+1]);
            if (!libstriezel::filesystem::file::exists(keyfile))
            {
              std::cout << "Error: The specified key file " << keyfile
                        << " does not exist!" << std::endl;
              /* Technically it's a file error, but let's return "invalid
                 parameter" here, because the file name parameter is wrong/
                 invalid.
              */
              return scantool::rcInvalidParameter;
            } //if file does not exist
            Configuration conf;
            if (!conf.loadFromFile(keyfile))
            {
              std::cout << "Error: Could not load key from file " << keyfile
                        << "!" << std::endl;
              return scantool::rcFileError;
            }
            if (conf.apikey().empty())
            {
              std::cout << "Error: Key file " << keyfile << " does not contain"
                        << " an API key!" << std::endl;
              return scantool::rcFileError;
            }
            key = conf.apikey();
            ++i; //Skip next parameter, because it's used as key file already.
            #ifdef SCAN_TOOL_DEBUG
            std::cout << "API key was set to \"" << key << "\"." << std::endl;
            #endif
          }
          else
          {
            std::cout << "Error: You have to enter a file name after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //API key from file
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
            const std::string next_resource = std::string(argv[i+1]);
            ++i; //Skip next parameter, because it's used as resource identifier already
            if (resources_rescan.find(next_resource) == resources_rescan.end())
            {
              std::cout << "Adding resource " << next_resource
                        << " to list of rescan requests." << std::endl;
            }
            resources_rescan.insert(next_resource);
          }
          else
          {
            std::cout << "Error: You have to enter a resource ID after \""
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
        else if ((param=="--initial-wait") or (param=="--wait"))
        {
          //Was the parameter already set?
          if (initial_wait)
          {
            std::cout << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          initial_wait = true;
        } //initial_wait
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
              << "Use --apikey to specify the VirusTotal API key." << std::endl;
    return scantool::rcInvalidParameter;
  }
  if (resources_report.empty() && resources_rescan.empty() && files_scan.empty())
  {
    std::cout << "No resources for report retrieval, rescan or file scan were given. Exiting." << std::endl;
    return scantool::rcInvalidParameter;
  } //if not resources

  scantool::virustotal::ScannerV2 scanVT(key);

  //initial wait to avoid exceeding the rate limit
  if (initial_wait)
  {
    const auto duration = scanVT.timeBetweenConsecutiveScanRequests();
    std::cout << "Waiting " << std::chrono::duration_cast<std::chrono::milliseconds>(duration).count()
                  << " millisecond(s) for time limit to expire as requested..." << std::endl;
    std::this_thread::sleep_for(duration);
  }

  //iterate over all resources for rescan requests
  for(const std::string& i : resources_rescan)
  {
    std::string scan_id = "";
    if (!scanVT.rescan(i, scan_id))
    {
      std::cout << "Error: Could not initiate rescan for \""
                << i << "\"!" << std::endl;
      return scantool::rcScanError;
    }
    std::cout << "Rescan for \"" << i << "\" initiated. "
              << "Scan-ID for later retrieval is " << scan_id << "." << std::endl;
  } //for (range-based)

  //iterate over all resources for report requests
  for(const std::string& i : resources_report)
  {
    scantool::virustotal::ScannerV2::Report report;
    if (!scanVT.getReport(i, report, false, std::string()))
    {
      std::cout << "Error: Could not retrieve report!" << std::endl;
      return scantool::rcScanError;
    }
    std::cout << std::endl;
    std::cout << "Report data for " << i << ":" << std::endl
              << "  response code: " << report.response_code << std::endl
              << "  verbose message: " << report.verbose_msg << std::endl
              << "  resource: " << report.resource << std::endl
              << "  scan_id: " << report.scan_id << std::endl
              << "  scan_date: " << report.scan_date << std::endl
              << "  scan engines: " << report.total << std::endl
              << "  engines that detected a threat: " << report.positives << std::endl
              << "  permanent link: " << report.permalink << std::endl
              << "  SHA256: " << report.sha256 << std::endl;
    for (const auto& eng : report.scans)
    {
      const auto eng2 = static_cast<scantool::virustotal::EngineV2*>(eng.get());
      std::cout << "    Engine " << eng->engine << " (version " << eng2->version
                << " of " << eng2->update << ")";
      if (eng->detected)
        std::cout << " detected " << eng->result << std::endl;
      else
        std::cout << " found nothing." << std::endl;
    } //for (inner, range-based)
  } //for (range-based)

  //iterate over all files for scan requests
  for(const std::string& i : files_scan)
  {
    std::string scan_id = "";
    if (!scanVT.scan(i, scan_id))
    {
      std::cout << "Error: Could not initiate scan for \""
                << i << "\"!" << std::endl;
      return scantool::rcScanError;
    }
    std::cout << "Scan for " << i << " initiated. "
              << "Scan-ID for later retrieval is " << scan_id << "." << std::endl;
  } //for (range-based)

  return 0;
}
