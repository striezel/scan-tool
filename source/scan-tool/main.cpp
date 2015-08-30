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

#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <thread>
#include <unordered_set>
#include "../Curly.hpp"
#include "../ScannerVirusTotalV2.hpp"
#include "../../libthoro/common/StringUtils.h"
#include "../../libthoro/filesystem/FileFunctions.hpp"
#include "../../libthoro/hash/sha256/FileSourceUtility.hpp"
#include "../../libthoro/hash/sha256/sha256.hpp"

//return codes
const int rcInvalidParameter = 1;
const int rcFileError = 2;
const int rcScanError = 3;

void showHelp()
{
  std::cout << "\nscan-tool [FILE ...]\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version        - displays the version of the program and quits\n"
            << "  -v               - same as --version\n"
            << "  --apikey KEY     - sets the API key for VirusTotal\n"
            << "  --silent         - produce less text on the standard output\n"
            << "  --maybe N        - sets the limit for false positives to N. N must be an\n"
            << "                     unsigned integer value. Default is 3.\n"
            << "  FILE             - file that shall be scanned. Can be repeated multiple\n"
            << "                     times, if you want to scan several files.\n"
            << " --list FILE       - read the files which shall be scanned from the file FILE,\n"
            << "                     one per line.\n"
            << " --files FILE      - same as --list FILE\n";
}

void showVersion()
{
  std::cout << "scan-tool, version 0.13, 2015-08-31\n";
}

int main(int argc, char ** argv)
{
  //string that will hold the API key
  std::string key = "";
  //whether output will be reduced
  bool silent = false;
  // limit for "maybe infected"; higher count means infected
  int maybeLimit = 0;
  //files that will be checked
  std::unordered_set<std::string> files_scan = std::unordered_set<std::string>();

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
            ++i; //Skip next parameter, because it's used as API key already.
            #ifdef SCAN_TOOL_DEBUG
            if (!silent)
              std::cout << "API key was set to \"" << key << "\"." << std::endl;
            #endif
          }
          else
          {
            std::cout << "Error: You have to enter some text after \""
                      << param <<"\"." << std::endl;
            return rcInvalidParameter;
          }
        } //API key
        else if ((param=="--silent") or (param=="-s"))
        {
          //Has the silent parameter already been set?
          if (silent)
          {
            std::cout << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return rcInvalidParameter;
          }
          silent = true;
        } //silent
        else if ((param=="--maybe") or (param=="--limit"))
        {
          //enough parameters?
          if ((i+1<argc) and (argv[i+1]!=NULL))
          {
            const std::string integer = std::string(argv[i+1]);
            int limit = -1;
            if (!stringToInt(integer, limit))
            {
              std::cout << "Error: \"" << integer << "\" is not an integer!" << std::endl;
              return rcInvalidParameter;
            }
            if (limit < 0)
            {
              std::cout << "Error: " << limit << " is negative, but only"
                        << " non-negative values are allowed here." << std::endl;
              return rcInvalidParameter;
            }
            maybeLimit = limit;
            ++i; //Skip next parameter, because it's used as limit already.
          }
          else
          {
            std::cout << "Error: You have to enter an integer value after \""
                      << param <<"\"." << std::endl;
            return rcInvalidParameter;
          }
        } //"maybe" limit
        else if ((param=="--files") or (param=="--list"))
        {
          //enough parameters?
          if ((i+1<argc) and (argv[i+1]!=NULL))
          {
            const std::string listFile = std::string(argv[i+1]);
            ++i; //Skip next parameter, because it's used as list file already.
            if (!libthoro::filesystem::File::exists(listFile))
            {
              std::cout << "Error: File " << listFile << " does not exist!"
                        << std::endl;
              return rcFileError;
            }
            //open file and read file names
            std::ifstream inFile;
            inFile.open(listFile, std::ios_base::in | std::ios_base::binary);
            if (!inFile.good() || !inFile.is_open())
            {
              std::cout << "Error: Could not open file " << listFile << "!"
                        << std::endl;
              return rcFileError;
            }
            std::string nextFile;
            while (!inFile.eof())
            {
              std::getline(inFile, nextFile, '\n');
              if (!nextFile.empty())
              {
                if (libthoro::filesystem::File::exists(nextFile))
                {
                  #ifdef SCAN_TOOL_DEBUG
                  std::cout << "Info: Adding " << nextFile << " to list of files for scan." << std::endl;
                  #endif // SCAN_TOOL_DEBUG
                  files_scan.insert(nextFile);
                } //if
                else
                {
                  std::cout << "Warning: File " << nextFile << " does not exist, skipping it."
                            << std::endl;
                }
              } //if string not empty
            } //while
            inFile.close();
          } //if
          else
          {
            std::cout << "Error: You have to enter a file name after \""
                      << param <<"\"." << std::endl;
            return rcInvalidParameter;
          } //else
        } //list of files
        //file for scan
        else if (libthoro::filesystem::File::exists(param))
        {
          files_scan.insert(param);
        } //file
        else
        {
          //unknown or wrong parameter
          std::cout << "Invalid parameter given: \"" << param << "\"." << std::endl
                    << "Use --help to get a list of valid parameters.\n" << std::endl;
          return rcInvalidParameter;
        } //if unknown parameter
      } //if parameter exists
      else
      {
        std::cout << "Parameter at index " << i << " is NULL." << std::endl;
        return rcInvalidParameter;
      }
      ++i;//on to next parameter
    } //while
  } //if arguments present

  if (key.empty())
  {
    std::cout << "Error: This program won't work properly without an API key! "
              << "Use --apikey to specifiy the VirusTotal API key." << std::endl;
    return rcInvalidParameter;
  }
  if (files_scan.empty())
  {
    std::cout << "No file scans requested, stopping here." << std::endl;
    return 0;
  } //if no requests

  if (maybeLimit <= 0)
    maybeLimit = 3;

  //create scanner: pass API key, honour time limits, set silent mode
  ScannerVirusTotalV2 scanVT(key, true, silent);

  //maps sha256 hashes to corresponding report; key = SHA256 hash, value = scan report
  std::map<std::string, ScannerVirusTotalV2::Report> mapHashToReport;
  //maps filename to hash; key = file name, value = SHA256 hash
  std::map<std::string, std::string> mapFileToHash;
  //list of queued scan requests; key = scan_id, value = file name
  std::unordered_map<std::string, std::string> queued_scans = std::unordered_map<std::string, std::string>();
  //time when last scan was queued
  std::chrono::steady_clock::time_point lastQueuedScanTime = std::chrono::steady_clock::now() - std::chrono::hours(24);

  //iterate over all files for scan requests
  for(const std::string& i : files_scan)
  {
    const SHA256::MessageDigest fileHash = SHA256::computeFromFile(i);
    if (fileHash.isNull())
    {
      std::cout << "Error: Could not determine SHA256 hash of " << i
                << "!" << std::endl;
      return rcFileError;
    } //if no hash
    const std::string hashString = fileHash.toHexString();
    ScannerVirusTotalV2::Report report;
    if (scanVT.getReport(hashString, report))
    {
      if (report.successfulRetrieval())
      {
        //got report
        if (report.positives == 0)
        {
          if (!silent)
            std::cout << i << " OK" << std::endl;
        }
        else if (report.positives <= maybeLimit)
        {
          if (!silent)
            std::clog << i << " might be infected, got " << report.positives
                      << " positives." << std::endl;
          //add file to list of infected files
          mapFileToHash[i] = hashString;
          mapHashToReport[hashString] = report;
        }
        else if (report.positives > maybeLimit)
        {
          if (!silent)
            std::clog << i << " is INFECTED, got " << report.positives
                      << " positives." << std::endl;
          //add file to list of infected files
          mapFileToHash[i] = hashString;
          mapHashToReport[hashString] = report;
        }
      } //if file was in report database
      else if (report.notFound())
      {
        //no data present for file
        const int64_t fileSize = libthoro::filesystem::File::getSize64(i);
        if ((fileSize <= scanVT.maxScanSize()) && (fileSize >= 0))
        {
          std::string scan_id = "";
          if (!scanVT.scan(i, scan_id))
          {
            std::cerr << "Error: Could not submit file " << i << " for scanning."
                      << std::endl;
            return rcScanError;
          }
          //remember time of last scan request
          lastQueuedScanTime = std::chrono::steady_clock::now();
          //add scan ID to list of queued scans for later retrieval
          queued_scans[scan_id] = i;
          if (!silent)
            std::clog << "Info: File " << i << " was queued for scan. Scan ID is "
                      << scan_id << "." << std::endl;
        } //if file size is below limit
        else
        {
          //File is too large.
          std::cout << "Warning: File " << i << " exceeds maximum file size "
                    << "for scan! File will be skipped." << std::endl;
        }
      } //else
      else
      {
        //unexpected response code
        std::cerr << "Error: Got unexpected response code ("<<report.response_code
                  << ") for report of file " << i << "." << std::endl;
        return rcScanError;
      }
    }
    else
    {
      if (!silent)
        std::clog << "Warning: Could not get report for file " << i << "!" << std::endl;
    }
  } //for (range-based)

  //try to retrieve queued scans
  if (!queued_scans.empty())
  {
    const auto duration = std::chrono::steady_clock::now() - lastQueuedScanTime;
    if (duration < std::chrono::seconds(60))
    {
      if (!silent)
        std::cout << "Giving VirusTotal some extra seconds to finish queued scans."
                  << std::endl;
      // Wait until 60 seconds since last queued scan are expired.
      std::this_thread::sleep_for(std::chrono::seconds(60) - duration);
    } //if not enough time elapsed

    auto qsIter = queued_scans.begin();
    while (qsIter != queued_scans.end())
    {
      const std::string& scan_id = qsIter->first;
      const std::string& filename = qsIter->second;
      ScannerVirusTotalV2::Report report;
      if (scanVT.getReport(scan_id, report))
      {
        if (report.successfulRetrieval())
        {
          //got report
          if (report.positives == 0)
          {
            if (!silent)
              std::cout << filename << " OK" << std::endl;
          }
          else if (report.positives <= maybeLimit)
          {
            if (!silent)
              std::clog << filename << " might be infected, got " << report.positives
                        << " positives." << std::endl;
            //if hash is not given, recalculate it
            if (report.sha256.empty())
            {
              report.sha256 = SHA256::computeFromFile(filename).toHexString();
            } //if hash is not present
            //add file to list of infected files
            mapFileToHash[filename] = report.sha256;
            mapHashToReport[report.sha256] = report;
          }
          else if (report.positives > maybeLimit)
          {
            if (!silent)
              std::clog << filename << " is INFECTED, got " << report.positives
                        << " positives." << std::endl;
            //add file to list of infected files
            mapFileToHash[filename] = report.sha256;
            mapHashToReport[report.sha256] = report;
          } //else
        } //if file was in report database
        else if (report.stillInQueue())
        {
          /* Response code -2 means that this stuff is still queued for
             analysis. Most likely any of the following items will still be
             queued, too, so we break out of the for loop here.
          */
          break;
        }
        else
        {
          std::cerr << "Error: Got unexpected response code (" << report.response_code
                    << ") from API. No further report retrieval of queued scans." << std::endl;
          break;
        } //else
        queued_scans.erase(qsIter);
        qsIter = queued_scans.begin();
      } //if report could be retrieved
      else
      {
        if (!silent)
          std::clog << "Warning: Could not get queued scan report for scan ID "
                    << scan_id << " / file " << filename << "!" << std::endl;
        ++qsIter;
      } //else
    } //while
  } //if some scans are/were queued

  //list possibly infected files
  if (!mapFileToHash.empty())
  {
    std::clog << "Possibly infected files: " << mapFileToHash.size() << std::endl;
    for (const auto& i : mapFileToHash)
    {
      std::clog << i.first << " may be infected!" << std::endl;
      const ScannerVirusTotalV2::Report& repVT = mapHashToReport[i.second];
      std::clog << repVT.positives << " out of " << repVT.total
                << " scanners detected a threat";
      if (!repVT.scan_date.empty())
        std::clog << " (date: " << repVT.scan_date << ")";
      std::clog << "." << std::endl;
      for (const auto& engine : repVT.scans)
      {
        if (engine->detected)
          std::clog << "    " << engine->engine << " detected " << engine->result << std::endl;
      } //for engine
      std::clog << std::endl;
    } //for i
  } //if infected files exist in map
  else
  {
    std::cout << "All of the given files seem to be OK." << std::endl;
  }

  //list files which are queued for scan but could not be scanned in time
  if (!queued_scans.empty())
  {
    std::cout << std::endl << queued_scans.size() << " file(s) could not be scanned yet."
              << std::endl;
    for(auto& qElem : queued_scans)
    {
      std::cout << "  " << qElem.second << " (scan ID " << qElem.first << ")" << std::endl;
    } //for (range-based)
  } //if there are some queued scans

  return 0;
}
