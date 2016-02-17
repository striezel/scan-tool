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

#include <cstdlib> //for std::exit()
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <thread> //for sleep functionality
#if defined(__linux__) || defined(linux)
#include <csignal>
#elif defined(_WIN32)
#include <Windows.h>
#endif
#include "summary.hpp"
#include "../Curly.hpp"
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"
#include "../../libthoro/common/StringUtils.h"
#include "../../libthoro/filesystem/file.hpp"
#include "../../libthoro/hash/sha256/FileSourceUtility.hpp"
#include "../../libthoro/hash/sha256/sha256.hpp"
//return codes
#include "../ReturnCodes.hpp"

/* default value for maximum scan report age

   Three months should be a a reasonable default value that does not put too
   much load on the scanner.
*/
const unsigned int cDefaultMaxAge = 90;

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
            << "  --list FILE      - read the files which shall be scanned from the file FILE,\n"
            << "                     one per line.\n"
            << "  --files FILE     - same as --list FILE\n"
            << "  --max-age N      - specifies the maximum age for retrieved scan reports to\n"
            << "                     be N days, where N is a positive integer. Files whose\n"
            << "                     reports are older than N days will be queued for rescan.\n"
            << "                     Default value is " << cDefaultMaxAge << " days.\n"
            << "  --cache          - cache API requests locally to avoid requesting reports on\n"
            << "                     files that have been requested recently. This option is\n"
            << "                     disabled by default.\n"
            << "  --integrity      - performs an integrity check of the cached reports and\n"
            << "                     removes any corrupted reports. Exits after check.\n"
            << "  --transition     - performs cache transition from 16 to 256 subdirectories.\n"
            << "                     This can be used to give older caches (v0.25 and earlier)\n"
            << "                     the current cache directory structure so that these older\n"
            << "                     cache files can be used by the current version program.\n"
            << "                     The program exits after the transition.\n";
}

void showVersion()
{
  std::cout << "scan-tool, version 0.27b, 2016-02-03\n";
}

/* Four variables that will be used in main() but also in signal handling
   function and are therefore declared as global variables. */
//maps SHA256 hashes to corresponding report; key = SHA256 hash, value = scan report
std::map<std::string, scantool::virustotal::ScannerV2::Report> mapHashToReport;
//maps filename to hash; key = file name, value = SHA256 hash
std::map<std::string, std::string> mapFileToHash = std::map<std::string, std::string>();
//list of queued scan requests; key = scan_id, value = file name
std::unordered_map<std::string, std::string> queued_scans = std::unordered_map<std::string, std::string>();
//list of files that exceed the file size for scans; ; first = file name, second = file size in octets
std::vector<std::pair<std::string, int64_t> > largeFiles;
// for statistics: total number of files
std::set<std::string>::size_type totalFiles;
// for statistics: number of processed files
std::set<std::string>::size_type processedFiles;

#if defined(__linux__) || defined(linux)
/** \brief signal handling function for Linux systems
 *
 * \param sig   the signal number (e.g. 15 for SIGTERM)
 * \remarks This function will not return, because it calls std::exit() at
 *          the end. std::exit() never returns.
 */
void linux_signal_handler(int sig)
{
  std::clog << "INFO: Caught signal ";
  switch (sig)
  {
    case SIGTERM:
         std::clog << "SIGTERM";
         break;
    case SIGINT:
         std::clog << "SIGINT";
         break;
    case SIGUSR1:
         std::clog << "SIGUSR1";
         break;
    case SIGUSR2:
         std::clog << "SIGUSR2";
         break;
    default:
        std::clog << sig;
        break;
  } //switch
  std::clog << "!" << std::endl;
  if ((sig == SIGTERM) || (SIGINT == sig))
  {
    std::clog << "Only " << processedFiles << " out of " << totalFiles
              << " files were processed." << std::endl;
    //Show the summary, e.g. infected files, too large files, and unfinished
    // queued scans, because user might want to see that despite termination.
    showSummary(mapFileToHash, mapHashToReport, queued_scans, largeFiles);
    std::clog << "Terminating program early due to caught signal." << std::endl;
    std::exit(scantool::rcProgramTerminationBySignal);
  } //if SIGINT or SIGTERM
  else if ((sig == SIGUSR1) || (SIGUSR2 == sig))
  {
    std::clog << "Current statistics:" << std::endl
              << processedFiles << " out of " << totalFiles
              << " files were processed so far." << std::endl;
    std::clog << "Queued for scan: " << queued_scans.size() << " item(s)." << std::endl;
  } //else if SIGUSR1 or SIGUSR2
}
#elif defined(_WIN32)
/** \brief signal handling function for Windows systems
 *
 * \param ctrlSignal   the received control signal
 * \return Returns false, if signal was not handled.
 *         Hypothetically returns true, if signal was handled, but in that
 *         case std::exit() steps in to terminate the program.
 * \remarks This function will never return true, because it calls std::exit()
 *          at the end, when a signal is handled. std::exit() never returns.
 */
BOOL windows_signal_handler(DWORD ctrlSignal)
{
  switch (ctrlSignal)
  {
    case CTRL_C_EVENT:
         std::clog << "INFO: Received Ctrl+C!";
         std::clog << "Only " << processedFiles << " out of " << totalFiles
                   << " files were processed." << std::endl;
         //Show the summary, e.g. infected files, too large files, and
         // unfinished queued scans, because user might want to see that
         // despite termination.
         showSummary(mapFileToHash, mapHashToReport, queued_scans, largeFiles);
         std::clog << "Terminating program early due to caught signal."
                   << std::endl;
         std::exit(rcProgramTerminationBySignal);
         return TRUE; //bogus
         break;
  } //switch
  return FALSE;
}
#endif

int main(int argc, char ** argv)
{
  //string that will hold the API key
  std::string key = "";
  //whether output will be reduced
  bool silent = false;
  // limit for "maybe infected"; higher count means infected
  int maybeLimit = 0;
  // maximum age of scan reports in days without requesting rescan
  int maxAgeInDays = 0;
  // flag for using request cache
  bool useRequestCache = false;
  //files that will be checked
  std::set<std::string> files_scan = std::set<std::string>();

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
            return scantool::rcInvalidParameter;
          }
        } //API key
        else if ((param=="--silent") or (param=="-s"))
        {
          //Has the silent parameter already been set?
          if (silent)
          {
            std::cout << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          silent = true;
        } //silent
        else if ((param=="--maybe") or (param=="--limit"))
        {
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string integer = std::string(argv[i+1]);
            int limit = -1;
            if (!stringToInt(integer, limit))
            {
              std::cout << "Error: \"" << integer << "\" is not an integer!" << std::endl;
              return scantool::rcInvalidParameter;
            }
            if (limit < 0)
            {
              std::cout << "Error: " << limit << " is negative, but only"
                        << " non-negative values are allowed here." << std::endl;
              return scantool::rcInvalidParameter;
            }
            maybeLimit = limit;
            ++i; //Skip next parameter, because it's used as limit already.
          }
          else
          {
            std::cout << "Error: You have to enter an integer value after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //"maybe" limit
        else if ((param=="--files") or (param=="--list"))
        {
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string listFile = std::string(argv[i+1]);
            ++i; //Skip next parameter, because it's used as list file already.
            if (!libthoro::filesystem::file::exists(listFile))
            {
              std::cout << "Error: File " << listFile << " does not exist!"
                        << std::endl;
              return scantool::rcFileError;
            }
            //open file and read file names
            std::ifstream inFile;
            inFile.open(listFile, std::ios_base::in | std::ios_base::binary);
            if (!inFile.good() || !inFile.is_open())
            {
              std::cout << "Error: Could not open file " << listFile << "!"
                        << std::endl;
              return scantool::rcFileError;
            }
            std::string nextFile;
            while (!inFile.eof())
            {
              std::getline(inFile, nextFile, '\n');
              if (!nextFile.empty())
              {
                if (libthoro::filesystem::file::exists(nextFile))
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
            return scantool::rcInvalidParameter;
          } //else
        } //list of files
        //age limit for reports
        else if ((param=="--max-age") or (param=="--age-limit"))
        {
          if (maxAgeInDays > 0)
          {
            std::cout << "Error: Report age has been specified multiple times." << std::endl;
            return scantool::rcInvalidParameter;
          }
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            const std::string integer = std::string(argv[i+1]);
            unsigned int limit = 0;
            if (!stringToUnsignedInt(integer, limit))
            {
              std::cout << "Error: \"" << integer << "\" is not an unsigned integer!" << std::endl;
              return scantool::rcInvalidParameter;
            }
            if (limit <= 0)
            {
              std::cout << "Error: Report age has to be more than zero days." << std::endl;
              return scantool::rcInvalidParameter;
            }
            //Is it more than ca. 100 years?
            if (limit > 36500)
            {
              if (!silent)
                std::cout << "Warning: Report age was capped to 36500 days." << std::endl;
              limit = 36500;
            }
            //Assign the parameter value.
            maxAgeInDays = limit;
            ++i; //Skip next parameter, because it's used as limit already.
          }
          else
          {
            std::cout << "Error: You have to enter an integer value after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //age limit
        //use request cache
        else if ((param=="--cache") or (param=="--request-cache") or (param=="--cache-requests"))
        {
          if (useRequestCache)
          {
            std::cout << "Error: Request cache was already enabled." << std::endl;
            return scantool::rcInvalidParameter;
          }
          useRequestCache = true;
        } //request cache
        else if ((param == "--integrity") or (param == "-i"))
        {
          std::cout << "Checking cache for corrupt files. This may take a while ..."
                    << std::endl;
          scantool::virustotal::CacheManagerV2 cacheMgr;
          const auto corruptFiles = cacheMgr.checkIntegrity(true, true);
          if (corruptFiles == 0)
            std::cout << "There seem to be no corrupt files." << std::endl;
          else if (corruptFiles == 1)
            std::cout << "There was one corrupt file." << std::endl;
          else
            std::cout << "There were " << corruptFiles << " corrupt files." << std::endl;
          return 0;
        } //integrity check
        else if ((param == "--transition") or (param == "--cache-transition"))
        {
          scantool::virustotal::CacheManagerV2 cacheMgr;
          return cacheMgr.performTransition();
        } //cache transition to current directory structure
        //file for scan
        else if (libthoro::filesystem::file::exists(param))
        {
          files_scan.insert(param);
        } //file
        else
        {
          //unknown or wrong parameter
          std::cout << "Invalid parameter given: \"" << param << "\"." << std::endl
                    << "Use --help to get a list of valid parameters.\n" << std::endl;
          return scantool::rcInvalidParameter;
        } //if unknown parameter
      } //if parameter exists
      else
      {
        std::cout << "Parameter at index " << i << " is null pointer." << std::endl;
        return scantool::rcInvalidParameter;
      }
      ++i;//on to next parameter
    } //while
  } //if arguments present

  if (key.empty())
  {
    std::cout << "Error: This program won't work properly without an API key! "
              << "Use --apikey to specifiy the VirusTotal API key." << std::endl;
    return scantool::rcInvalidParameter;
  }
  if (files_scan.empty())
  {
    std::cout << "No file scans requested, stopping here." << std::endl;
    return 0;
  } //if no requests

  // set "false positive" limit, if it was not set
  if (maybeLimit <= 0)
    maybeLimit = 3;
  //set maximum report age, if it was not set
  if (maxAgeInDays <= 0)
  {
    maxAgeInDays = cDefaultMaxAge;
    if (!silent)
      std::cout << "Information: Maximum report age was set to " << maxAgeInDays
                << " days." << std::endl;
  } //if

  const auto ageLimit = std::chrono::system_clock::now() - std::chrono::hours(24*maxAgeInDays);

  //handle request cache settings
  scantool::virustotal::CacheManagerV2 cacheMgr;
  std::string requestCacheDirVT = "";
  if (useRequestCache)
  {
    if (!cacheMgr.createCacheDirectory())
    {
      std::cerr << "Error: Could not create request cache directory!" << std::endl;
      return scantool::rcFileError;
    } //if directory could not be created
    // cache directory is ~/.scan-tool/vt-cache/
    requestCacheDirVT = cacheMgr.getCacheDirectory();
    if (!silent)
      std::clog << "Info: Request cache is enabled. "
                << "Cache directory is " << requestCacheDirVT << "." << std::endl;
  } //if useRequestCache

  totalFiles = files_scan.size();
  processedFiles = 0;

  //install signal handlers
  #if defined(__linux__) || defined(linux)
  struct sigaction sa;

  sa.sa_handler = linux_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  //Install one for SIGINT ...
  if (sigaction(SIGINT, &sa, nullptr) != 0)
  {
    std::clog << "Error: Could not set signal handling function for SIGINT!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  // ... and one for SIGTERM.
  if (sigaction(SIGTERM, &sa, nullptr) != 0)
  {
    std::clog << "Error: Could not set signal handling function for SIGTERM!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  // ... and one for SIGUSR1, ...
  if (sigaction(SIGUSR1, &sa, nullptr) != 0)
  {
    std::clog << "Error: Could not set signal handling function for SIGUSR1!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  // ... and one for SIGUSR2.
  if (sigaction(SIGUSR2, &sa, nullptr) != 0)
  {
    std::clog << "Error: Could not set signal handling function for SIGUSR2!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  #elif defined(_WIN32)
  if (SetConsoleCtrlHandler((PHANDLER_ROUTINE) windows_signal_handler, TRUE) == 0)
  {
    std::clog << "Error: Could not set signal handling function for Ctrl+C!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  } //if
  #else
    #error Unknown operating system! No known signal handing facility.
  #endif // defined

  //create scanner: pass API key, honour time limits, set silent mode
  scantool::virustotal::ScannerV2 scanVT(key, true, silent);
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
      return scantool::rcFileError;
    } //if no hash
    const std::string hashString = fileHash.toHexString();
    scantool::virustotal::ScannerV2::Report report;
    if (scanVT.getReport(hashString, report, useRequestCache, requestCacheDirVT))
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
        } //else (file is probably infected)

        //check, if rescan is required because of age
        if (report.hasTime_t()
            && (std::chrono::system_clock::from_time_t(report.scan_date_t) < ageLimit))
        {
          std::string scan_id = "";
          if (!scanVT.rescan(hashString, scan_id))
          {
            std::cerr << "Error: Could not initiate rescan for file " << i
                      << "!" << std::endl;
            return scantool::rcScanError;
          }
          if (!silent)
            std::clog << "Info: " << i << " was queued for re-scan, because "
                      << "report is from " << report.scan_date
                      << " and thus it is older than " << maxAgeInDays
                      << " days. Scan ID for retrieval is " << scan_id
                      << "." << std::endl;
          /* Delete a possibly existing cached entry for that file, because
             it is now potentially outdated, as soon as the next request for
             that report is performed. */
          cacheMgr.deleteCachedElement(hashString);
        } //if rescan because of old report
      } //if file was in report database
      else if (report.notFound())
      {
        //no data present for file
        const int64_t fileSize = libthoro::filesystem::file::getSize64(i);
        if ((fileSize <= scanVT.maxScanSize()) && (fileSize >= 0))
        {
          std::string scan_id = "";
          if (!scanVT.scan(i, scan_id))
          {
            std::cerr << "Error: Could not submit file " << i << " for scanning."
                      << std::endl;
            return scantool::rcScanError;
          }
          //remember time of last scan request
          lastQueuedScanTime = std::chrono::steady_clock::now();
          //add scan ID to list of queued scans for later retrieval
          queued_scans[scan_id] = i;
          if (!silent)
            std::clog << "Info: File " << i << " was queued for scan. Scan ID is "
                      << scan_id << "." << std::endl;
          //delete previous report, because it contains no relevant data
          cacheMgr.deleteCachedElement(hashString);
        } //if file size is below limit
        else
        {
          //File is too large.
          if (!silent)
            std::cout << "Warning: File " << i << " is "
                      << libthoro::filesystem::getSizeString(fileSize)
                      << " and exceeds maximum file size for scan! "
                      << "File will be skipped." << std::endl;
          //save file name + size for later
          largeFiles.push_back(std::pair<std::string, int64_t>(i, fileSize));
        } //else (file too large)
      } //else if report not found
      else
      {
        //unexpected response code
        std::cerr << "Error: Got unexpected response code ("<<report.response_code
                  << ") for report of file " << i << "." << std::endl;
        return scantool::rcScanError;
      }
    }
    else
    {
      if (!silent)
        std::clog << "Warning: Could not get report for file " << i << "!" << std::endl;
    }
    // increase number of processed files
    ++processedFiles;
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
      scantool::virustotal::ScannerV2::Report report;
      if (scanVT.getReport(scan_id, report, false, std::string()))
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

  //show the summary, e.g. infected files, too large files, and unfinished queued scans
  showSummary(mapFileToHash, mapHashToReport, queued_scans, largeFiles);

  return 0;
}
