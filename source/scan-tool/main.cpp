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
#include "Strategies.hpp"
#include "ScanStrategyDefault.hpp"
#include "ScanStrategyDirectScan.hpp"
#include "ScanStrategyNoRescan.hpp"
#include "summary.hpp"
#include "ZipHandler.hpp"
#include "../Configuration.hpp"
#include "../Curly.hpp"
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"
#include "../../libthoro/common/StringUtils.hpp"
#include "../../libthoro/filesystem/file.hpp"
#include "../../libthoro/filesystem/directory.hpp"
#include "../../libthoro/hash/sha256/FileSourceUtility.hpp"
#include "../../libthoro/hash/sha256/sha256.hpp"
#include "../Constants.hpp"
//return codes
#include "../ReturnCodes.hpp"

void showHelp()
{
  std::cout << "\nscan-tool [FILE ...]\n"
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
            << "  --cache-dir DIR  - uses DIR as cache directory. This option only has an\n"
            << "                     effect, if the --cache option is specified, too. If no\n"
            << "                     cache directory is specified, the program will try to use\n"
            << "                     a preset directory (usually ~/.scan-tool/vt-cache, as in\n"
            << "                     earlier versions).\n"
            << "  --strategy STRA  - sets the scan strategy to STRA. Possible strategies are:\n"
            << "                     default - checks for existing reports before submitting a\n"
            << "                               file for scan to VirusTotal\n"
            << "                     direct - submits files directly to VirusTotal and gets\n"
            << "                              the scan results after all files have been sub-\n"
            << "                              mitted.\n"
            << "                     no-rescan - like default, but will never do rescans for\n"
            << "                                 old reports.\n"
            << "  --zip            - add ZIP file handler which extracts ZIP files and scans\n"
            << "                     each contained file, too.\n";
}

void showVersion()
{
  std::cout << "scan-tool, version 0.36b, 2016-04-25\n";
}

/* Four variables that will be used in main() but also in signal handling
   function and are therefore declared as global variables. */
//maps SHA256 hashes to corresponding report; key = SHA256 hash, value = scan report
std::map<std::string, scantool::virustotal::ScannerV2::Report> mapHashToReport;
//maps filename to hash; key = file name, value = SHA256 hash
std::map<std::string, std::string> mapFileToHash = std::map<std::string, std::string>();
//list of queued scan requests; key = scan_id, value = file name
std::unordered_map<std::string, std::string> queued_scans = std::unordered_map<std::string, std::string>();
//list of files that exceed the file size for scans; first = file name, second = file size in octets
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
  // custom cache directory path
  std::string requestCacheDirVT = "";
  //files that will be checked
  std::set<std::string> files_scan = std::set<std::string>();
  //scan strategy
  scantool::virustotal::Strategy selectedStrategy = scantool::virustotal::Strategy::None;
  //flag for ZIP handler
  bool handleZIP = false;

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
          //only one key required
          if (!key.empty())
          {
            std::cout << "Error: API key was already specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
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
            if (!libthoro::filesystem::file::exists(keyfile))
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
            if (!silent)
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
        else if ((param=="--strategy") or (param=="--logic"))
        {
          //only one strategy is possible
          if (selectedStrategy != scantool::virustotal::Strategy::None)
          {
            std::cout << "Error: Scan strategy was already specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            selectedStrategy = scantool::virustotal::stringToStrategy(std::string(argv[i+1]));
            //Is it a recognized strategy?
            if (selectedStrategy == scantool::virustotal::Strategy::None)
            {
              std::cout << "Error: \"" << std::string(argv[i+1]) << "\" is not"
                        << " a known scan strategy." << std::endl;
              return scantool::rcInvalidParameter;
            }
            ++i; //Skip next parameter, because it's used as strategy already.
            if (!silent)
              std::cout << "Info: Scan strategy was set to \""
                        << scantool::virustotal::strategyToString(selectedStrategy)
                        << "\"." << std::endl;
          }
          else
          {
            std::cout << "Error: You have to enter some text after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //scan strategy
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
        //set custom directory for request cache
        else if ((param=="--cache-dir") or (param=="--cache-directory") or (param=="--request-cache-directory"))
        {
          if (!requestCacheDirVT.empty())
          {
            std::cout << "Error: Request cache directory was already set to "
                      << requestCacheDirVT << "!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //enough parameters?
          if ((i+1 < argc) and (argv[i+1] != nullptr))
          {
            requestCacheDirVT = libthoro::filesystem::unslashify(std::string(argv[i+1]));
            ++i; //Skip next parameter, because it's already used as directory.
          }
          else
          {
            std::cout << "Error: You have to enter a directory path after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //request cache directory
        else if (param=="--zip")
        {
          //Has the ZIP option already been set?
          if (handleZIP)
          {
            std::cout << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleZIP = true;
        } //handle ZIP files
        else if ((param == "--integrity") or (param == "-i"))
        {
          //add note about new executable for cache stuff
          std::cout << "Error: Checking cache for corrupt files is now done "
                    << "by scan-tool-cache. Use scan-tool-cache instead."
                    << std::endl;
          return scantool::rcInvalidParameter;
        } //integrity check
        else if ((param == "--transition") or (param == "--cache-transition"))
        {
          //add note about new executable for cache stuff
          std::cout << "Error: Cache transition is now done by scan-tool-cache."
                    << " Use scan-tool-cache instead." << std::endl;
          return scantool::rcInvalidParameter;
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
              << "Use --apikey to specify the VirusTotal API key." << std::endl;
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
  scantool::virustotal::CacheManagerV2 cacheMgr(requestCacheDirVT);
  if (useRequestCache)
  {
    if (!cacheMgr.createCacheDirectory())
    {
      std::cerr << "Error: Could not create request cache directory!" << std::endl;
      return scantool::rcFileError;
    } //if directory could not be created
    // cache directory is ~/.scan-tool/vt-cache/ or a user-defined location
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

  std::unique_ptr<scantool::virustotal::ScanStrategy> strategy = nullptr;
  switch (selectedStrategy)
  {
    case scantool::virustotal::Strategy::DirectScan:
         strategy = std::unique_ptr<scantool::virustotal::ScanStrategyDirectScan>(new scantool::virustotal::ScanStrategyDirectScan());
         break;
    case scantool::virustotal::Strategy::NoRescan:
         strategy = std::unique_ptr<scantool::virustotal::ScanStrategyNoRescan>(new scantool::virustotal::ScanStrategyNoRescan());
         break;
    case scantool::virustotal::Strategy::Default:
    case scantool::virustotal::Strategy::None:
    default:
         //Use default strategy in all other cases.
         strategy = std::unique_ptr<scantool::virustotal::ScanStrategyDefault>(new scantool::virustotal::ScanStrategyDefault());
         break;
  } //switch

  //check, if user wants ZIP handler
  if (handleZIP)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::ZipHandler>(new scantool::virustotal::ZipHandler));
  }

  //iterate over all files for scan requests
  for(const std::string& i : files_scan)
  {
    //apply strategy to current file
    const int exitCode = strategy->scan(scanVT, i, cacheMgr, requestCacheDirVT,
        useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit,
        mapHashToReport, mapFileToHash, queued_scans, lastQueuedScanTime,
        largeFiles);
    //exit early, if an error occurred
    if (exitCode != 0)
      return exitCode;
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
