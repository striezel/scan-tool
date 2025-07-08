/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2017, 2021  Dirk Stolle

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
#include "Handler7z.hpp"
#include "HandlerAr.hpp"
#include "HandlerCab.hpp"
#include "HandlerGzip.hpp"
#include "HandlerInstallShield.hpp"
#include "HandlerISO9660.hpp"
#include "HandlerRar.hpp"
#include "HandlerTar.hpp"
#include "HandlerXz.hpp"
#include "Strategies.hpp"
#include "ScanStrategyDefault.hpp"
#include "ScanStrategyDirectScan.hpp"
#include "ScanStrategyNoRescan.hpp"
#include "ScanStrategyScanAndForget.hpp"
#include "summary.hpp"
#include "Version.hpp"
#include "ZipHandler.hpp"
#include "../Configuration.hpp"
#include "../Curly.hpp"
#include "../virustotal/CacheManagerV2.hpp"
#include "../virustotal/ScannerV2.hpp"
#include "../../libstriezel/common/StringUtils.hpp"
#include "../../libstriezel/filesystem/file.hpp"
#include "../../libstriezel/filesystem/directory.hpp"
#include "../../libstriezel/hash/sha256/FileSourceUtility.hpp"
#include "../../libstriezel/hash/sha256/sha256.hpp"
#include "../Constants.hpp"
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
            << "                     scan-and-forget - only submits files for scanning to\n"
            << "                                       VirusTotal, but does not get reports.\n"
            << "  --zip            - add ZIP file handler which extracts ZIP files and scans\n"
            << "                     each contained file, too.\n"
            << "  --7zip | --7z    - add 7-Zip file handler which extracts 7-Zip files and\n"
            << "                     scans each contained file, too.\n"
            << "  --tar            - add tape archive (*.tar) file handler which extracts tape\n"
            << "                     archives and scans each contained file, too.\n"
            << "  --gzip | --gz    - add gzip file handler which extracts gzip files and scans\n"
            << "                     each contained file, too.\n"
            << "  --ar             - add Ar archive file handler which extracts these archives\n"
            << "                     and scans each contained file, too.\n"
            << "  --xz             - add XZ file handler which decompressed XZ files and scans\n"
            << "                     the decompressed file, too.\n"
            << "  --iso9660        - add ISO 9660 (*.iso) file handler which extracts ISO 9660\n"
            << "                     disk images and scans each contained file, too.\n"
            << "  --cab            - add Cabinet archive (*.cab) file handler which extracts\n"
            << "                     these archives and scans each contained file, too.\n"
            << "  --rar            - add Rar file handler which extracts Roschal archives and\n"
            << "                     scans each contained file, too. Note that due to the\n"
            << "                     proprietary nature of this file format it is possible\n"
            << "                     that not all file of the archive can be extracted.\n"
            << "  --installshield  - add InstallShield CAB file handler which extracts\n"
            << "                     InstallShield Cabinet archives and scans each contained\n"
            << "                     file, too.\n"
            << "  --ignore-extraction-errors\n"
            << "                   - tells the program to ignore errors during archive\n"
            << "                     extraction and continue as if these errors did not occur.\n";
}

void showVersion()
{
  std::cout << "scan-tool, " << scantool::version << std::endl;
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
         std::exit(scantool::rcProgramTerminationBySignal);
         return TRUE; //bogus
         break;
  } //switch
  return FALSE;
}
#endif

int main(int argc, char ** argv)
{
  // string that will hold the API key
  std::string key = "";
  // whether output will be reduced
  bool silent = false;
  // limit for "maybe infected"; higher count means infected
  int maybeLimit = 0;
  // maximum age of scan reports in days without requesting rescan
  int maxAgeInDays = 0;
  // flag for using request cache
  bool useRequestCache = false;
  // custom cache directory path
  std::string requestCacheDirVT = "";
  // files that will be checked
  std::set<std::string> files_scan = std::set<std::string>();
  // scan strategy
  scantool::virustotal::Strategy selectedStrategy = scantool::virustotal::Strategy::None;
  // flags for archive file handlers
  bool handle7Zip = false;
  bool handleZIP = false;
  bool handleTar = false;
  bool handleGzip = false;
  bool handleISO9660 = false;
  bool handleAr = false;
  bool handleXz = false;
  bool handleCab = false;
  bool handleRar = false;
  bool handleInstallShield = false;
  bool ignoreExtractionErrors = false;

  if ((argc > 1) && (argv != nullptr))
  {
    int i = 1;
    while (i < argc)
    {
      if (argv[i] != nullptr)
      {
        const std::string param = std::string(argv[i]);
        // help parameter
        if ((param == "--help") || (param == "-?") || (param == "/?"))
        {
          showHelp();
          return 0;
        }
        // version information requested?
        else if ((param == "--version") || (param == "-v"))
        {
          showVersion();
          return 0;
        }
        else if ((param == "--key") || (param == "--apikey"))
        {
          // only one key required
          if (!key.empty())
          {
            std::cerr << "Error: API key was already specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            key = std::string(argv[i+1]);
            ++i; // Skip next parameter, because it's used as API key already.
            #ifdef SCAN_TOOL_DEBUG
            if (!silent)
              std::cout << "API key was set to \"" << key << "\"." << std::endl;
            #endif
          }
          else
          {
            std::cerr << "Error: You have to enter some text after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //API key
        else if (param == "--keyfile")
        {
          // only one key required
          if (!key.empty())
          {
            std::cerr << "Error: API key was already specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            const std::string keyfile = std::string(argv[i+1]);
            if (!libstriezel::filesystem::file::exists(keyfile))
            {
              std::cerr << "Error: The specified key file " << keyfile
                        << " does not exist!" << std::endl;
              /* Technically it's a file error, but let's return "invalid
                 parameter" here, because the file name parameter is wrong/
                 invalid.
              */
              return scantool::rcInvalidParameter;
            } // if file does not exist
            Configuration conf;
            if (!conf.loadFromFile(keyfile))
            {
              std::cerr << "Error: Could not load key from file " << keyfile
                        << "!" << std::endl;
              return scantool::rcFileError;
            }
            if (conf.apikey().empty())
            {
              std::cerr << "Error: Key file " << keyfile << " does not contain"
                        << " an API key!" << std::endl;
              return scantool::rcFileError;
            }
            key = conf.apikey();
            ++i; // Skip next parameter, because it's used as key file already.
            #ifdef SCAN_TOOL_DEBUG
            if (!silent)
              std::cout << "API key was set to \"" << key << "\"." << std::endl;
            #endif
          }
          else
          {
            std::cerr << "Error: You have to enter a file name after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } // API key from file
        else if ((param == "--silent") || (param == "-s"))
        {
          // Has the silent parameter already been set?
          if (silent)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          silent = true;
        }
        else if ((param == "--maybe") || (param == "--limit"))
        {
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            const std::string integer = std::string(argv[i+1]);
            int limit = -1;
            if (!stringToInt(integer, limit))
            {
              std::cerr << "Error: \"" << integer << "\" is not an integer!" << std::endl;
              return scantool::rcInvalidParameter;
            }
            if (limit < 0)
            {
              std::cerr << "Error: " << limit << " is negative, but only"
                        << " non-negative values are allowed here." << std::endl;
              return scantool::rcInvalidParameter;
            }
            maybeLimit = limit;
            ++i; // Skip next parameter, because it's used as limit already.
          }
          else
          {
            std::cerr << "Error: You have to enter an integer value after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } // "maybe" limit
        else if ((param == "--files") || (param == "--list"))
        {
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            const std::string listFile = std::string(argv[i+1]);
            ++i; // Skip next parameter, because it's used as list file already.
            if (!libstriezel::filesystem::file::exists(listFile))
            {
              std::cerr << "Error: File " << listFile << " does not exist!"
                        << std::endl;
              return scantool::rcFileError;
            }
            // open file and read file names
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
                if (libstriezel::filesystem::file::exists(nextFile))
                {
                  #ifdef SCAN_TOOL_DEBUG
                  std::cout << "Info: Adding " << nextFile << " to list of files for scan." << std::endl;
                  #endif // SCAN_TOOL_DEBUG
                  files_scan.insert(nextFile);
                }
                else
                {
                  std::cout << "Warning: File " << nextFile << " does not exist, skipping it."
                            << std::endl;
                }
              } // if string not empty
            } // while
            inFile.close();
          } // if
          else
          {
            std::cerr << "Error: You have to enter a file name after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } // list of files
        // age limit for reports
        else if ((param == "--max-age") || (param == "--age-limit"))
        {
          if (maxAgeInDays > 0)
          {
            std::cerr << "Error: Report age has been specified multiple times." << std::endl;
            return scantool::rcInvalidParameter;
          }
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            const std::string integer = std::string(argv[i+1]);
            unsigned int limit = 0;
            if (!stringToUnsignedInt(integer, limit))
            {
              std::cerr << "Error: \"" << integer << "\" is not an unsigned integer!" << std::endl;
              return scantool::rcInvalidParameter;
            }
            if (limit <= 0)
            {
              std::cerr << "Error: Report age has to be more than zero days." << std::endl;
              return scantool::rcInvalidParameter;
            }
            // Is it more than ca. 100 years?
            if (limit > 36500)
            {
              if (!silent)
                std::cerr << "Warning: Report age was capped to 36500 days." << std::endl;
              limit = 36500;
            }
            // Assign the parameter value.
            maxAgeInDays = limit;
            ++i; // Skip next parameter, because it's used as limit already.
          }
          else
          {
            std::cerr << "Error: You have to enter an integer value after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } // age limit
        else if ((param == "--strategy") || (param == "--logic"))
        {
          // only one strategy is possible
          if (selectedStrategy != scantool::virustotal::Strategy::None)
          {
            std::cerr << "Error: Scan strategy was already specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            selectedStrategy = scantool::virustotal::stringToStrategy(std::string(argv[i+1]));
            // Is it a recognized strategy?
            if (selectedStrategy == scantool::virustotal::Strategy::None)
            {
              std::cerr << "Error: \"" << std::string(argv[i+1]) << "\" is not"
                        << " a known scan strategy." << std::endl;
              return scantool::rcInvalidParameter;
            }
            ++i; // Skip next parameter, because it's used as strategy already.
            if (!silent)
              std::cout << "Info: Scan strategy was set to \""
                        << scantool::virustotal::strategyToString(selectedStrategy)
                        << "\"." << std::endl;
          }
          else
          {
            std::cerr << "Error: You have to enter some text after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } // scan strategy
        // use request cache
        else if ((param == "--cache") || (param == "--request-cache") || (param == "--cache-requests"))
        {
          if (useRequestCache)
          {
            std::cerr << "Error: Request cache was already enabled." << std::endl;
            return scantool::rcInvalidParameter;
          }
          useRequestCache = true;
        } // request cache
        // set custom directory for request cache
        else if ((param == "--cache-dir") || (param == "--cache-directory") || (param == "--request-cache-directory"))
        {
          if (!requestCacheDirVT.empty())
          {
            std::cerr << "Error: Request cache directory was already set to "
                      << requestCacheDirVT << "!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          // enough parameters?
          if ((i+1 < argc) && (argv[i+1] != nullptr))
          {
            requestCacheDirVT = libstriezel::filesystem::unslashify(std::string(argv[i+1]));
            ++i; // Skip next parameter, because it's already used as directory.
          }
          else
          {
            std::cerr << "Error: You have to enter a directory path after \""
                      << param << "\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } // request cache directory
        else if (param == "--zip")
        {
          // Has the ZIP option already been set?
          if (handleZIP)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleZIP = true;
        } // handle ZIP files
        else if ((param == "--7zip") || (param == "--7z") || (param == "--7-zip"))
        {
          // Has the 7z option already been set?
          if (handle7Zip)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handle7Zip = true;
        } // handle 7-Zip files
        else if (param == "--tar")
        {
          // Has the tar option already been set?
          if (handleTar)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleTar = true;
        } // handle tape archive files
        else if ((param == "--gzip") || (param == "--gz"))
        {
          // Has the gzip option already been set?
          if (handleGzip)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleGzip = true;
        } // handle .gz files
        else if (param == "--xz")
        {
          // Has the XZ option already been set?
          if (handleXz)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleXz = true;
        } // handle XZ compressed files
        else if (param == "--ar")
        {
          // Has the Ar option already been set?
          if (handleAr)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleAr = true;
        } // handle Ar archive files
        else if ((param == "--iso") || (param == "--iso9660"))
        {
          // Has the ISO9660 option already been set?
          if (handleISO9660)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleISO9660 = true;
        } // handle .iso files
        else if ((param == "--cab") || (param == "--cabinet"))
        {
          // Has the CAB option already been set?
          if (handleCab)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleCab = true;
        } // handle .cab files
        else if (param == "--rar")
        {
          // Has the Rar option already been set?
          if (handleRar)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleRar = true;
        } // handle .rar files
        else if ((param == "--installshield") || (param == "--unshield"))
        {
          // Has the InstallShield option already been set?
          if (handleInstallShield)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          handleInstallShield = true;
        } // handle InstallShield CAB files
        else if ((param == "--ignore-extraction-errors") || (param == "--ignore-archive-errors"))
        {
          // Has the ignore option already been set?
          if (ignoreExtractionErrors)
          {
            std::cerr << "Error: Parameter " << param << " must not occur more than once!"
                      << std::endl;
            return scantool::rcInvalidParameter;
          }
          ignoreExtractionErrors = true;
        } // ignore archive extraction errors
        else if ((param == "--integrity") || (param == "-i"))
        {
          // add note about new executable for cache stuff
          std::cerr << "Error: Checking cache for corrupt files is now done "
                    << "by scan-tool-cache. Use scan-tool-cache instead."
                    << std::endl;
          return scantool::rcInvalidParameter;
        } // integrity check
        else if ((param == "--transition") || (param == "--cache-transition"))
        {
          // add note about new executable for cache stuff
          std::cerr << "Error: Cache transition is now done by scan-tool-cache."
                    << " Use scan-tool-cache instead." << std::endl;
          return scantool::rcInvalidParameter;
        } // cache transition to current directory structure
        // file for scan
        else if (libstriezel::filesystem::file::exists(param))
        {
          files_scan.insert(param);
        } // file
        else
        {
          // unknown or wrong parameter
          std::cerr << "Invalid parameter given: \"" << param << "\"." << std::endl
                    << "Use --help to get a list of valid parameters.\n" << std::endl;
          return scantool::rcInvalidParameter;
        } // if unknown parameter
      } // if parameter exists
      else
      {
        std::cout << "Parameter at index " << i << " is null pointer." << std::endl;
        return scantool::rcInvalidParameter;
      }
      ++i; // on to next parameter
    } // while
  } // if arguments present

  if (key.empty())
  {
    std::cerr << "Error: This program won't work properly without an API key! "
              << "Use --apikey to specify the VirusTotal API key." << std::endl;
    return scantool::rcInvalidParameter;
  }
  if (files_scan.empty())
  {
    std::cout << "No file scans requested, stopping here." << std::endl;
    return 0;
  } // if no requests

  // set "false positive" limit, if it was not set
  if (maybeLimit <= 0)
    maybeLimit = 3;
  // set maximum report age, if it was not set
  if (maxAgeInDays <= 0)
  {
    maxAgeInDays = cDefaultMaxAge;
    if (!silent)
      std::cout << "Information: Maximum report age was set to " << maxAgeInDays
                << " days." << std::endl;
  }

  const auto ageLimit = std::chrono::system_clock::now() - std::chrono::hours(24*maxAgeInDays);

  // handle request cache settings
  scantool::virustotal::CacheManagerV2 cacheMgr(requestCacheDirVT);
  if (useRequestCache)
  {
    if (!cacheMgr.createCacheDirectory())
    {
      std::cerr << "Error: Could not create request cache directory!" << std::endl;
      return scantool::rcFileError;
    } // if directory could not be created
    // cache directory is ~/.scan-tool/vt-cache/ or a user-defined location
    requestCacheDirVT = cacheMgr.getCacheDirectory();
    if (!silent)
      std::clog << "Info: Request cache is enabled. "
                << "Cache directory is " << requestCacheDirVT << "." << std::endl;
  } // if useRequestCache

  totalFiles = files_scan.size();
  processedFiles = 0;

  // install signal handlers
  #if defined(__linux__) || defined(linux)
  struct sigaction sa;

  sa.sa_handler = linux_signal_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  // Install one for SIGINT ...
  if (sigaction(SIGINT, &sa, nullptr) != 0)
  {
    std::cerr << "Error: Could not set signal handling function for SIGINT!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  // ... and one for SIGTERM.
  if (sigaction(SIGTERM, &sa, nullptr) != 0)
  {
    std::cerr << "Error: Could not set signal handling function for SIGTERM!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  // ... and one for SIGUSR1, ...
  if (sigaction(SIGUSR1, &sa, nullptr) != 0)
  {
    std::cerr << "Error: Could not set signal handling function for SIGUSR1!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  // ... and one for SIGUSR2.
  if (sigaction(SIGUSR2, &sa, nullptr) != 0)
  {
    std::cerr << "Error: Could not set signal handling function for SIGUSR2!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  #elif defined(_WIN32)
  if (SetConsoleCtrlHandler((PHANDLER_ROUTINE) windows_signal_handler, TRUE) == 0)
  {
    std::cerr << "Error: Could not set signal handling function for Ctrl+C!"
              << std::endl;
    return scantool::rcSignalHandlerError;
  }
  #else
    #error Unknown operating system! No known signal handling facility.
  #endif

  // create scanner: pass API key, honour time limits, set silent mode
  scantool::virustotal::ScannerV2 scanVT(key, true, silent);
  // time when last scan was queued
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
    case scantool::virustotal::Strategy::ScanAndForget:
         strategy = std::unique_ptr<scantool::virustotal::ScanStrategyScanAndForget>(new scantool::virustotal::ScanStrategyScanAndForget());
         break;
    case scantool::virustotal::Strategy::Default:
    case scantool::virustotal::Strategy::None:
    default:
         // Use default strategy in all other cases.
         strategy = std::unique_ptr<scantool::virustotal::ScanStrategyDefault>(new scantool::virustotal::ScanStrategyDefault());
         break;
  }

  // check, if user wants ZIP handler
  if (handleZIP)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::ZipHandler>(new scantool::virustotal::ZipHandler(ignoreExtractionErrors)));
  }
  // check, if user wants 7z handler
  if (handle7Zip)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::Handler7z>(new scantool::virustotal::Handler7z(ignoreExtractionErrors)));
  }
  // check if user wants tar handler
  if (handleTar)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerTar>(new scantool::virustotal::HandlerTar(ignoreExtractionErrors)));
  }
  // check if user wants gz handler
  if (handleGzip)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerGzip>(new scantool::virustotal::HandlerGzip(ignoreExtractionErrors)));
  }
  // check if user wants Ar handler
  if (handleAr)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerAr>(new scantool::virustotal::HandlerAr(ignoreExtractionErrors)));
  }
  // check XZ handler
  if (handleXz)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerXz>(new scantool::virustotal::HandlerXz(ignoreExtractionErrors)));
  }
  // check if user wants iso9660 handler
  if (handleISO9660)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerISO9660>(new scantool::virustotal::HandlerISO9660(ignoreExtractionErrors)));
  }
  // check if user wants cabinet handler
  if (handleCab)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerCab>(new scantool::virustotal::HandlerCab(ignoreExtractionErrors)));
  }
  // check if user wants InstallShield cabinet handler
  if (handleInstallShield)
  {
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerInstallShield>(new scantool::virustotal::HandlerInstallShield(ignoreExtractionErrors)));
  }
  // check Rar handler
  if (handleRar)
  {
    /* Rar handler will always ignore extraction errors, because due to the
       proprietary nature of this archive format it is very possible that not
       all files in the archive can be extracted (ca. 50 % chance?).
       So naturally some files will get extraction errors, even if the file
       itself is OK. */
    strategy->addHandler(std::unique_ptr<scantool::virustotal::HandlerRar>(new scantool::virustotal::HandlerRar(true)));
  }

  // iterate over all files for scan requests
  for(const std::string& i : files_scan)
  {
    // apply strategy to current file
    const int exitCode = strategy->scan(scanVT, i, cacheMgr, requestCacheDirVT,
        useRequestCache, silent, maybeLimit, maxAgeInDays, ageLimit,
        mapHashToReport, mapFileToHash, queued_scans, lastQueuedScanTime,
        largeFiles, processedFiles, totalFiles);
    // exit early, if an error occurred
    if (exitCode != 0)
      return exitCode;
    // increase number of processed files
    ++processedFiles;
  }

  // try to retrieve queued scans
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
    } // if not enough time elapsed

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
          // got report
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
            // if hash is not given, recalculate it
            if (report.sha256.empty())
            {
              report.sha256 = SHA256::computeFromFile(filename).toHexString();
            } // if hash is not present
            // add file to list of infected files
            mapFileToHash[filename] = report.sha256;
            mapHashToReport[report.sha256] = report;
          }
          else if (report.positives > maybeLimit)
          {
            if (!silent)
              std::clog << filename << " is INFECTED, got " << report.positives
                        << " positives." << std::endl;
            // add file to list of infected files
            mapFileToHash[filename] = report.sha256;
            mapHashToReport[report.sha256] = report;
          } // else
        } // if file was in report database
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
        }
        queued_scans.erase(qsIter);
        qsIter = queued_scans.begin();
      } // if report could be retrieved
      else
      {
        if (!silent)
          std::clog << "Warning: Could not get queued scan report for scan ID "
                    << scan_id << " / file " << filename << "!" << std::endl;
        ++qsIter;
      }
    } // while
  } // if some scans are/were queued

  // show the summary, e.g. infected files, too large files, and unfinished queued scans
  showSummary(mapFileToHash, mapHashToReport, queued_scans, largeFiles);

  return 0;
}
