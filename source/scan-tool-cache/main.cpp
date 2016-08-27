/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
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

#include <chrono>
#include <iostream>
#include <string>
#include "../../libstriezel/common/StringUtils.hpp"
#include "../../libstriezel/filesystem/directory.hpp"
#include "../../libstriezel/filesystem/file.hpp"
#include "../virustotal/CacheManagerV2.hpp"
#include "../Configuration.hpp"
#include "../Constants.hpp"
#include "../ReturnCodes.hpp"
#include "../scan-tool/Version.hpp"
#include "CacheIteration.hpp"
#include "CacheOperation.hpp"
#include "IterationOperationStatistics.hpp"
#include "IterationOperationUpdate.hpp"

void showHelp()
{
  std::cout << "\nscan-tool-cache OPTIONS ...\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version | -v   - displays the version of the program and quits\n"
            << "  --directory | -d - print the path of the cache directory to the standard\n"
            << "                     output\n"
            << "  --exists | -x    - checks whether the cache directory exists.\n"
            << "                     Exit code is zero, if the directory exists. Exit code is\n"
            << "                     " << scantool::rcCacheDirectoryMissing << ", if it is missing.\n"
            << "  --integrity | -i - performs an integrity check of the cached reports and\n"
            << "                     removes any corrupted reports. Exits after check.\n"
            << "  --transition     - performs cache transition from 16 to 256 subdirectories.\n"
            << "                     This can be used to give older caches (v0.25 and earlier)\n"
            << "                     the current cache directory structure so that these older\n"
            << "                     cache files can be used by the current version program.\n"
            << "                     The program exits after the transition.\n"
            << "  --statistics     - show some statistics about the request cache.\n"
            << "  --update | -u    - updates old cached reports by retrieving the current\n"
            << "                     report or initiating a rescan. This operation requires an\n"
            << "                     VirusTotal API key. (Use --apikey parameter.)\n"
            << "  --apikey KEY     - sets the API key for VirusTotal\n"
            << "  --keyfile FILE   - read the API key for VirusTotal from the file FILE.\n"
            << "                     This way the API key will not appear in the process list\n"
            << "                     and/or shell history. However, the file name can still be\n"
            << "                     seen, so proper file permissions should be set.\n"
            << "  --max-age N      - specifies the maximum age for retrieved scan reports to\n"
            << "                     be N days, where N is a positive integer. Files whose\n"
            << "                     reports are older than N days will be updated during the\n"
            << "                     update operation (see --update).\n"
            << "                     Default value is " << cDefaultMaxAge << " days.\n"
            << "  --silent         - produce less text on the standard output\n"
            << "  --cache-dir DIR  - uses DIR as cache directory. If no cache directory is\n"
            << "                     specified, the program will try to use a preset directory\n"
            << "                     (usually ~/.scan-tool/vt-cache, as in earlier versions).\n";
}

void showVersion()
{
  std::cout << "scan-tool-cache, " << scantool::version << std::endl;
}

int main(int argc, char ** argv)
{
  //requested operation
  scantool::virustotal::CacheOperation op = scantool::virustotal::CacheOperation::None;
  //string that will hold the API key (so far only required for update operation)
  std::string key = "";
  //whether output will be reduced
  bool silent = false;
  // maximum age of scan reports in days where no update is required
  int maxAgeInDays = 0;
  // custom cache directory path
  std::string requestCacheDirVT = "";

  if ((argc>1) and (argv!=nullptr))
  {
    int i=1;
    while (i<argc)
    {
      if (argv[i]!=nullptr)
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
        else if ((param == "--directory") or (param == "-d"))
        {
          std::cout << scantool::virustotal::CacheManagerV2::getDefaultCacheDirectory() << std::endl;
          return 0;
        } //cache directory path
        else if ((param == "--exists") or (param == "-x"))
        {
          if (op != scantool::virustotal::CacheOperation::None)
          {
            std::cout << "Error: Operation must not be specified more than once!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //operation: existence check
          op = scantool::virustotal::CacheOperation::ExistenceCheck;
        } //cache directory existence
        else if ((param == "--integrity") or (param == "-i"))
        {
          if (op != scantool::virustotal::CacheOperation::None)
          {
            std::cout << "Error: Operation must not be specified more than once!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //operation: integrity check
          op = scantool::virustotal::CacheOperation::IntegrityCheck;
        } //integrity check
        else if ((param == "--statistics") or (param == "--stats"))
        {
          if (op != scantool::virustotal::CacheOperation::None)
          {
            std::cout << "Error: More than one operation was specified!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          // operation: stats
          op = scantool::virustotal::CacheOperation::Statistics;
        } //cache statistics
        else if ((param == "--update") or (param == "-u"))
        {
          if (op != scantool::virustotal::CacheOperation::None)
          {
            std::cout << "Error: Operation must not be specified more than once!" << std::endl;
            return scantool::rcInvalidParameter;
          }
          //operation: update cache
          op = scantool::virustotal::CacheOperation::Update;
        } //cache update
        else if ((param == "--transition") or (param == "--cache-transition"))
        {
          scantool::virustotal::CacheManagerV2 cacheMgr;
          return cacheMgr.performTransition();
        } //cache transition to current directory structure
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
        //age limit for update of reports
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
                std::cout << "Warning: Maximum age was capped to 36500 days." << std::endl;
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
            requestCacheDirVT = libstriezel::filesystem::unslashify(std::string(argv[i+1]));
            ++i; //Skip next parameter, because it's already used as directory.
          }
          else
          {
            std::cout << "Error: You have to enter a directory path after \""
                      << param <<"\"." << std::endl;
            return scantool::rcInvalidParameter;
          }
        } //request cache directory
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
        std::cout << "Parameter at index " << i << " is NULL." << std::endl;
        return scantool::rcInvalidParameter;
      }
      ++i;//on to next parameter
    } //while
  } //if arguments present


  //check operation
  if (scantool::virustotal::CacheOperation::None == op)
  {
    std::cout << "Error: No operation parameter was specified!" << std::endl;
    return scantool::rcInvalidParameter;
  }

  //existence check
  if (op == scantool::virustotal::CacheOperation::ExistenceCheck)
  {
    #ifdef SCAN_TOOL_DEBUG
    std::cout << "Request cache directory: " << requestCacheDirVT << std::endl;
    #endif // SCAN_TOOL_DEBUG
    scantool::virustotal::CacheManagerV2 cacheMgr(requestCacheDirVT);
    const std::string cacheDirectory = cacheMgr.getCacheDirectory();
    if (libstriezel::filesystem::directory::exists(cacheDirectory))
    {
      std::cout << "Info: The cache directory exists." << std::endl;
      return 0;
    }
    //directory does not exist
    std::cout << "Info: The cache directory does NOT exist." << std::endl;
    return scantool::rcCacheDirectoryMissing;
  } //if existence check

  //integrity check
  if (op == scantool::virustotal::CacheOperation::IntegrityCheck)
  {
    std::cout << "Checking cache for corrupt files. This may take a while ..."
              << std::endl;
    scantool::virustotal::CacheManagerV2 cacheMgr(requestCacheDirVT);
    const auto corruptFiles = cacheMgr.checkIntegrity(true, true);
    if (corruptFiles == 0)
      std::cout << "There seem to be no corrupt files." << std::endl;
    else if (corruptFiles == 1)
      std::cout << "There was one corrupt file." << std::endl;
    else
      std::cout << "There were " << corruptFiles << " corrupt files." << std::endl;
    return 0;
  } //if integrity check

  //statistics
  if (op == scantool::virustotal::CacheOperation::Statistics)
  {
    //set maximum report age, if it was not set
    if (maxAgeInDays <= 0)
    {
      maxAgeInDays = cDefaultMaxAge;
      if (!silent)
        std::cout << "Information: Maximum report age was set to " << maxAgeInDays
                  << " days." << std::endl;
    } //if
    const auto ageLimit = std::chrono::system_clock::now() - std::chrono::hours(24*maxAgeInDays);

    scantool::virustotal::CacheManagerV2 cacheMgr(requestCacheDirVT);
    scantool::virustotal::CacheIteration ci;
    scantool::virustotal::IterationOperationStatistics opStats(ageLimit);
    std::cout << "Collecting information, this may take a while ..." << std::endl;
    if (!ci.iterate(cacheMgr.getCacheDirectory(), opStats))
    {
      std::cout << "Error: Could not collect cache information!" << std::endl;
      return scantool::rcIterationError;
    }
    std::cout << std::endl << "Cache statistics:" << std::endl
              << "Total number of files: " << opStats.total() << std::endl
              << "Files that failed to parse: " << opStats.unparsable() << std::endl
              << "Files not found by VirusTotal: " << opStats.unknown() << std::endl
              << "Old reports (>" << maxAgeInDays << " days): " << opStats.oldReports() << std::endl
              << "Oldest cached scan's date: ";
    if (opStats.oldest() != static_cast<std::time_t>(-1))
    {
      const auto t = opStats.oldest();
      std::cout << std::asctime(std::localtime(&t));
    }
    else
    {
      std::cout << "(none)";
    }
    std::cout << std::endl << "Newest cached scan's date: ";
    if (opStats.newest() != static_cast<std::time_t>(-1))
    {
      const auto t = opStats.newest();
      std::cout << std::asctime(std::localtime(&t));
    }
    else
    {
      std::cout << "(none)";
    }
    std::cout << std::endl;
    return 0;
  } //if statistics

  //update
  if (op == scantool::virustotal::CacheOperation::Update)
  {
    #ifdef SCAN_TOOL_DEBUG
    std::cout << "Request cache directory: " << requestCacheDirVT << std::endl;
    #endif // SCAN_TOOL_DEBUG
    //check for API key
    if (key.empty())
    {
      std::cout << "Error: The update option will not work without an API key! "
                << "Use --apikey to specify the VirusTotal API key." << std::endl;
      return scantool::rcInvalidParameter;
    }
    //set maximum report age, if it was not set
    if (maxAgeInDays <= 0)
    {
      maxAgeInDays = cDefaultMaxAge;
      if (!silent)
        std::cout << "Information: Maximum report age was set to " << maxAgeInDays
                  << " days." << std::endl;
    } //if

    const auto ageLimit = std::chrono::system_clock::now() - std::chrono::hours(24*maxAgeInDays);

    scantool::virustotal::CacheIteration ci;
    scantool::virustotal::CacheManagerV2 cacheMgr(requestCacheDirVT);
    scantool::virustotal::IterationOperationUpdate opUpdate(key, silent, ageLimit, cacheMgr.getCacheDirectory());
    std::cout << "Updating cache information, this may take a while ..." << std::endl;
    if (!ci.iterate(cacheMgr.getCacheDirectory(), opUpdate))
    {
      std::cout << "Error: Could not update cached information!" << std::endl;
      return scantool::rcIterationError;
    }
    //check pending rescans
    if (!opUpdate.pendingRescans().empty())
    {
      if (!silent)
        std::cout << "Info: Checking " << opUpdate.pendingRescans().size()
                  << " pending rescan(s)..." << std::endl;
      scantool::virustotal::ScannerV2& scanVT = opUpdate.scanner();
      for(const auto & resID : opUpdate.pendingRescans())
      {
        //get current report
        scantool::virustotal::ReportV2 dummy;
        if (!scanVT.getReport(resID, dummy, false, cacheMgr.getCacheDirectory()))
        {
          std::cout << "Info: Not all pending rescans were finished!" << std::endl;
          break;
        }
        //info about rescan success
        if (!silent)
        {
          if (dummy.hasTime_t())
          {
            if (std::chrono::system_clock::from_time_t(dummy.scan_date_t) > ageLimit)
              std::cout << "Cached file for resource " << resID
                        << " was updated after rescan." << std::endl;
            else
              std::cout << "Cached file for resource " << resID
                        << " could not be updated yet, because rescan is still pending."
                        << std::endl;
          } //if has time_t
        } //if not silent
      } //for (range-based)
    } //if pending rescans exist

    //done
    if (!silent)
      std::cout << "Cache update is complete." << std::endl;
    return 0;
  } //if update

  //program flow should never reach that point
  std::cout << "Error: Operation is not implemented yet!" << std::endl;
  return scantool::rcInvalidParameter;
}
