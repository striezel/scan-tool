/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016  Thoronador

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
#include "../../libthoro/filesystem/directory.hpp"
#include "../virustotal/CacheManagerV2.hpp"
//return codes
#include "../ReturnCodes.hpp"
#include "CacheIteration.hpp"
#include "IterationOperationStatistics.hpp"

void showHelp()
{
  std::cout << "\nscan-tool-cache OPTIONS ...\n"
            << "options:\n"
            << "  --help           - displays this help message and quits\n"
            << "  -?               - same as --help\n"
            << "  --version | -v   - displays the version of the program and quits\n"
            << " --directory | -d  - print the path of the cache directory to the standard\n"
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
            << "  --statistics     - show some statistics about the request cache.\n";
}

void showVersion()
{
  std::cout << "scan-tool-cache, version 0.29, 2016-02-27\n";
}

int main(int argc, char ** argv)
{
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
        else if ((param == "--directory") or (param == "-d"))
        {
          std::cout << scantool::virustotal::CacheManagerV2::getDefaultCacheDirectory() << std::endl;
          return 0;
        } //cache directory path
        else if ((param == "--exists") or (param == "-x"))
        {
          const std::string cacheDirectory = scantool::virustotal::CacheManagerV2::getDefaultCacheDirectory();
          if (libthoro::filesystem::directory::exists(cacheDirectory))
          {
            std::cout << "Info: The cache directory exists." << std::endl;
            return 0;
          }
          //directory does not exist
          std::cout << "Info: The cache directory does NOT exist." << std::endl;
          return scantool::rcCacheDirectoryMissing;
        } //cache directory existence
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
        else if ((param == "--statistics") or (param == "--stats"))
        {
          scantool::virustotal::CacheManagerV2 cacheMgr;
          scantool::virustotal::CacheIteration ci;
          scantool::virustotal::IterationOperationStatistics opStats;
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
        } //cache statistics
        else if ((param == "--transition") or (param == "--cache-transition"))
        {
          scantool::virustotal::CacheManagerV2 cacheMgr;
          return cacheMgr.performTransition();
        } //cache transition to current directory structure
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

  return 0;
}
