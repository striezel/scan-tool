/*
 -------------------------------------------------------------------------------
    This file is part of the test suite for scan-tool.
    Copyright (C) 2016 Dirk Stolle

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
#include "../../libthoro/filesystem/file.hpp"
#include "../../source/Configuration.hpp"

int main(int argc, char** argv)
{
  std::string filename = "";
  if ((argc < 2) || (argv == nullptr) || (argv[1] == nullptr))
  {
    std::cout << "Error: This program expects a configuration file name as "
              << "its first argument." << std::endl;
    return 1;
  }
  const std::string keyfile = std::string(argv[1]);
  if (!libthoro::filesystem::file::exists(keyfile))
  {
    std::cout << "Error: The specified key file " << keyfile
              << " does not exist!" << std::endl;
    return 1;
  } //if file does not exist
  Configuration conf;
  if (!conf.loadFromFile(keyfile))
  {
    std::cout << "Error: Could not load key from file " << keyfile << "!"
              << std::endl;
    return 1;
  }
  if (conf.apikey().empty())
  {
    std::cout << "Error: Key file " << keyfile << " does not contain"
              << " an API key!" << std::endl;
    return 1;
  }
  //OK
  std::cout << "Test was successful." << std::endl
            << "Key is \"" << conf.apikey() << "\"." << std::endl;
  return 0;
}
