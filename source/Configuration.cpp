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

#include "Configuration.hpp"
#include <fstream>
#include <iostream>

const char Configuration::cCommentCharacter = '#';

Configuration::Configuration()
: m_apikey("")
{
}

const std::string& Configuration::apikey() const
{
  return m_apikey;
}

void Configuration::clear()
{
  m_apikey.clear();
}

bool Configuration::loadFromFile(const std::string& fileName)
{
  std::ifstream input;
  input.open(fileName.c_str(), std::ios::in | std::ios::binary);
  if (!input)
  {
    return false;
  }

  //clear existing values
  clear();

  const unsigned int cMaxLine = 1024;
  char buffer[cMaxLine];
  std::string line = "";
  std::string::size_type sep_pos = 0;
  while (input.getline(buffer, cMaxLine-1))
  {
    buffer[cMaxLine-1] = '\0';
    line = std::string(buffer);
    //check for possible carriage return at end (happens on Windows systems)
    if (!line.empty())
    {
      if (line.at(line.length()-1)=='\r')
      {
        line.erase(line.length()-1);
      }//if
    }

    if (!line.empty())
    {
      //Is it a comment line?
      if (line[0] != cCommentCharacter)
      {
        sep_pos = line.find('=');
        if (sep_pos == std::string::npos || sep_pos == 0)
        {
          std::cout << "Configuration::loadFromFile: ERROR: Invalid line found: \""
                    << line <<"\".\nGeneral format: \"Name of Setting=value\"\n"
                    << "Loading from file cancelled.\n";
          input.close();
          return false;
        }

        const std::string name = line.substr(0, sep_pos);
        if (name=="apikey")
        {
          m_apikey = line.substr(sep_pos+1);
        }
        else
        {
          std::cout << "Configuration::loadFromFile: ERROR: Unknown entry name found: \""
                    << line <<"\".\nKnown entries: apikey.\n";
          input.close();
          return false;
        } //else
      } //if not comment
    }//if not empty
  }//while
  input.close();
  return true;
}
