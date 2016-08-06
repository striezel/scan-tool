/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Dirk Stolle

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

#ifndef SCANTOOL_ENGINE_HPP
#define SCANTOOL_ENGINE_HPP

#include <string>

namespace scantool
{

struct Engine
{
  ///default constructor
  Engine();

  ///virtual destructor
  virtual ~Engine() {}

  std::string engine;  /**< name of the antivirus engine */
  bool detected;       /**< whether the engine detected a virus */
  std::string result;  /**< name of the detected malware */
}; //struct Engine

} //namespace

#endif // SCANTOOL_ENGINE_HPP
