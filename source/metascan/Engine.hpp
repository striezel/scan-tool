/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Dirk Stolle

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

#ifndef SCANTOOL_MSO_ENGINE_HPP
#define SCANTOOL_MSO_ENGINE_HPP

#include "../Engine.hpp"
#include <chrono>

namespace scantool
{

namespace metascan
{

struct Engine: public scantool::Engine
{
  ///default constructor
  Engine();

  int scan_result_i; /**< numeric value to represent scan result */
  std::string def_time; /**< date of virus definitions of the anti-virus engine */
  std::chrono::milliseconds scan_time;  /**< time in milliseconds required for scan by this AV engine */
}; //struct Engine

} //namespace

} //namespace

#endif // SCANTOOL_MSO_ENGINE_HPP
