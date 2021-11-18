/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016, 2021  Dirk Stolle

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

#ifndef SCANTOOL_ENGINEV2_HPP
#define SCANTOOL_ENGINEV2_HPP

#include "../Engine.hpp"

namespace scantool::virustotal
{

struct EngineV2: public scantool::Engine
{
  /// Creates empty engine entry.
  EngineV2();

  std::string version; /**< version of the antivirus engine */
  std::string update;  /**< last update of the antivirus engine */
};

} // namespace

#endif // SCANTOOL_ENGINEV2_HPP
