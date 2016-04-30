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

#ifndef SCANTOOL_VT_HANDLERAR_HPP
#define SCANTOOL_VT_HANDLERAR_HPP

#include "HandlerGeneric.hpp"
#include "../../libthoro/archive/ar/archive.hpp"

struct ArDetection
{
  static bool isArcT(const std::string& fn)
  {
    return libthoro::ar::archive::isAr(fn);
  }
}; //struct

namespace scantool
{

namespace virustotal
{

typedef HandlerGeneric<libthoro::ar::archive, ArDetection> HandlerAr;

} //namespace

} //namespace

#endif // SCANTOOL_VT_HANDLERAR_HPP
