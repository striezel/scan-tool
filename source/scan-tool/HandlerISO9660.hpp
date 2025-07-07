/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2016, 2025  Dirk Stolle

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

#ifndef SCANTOOL_VT_HANDLERISO9660_HPP
#define SCANTOOL_VT_HANDLERISO9660_HPP

#include "HandlerGeneric.hpp"
#include "../../libstriezel/archive/iso9660/archive.hpp"

struct IsoDetection
{
  static bool isArcT(const std::string& fn)
  {
    return libstriezel::archive::iso9660::archive::isISO9660(fn);
  }
}; // struct

namespace scantool::virustotal
{

typedef HandlerGeneric<libstriezel::archive::iso9660::archive, IsoDetection> HandlerISO9660;

} // namespace

#endif // SCANTOOL_VT_HANDLERISO9660_HPP
