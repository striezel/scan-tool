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

#include "MetascanDefintions.hpp"

namespace MSO
{

bool isInfected(const int scan_result_i)
{
  //See https://www.metascan-online.com/public-api#!/definitions
  switch (scan_result_i)
  {
    case 1: //"infected"
    case 2: //"suspicious"
    case 8: //"skipped dirty"
         return true;
    default:
         return false;
  } //swi
}

} //namespace
