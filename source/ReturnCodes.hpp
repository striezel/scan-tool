/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015, 2016  Thoronador

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

#ifndef SCANTOOL_RETURNCODES_HPP
#define SCANTOOL_RETURNCODES_HPP

//return codes
// -- invalid/malformed parameter value
const int rcInvalidParameter = 1;
// -- file I/O error
const int rcFileError = 2;
// -- scanner-related error
const int rcScanError = 3;
// -- an error related to the signal handler occurred
const int rcSignalHandlerError = 4;
// -- program was terminated by an intercepted signal
const int rcProgramTerminationBySignal = 5;

#endif // SCANTOOL_RETURNCODES_HPP
