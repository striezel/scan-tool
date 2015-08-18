/*
 -------------------------------------------------------------------------------
    This file is part of scan-tool.
    Copyright (C) 2015  Thoronador

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

#ifndef SCANNERVIRUSTOTAL_HPP
#define SCANNERVIRUSTOTAL_HPP

#include <string>
#include "Scanner.hpp"

class ScannerVirusTotal: public Scanner
{
  public:
    /** \brief default constructor
     *
     * \param apikey   the VirusTotal API key used for scanning
     * \param honourTimeLimits   whether or not time limits should be honoured
     */
    ScannerVirusTotal(const std::string& apikey, const bool honourTimeLimits);


    /** \brief sets a new API key
     *
     * \param apikey   the VirusTotal API key used for scanning
     */
    void setApiKey(const std::string& apikey);


    /** \brief duration between consecutive requests, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive requests.
     */
    virtual std::chrono::seconds timeBetweenConsecutiveRequests() const override;
  private:
    std::string m_apikey; /**< holds the VirusTotal API key */
}; //class

#endif // SCANNERVIRUSTOTAL_HPP
