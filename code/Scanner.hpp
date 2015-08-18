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

#ifndef SCANNER_HPP
#define SCANNER_HPP

#include <chrono>

class Scanner
{
  public:
    /** \brief default constructor
     *
     * \param honourTimeLimits   whether or not time limits should be honoured
     */
    Scanner(const bool honourTimeLimits);


    ///virtual destructor
    virtual ~Scanner() {}


    /** \brief checks, if this scanner respects its time limit
     *
     * \return True, if time limit is considered between requests.
     *         Returns false, if not.
     */
    bool honoursTimeLimit() const;


     /** \brief set, if time limit is considered between two requests
      *
      * \param doHonour   new value that determines whether time limits matter
      */
    void honourTimeLimit(const bool doHonour);


    /** \brief duration between consecutive requests, if time limit is respected
     *
     * \return Returns the minimum interval between two consecutive requests.
     */
    virtual std::chrono::seconds timeBetweenConsecutiveRequests() const = 0;


    /** \brief returns the time of the last request
     *
     * \return Returns the time of the last request.
     */
    std::chrono::steady_clock::time_point lastRequestTime() const;
  private:
    bool m_HonourLimit; /**< whether to honour time limits */
    std::chrono::steady_clock::time_point m_LastRequest; /**< time of the last request */
}; //class

#endif // SCANNER_HPP
